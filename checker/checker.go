package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
	"encoding/json"

	_ "github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/valyala/fasthttp"
)

// ============================================
// Prometheus метрики
// ============================================
var (
	rpsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "checker_requests_total",
			Help: "Total number of check requests",
		},
		[]string{"geo"},
	)

	queueSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "checker_queue_size",
			Help: "Current queue size",
		},
		[]string{"geo"},
	)

	workersActive = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "checker_workers_active",
			Help: "Number of active workers",
		},
		[]string{"geo"},
	)

	checksSuccess = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "checker_success_total",
			Help: "Total successful checks (VPN detected)",
		},
		[]string{"geo", "protocol"},
	)

	checksFailed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "checker_failed_total",
			Help: "Total failed checks",
		},
		[]string{"geo"},
	)
)

// ============================================
// Структуры
// ============================================
type Checker struct {
	db         *sql.DB
	geo        string
	minWorkers int
	maxWorkers int
	queue      chan *Address
	workers    int
	mu         sync.Mutex
	wg         sync.WaitGroup // ✅ Добавлено для graceful shutdown
}

type Address struct {
	ID   string
	IP   string
	Port int
	Geo  string // ✅ Добавлено
}

// VPNSignature - сигнатуры для определения типа VPN
type VPNSignature struct {
	Protocol string
	Patterns []string
	Headers  map[string]string
}

var vpnSignatures = []VPNSignature{
	{
		Protocol: "Fortinet",
		Patterns: []string{
			"<title>FortiGate",
			"fortigate",
			"/remote/login",
			"fgt_lang",
		},
		Headers: map[string]string{
			"Server": "xxxxxxxx-xxxxx", // FortiGate маскирует сервер
		},
	},
	{
		Protocol: "Cisco AnyConnect",
		Patterns: []string{
			"webvpn.html",
			"/+CSCOE+/",
			"Cisco AnyConnect",
			"csco_",
		},
	},
	{
		Protocol: "Palo Alto",
		Patterns: []string{
			"global-protect",
			"PanGPS",
			"/global-protect/",
		},
	},
	{
		Protocol: "SonicWall",
		Patterns: []string{
			"SonicWALL",
			"sslvpn",
			"/cgi-bin/userLogin",
		},
	},
	{
		Protocol: "Pulse Secure",
		Patterns: []string{
			"Pulse Secure",
			"/dana-na/",
			"Juniper Networks",
		},
	},
	{
		Protocol: "OpenVPN",
		Patterns: []string{
			"OpenVPN",
			"/ovpnws/",
		},
	},
}

// ============================================
// Конструктор
// ============================================
func NewChecker(db *sql.DB, geo string, minWorkers, maxWorkers int) *Checker {
	return &Checker{
		db:         db,
		geo:        geo,
		minWorkers: minWorkers,
		maxWorkers: maxWorkers,
		queue:      make(chan *Address, 1000), // ✅ Буфер для сглаживания
		workers:    0,
	}
}

// ============================================
// Основной цикл
// ============================================
func (c *Checker) Run(ctx context.Context) error {
	log.Printf("🚀 Starting checker for GEO=%s (workers: %d-%d)", c.geo, c.minWorkers, c.maxWorkers)

	// Запускаем фоновые горутины
	c.wg.Add(2)
	go c.fetchLoop(ctx)
	go c.metricsLoop(ctx)

	// Запускаем минимальное количество воркеров
	for i := 0; i < c.minWorkers; i++ {
		c.startWorker(ctx)
	}

	// Автомасштабирование воркеров на основе CPU
	target := c.minWorkers
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("🛑 Shutting down checker for GEO=%s", c.geo)
			close(c.queue)
			c.wg.Wait() // ✅ Ждём завершения всех горутин
			return nil

		case <-ticker.C:
			// Получаем текущую загрузку CPU
			perc, err := cpu.Percent(time.Second, false)
			if err != nil {
				log.Printf("⚠️ Failed to get CPU usage: %v", err)
				continue
			}

			load := perc[0] / 100.0

			// Автомасштабирование
			if load < 0.70 && target < c.maxWorkers {
				// CPU недогружен - добавляем воркеры
				target = int(math.Min(float64(target+10), float64(c.maxWorkers)))
				log.Printf("📈 CPU low (%.1f%%), scaling up to %d workers", load*100, target)
			} else if load > 0.90 && target > c.minWorkers {
				// CPU перегружен - уменьшаем воркеры
				target = int(math.Max(float64(target-10), float64(c.minWorkers)))
				log.Printf("📉 CPU high (%.1f%%), scaling down to %d workers", load*100, target)
			}

			// Добавляем воркеры до target
			c.mu.Lock()
			currentWorkers := c.workers
			c.mu.Unlock()

			for currentWorkers < target {
				c.startWorker(ctx)
				currentWorkers++
			}

			// Логируем текущее состояние
			qLen := len(c.queue)
			log.Printf("📊 [%s] Workers: %d/%d, Queue: %d, CPU: %.1f%%",
				c.geo, currentWorkers, c.maxWorkers, qLen, load*100)
		}
	}
}

// ============================================
// Получение адресов из БД
// ============================================
func (c *Checker) fetchLoop(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			// Проверяем размер очереди
			queueLen := len(c.queue)
			if queueLen > 500 {
				// Очередь заполнена - пропускаем итерацию
				log.Printf("⚠️ Queue is full (%d), skipping fetch", queueLen)
				continue
			}

			addrs, err := c.fetchAddresses(ctx, 100)
			if err != nil {
				log.Printf("❌ Failed to fetch addresses: %v", err)
				continue
			}

			if len(addrs) == 0 {
				log.Printf("📭 No unchecked addresses for GEO=%s", c.geo)
				continue
			}

			// Добавляем адреса в очередь
			for _, a := range addrs {
				select {
				case c.queue <- a:
					// Успешно добавлено
				case <-ctx.Done():
					return
				default:
					// Очередь переполнена - пропускаем
					log.Printf("⚠️ Queue overflow, dropping address %s:%d", a.IP, a.Port)
				}
			}

			log.Printf("✅ Fetched %d addresses for GEO=%s", len(addrs), c.geo)
		}
	}
}

func (c *Checker) fetchAddresses(ctx context.Context, limit int) ([]*Address, error) {
	// ✅ ИСПРАВЛЕНО: добавлена обработка ошибок, SKIP LOCKED
	query := `
		SELECT id, ip, port, geo
		FROM scanned_addresses
		WHERE geo = $1 AND is_checked = FALSE
		ORDER BY created_at ASC
		LIMIT $2
		FOR UPDATE SKIP LOCKED
	`

	rows, err := c.db.QueryContext(ctx, query, c.geo, limit)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var addrs []*Address
	for rows.Next() {
		var a Address
		if err := rows.Scan(&a.ID, &a.IP, &a.Port, &a.Geo); err != nil {
			log.Printf("⚠️ Scan error: %v", err)
			continue
		}
		addrs = append(addrs, &a)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration failed: %w", err)
	}

	return addrs, nil
}

// ============================================
// Управление воркерами
// ============================================
func (c *Checker) startWorker(ctx context.Context) {
	c.mu.Lock()
	c.workers++
	workerID := c.workers
	c.mu.Unlock()

	c.wg.Add(1)
	go c.workerLoop(ctx, workerID)
}

func (c *Checker) workerLoop(ctx context.Context, workerID int) {
	defer func() {
		c.mu.Lock()
		c.workers--
		c.mu.Unlock()
		c.wg.Done()
	}()

	// ✅ ИСПРАВЛЕНО: правильная настройка TLS
	client := &fasthttp.Client{
		ReadTimeout:         10 * time.Second,
		WriteTimeout:        10 * time.Second,
		MaxIdleConnDuration: 60 * time.Second,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	log.Printf("👷 Worker %d started for GEO=%s", workerID, c.geo)

	for {
		select {
		case addr, ok := <-c.queue:
			if !ok {
				log.Printf("👋 Worker %d stopping (queue closed)", workerID)
				return
			}

			rpsTotal.WithLabelValues(c.geo).Inc()
			c.checkOne(client, addr)

		case <-ctx.Done():
			log.Printf("👋 Worker %d stopping (context cancelled)", workerID)
			return
		}
	}
}

// ============================================
// Проверка одного адреса
// ============================================
func (c *Checker) checkOne(client *fasthttp.Client, addr *Address) {
	// ✅ ИСПРАВЛЕНО: полная логика проверки и сохранения в БД
	startTime := time.Now()

	// Пробуем HTTPS
	url := fmt.Sprintf("https://%s:%d", addr.IP, addr.Port)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(url)
	req.Header.SetMethod("GET")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	err := client.DoTimeout(req, resp, 10*time.Second)

	// Помечаем адрес как проверенный
	defer c.markChecked(addr.ID)

	if err != nil {
		// Не удалось подключиться
		checksFailed.WithLabelValues(c.geo).Inc()
		log.Printf("❌ [%s:%d] Connection failed: %v", addr.IP, addr.Port, err)
		return
	}

	// Анализируем ответ
	statusCode := resp.StatusCode()
	body := string(resp.Body())
	headers := make(map[string]string)

	resp.Header.VisitAll(func(key, value []byte) {
		headers[string(key)] = string(value)
	})

	// Определяем тип VPN
	protocol, version, domainHint := c.detectVPN(body, headers)

	if protocol == "" {
		// VPN не обнаружен
		log.Printf("ℹ️ [%s:%d] No VPN detected (status: %d)", addr.IP, addr.Port, statusCode)
		return
	}

	// VPN обнаружен!
	checksSuccess.WithLabelValues(c.geo, protocol).Inc()

	elapsed := time.Since(startTime)
	log.Printf("✅ [%s:%d] VPN found: %s (version: %s, time: %v)",
		addr.IP, addr.Port, protocol, version, elapsed)

	// Сохраняем в БД
	if err := c.saveVPN(addr, url, protocol, version, domainHint); err != nil {
		log.Printf("❌ Failed to save VPN: %v", err)
	}
}

// ============================================
// Определение типа VPN
// ============================================
func (c *Checker) detectVPN(body string, headers map[string]string) (protocol, version, domainHint string) {
	bodyLower := strings.ToLower(body)

	for _, sig := range vpnSignatures {
		matched := false

		// Проверяем паттерны в body
		for _, pattern := range sig.Patterns {
			if strings.Contains(bodyLower, strings.ToLower(pattern)) {
				matched = true
				break
			}
		}

		// Проверяем заголовки
		if !matched {
			for headerKey, headerPattern := range sig.Headers {
				if headerValue, ok := headers[headerKey]; ok {
					if strings.Contains(strings.ToLower(headerValue), strings.ToLower(headerPattern)) {
						matched = true
						break
					}
				}
			}
		}

		if matched {
			protocol = sig.Protocol

			// Извлекаем версию (примитивно)
			version = c.extractVersion(body, sig.Protocol)

			// Извлекаем domain hint
			domainHint = c.extractDomainHint(body)

			return
		}
	}

	return "", "", ""
}

func (c *Checker) extractVersion(body, protocol string) string {
	// Примитивное извлечение версии
	// Для Fortinet: ищем "v6.0.0" или "6.2.5"
	versionRegex := regexp.MustCompile(`v?(\d+\.\d+\.\d+)`)
	matches := versionRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}
	return "unknown"
}

func (c *Checker) extractDomainHint(body string) string {
	// Ищем упоминания домена
	// Примеры: "Login to CORP", "DOMAIN\username"
	domainRegex := regexp.MustCompile(`(?i)domain[:\s]+([a-zA-Z0-9\-\.]+)`)
	matches := domainRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}

	// Ищем паттерн "Login to XXX"
	loginRegex := regexp.MustCompile(`(?i)login to ([a-zA-Z0-9\-]+)`)
	matches = loginRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// ============================================
// Сохранение в БД
// ============================================
func (c *Checker) saveVPN(addr *Address, targetURL, protocol, version, domainHint string) error {
	// ✅ ИСПРАВЛЕНО: правильный INSERT с конфликтами
	query := `
		INSERT INTO vpns (
			id, target_url, ip, port, geo, protocol, version, domain_hint,
			status, created_at, updated_at
		) VALUES (
			gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7,
			'new', NOW(), NOW()
		)
		ON CONFLICT (target_url) DO UPDATE SET
			updated_at = NOW(),
			last_checked = NOW()
		RETURNING id
	`

	var vpnID string
	err := c.db.QueryRow(
		query,
		targetURL, addr.IP, addr.Port, addr.Geo,
		protocol, version, domainHint,
	).Scan(&vpnID)

	if err != nil {
		return fmt.Errorf("insert vpn failed: %w", err)
	}

	log.Printf("💾 Saved VPN: %s (ID: %s)", targetURL, vpnID)

	// Создаём задачу для брута
	return c.createBruteTask(vpnID, addr.Geo)
}

func (c *Checker) createBruteTask(vpnID, geo string) error {
	query := `
		INSERT INTO tasks (id, type, status, payload, geo, created_at)
		VALUES (gen_random_uuid(), 'brute', 'pending', $1, $2, NOW())
	`

	payload := map[string]interface{}{
		"vpn_id": vpnID,
		"mode":   "initial",
	}

	payloadJSON, _ := json.Marshal(payload)

	_, err := c.db.Exec(query, string(payloadJSON), geo)
	if err != nil {
		return fmt.Errorf("create brute task failed: %w", err)
	}

	log.Printf("📝 Created brute task for VPN: %s", vpnID)
	return nil
}

func (c *Checker) markChecked(addrID string) {
	// ✅ ИСПРАВЛЕНО: правильный UPDATE
	query := `
		UPDATE scanned_addresses
		SET is_checked = TRUE, updated_at = NOW()
		WHERE id = $1
	`

	_, err := c.db.Exec(query, addrID)
	if err != nil {
		log.Printf("⚠️ Failed to mark address as checked: %v", err)
	}
}

// ============================================
// Метрики
// ============================================
func (c *Checker) metricsLoop(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			c.mu.Lock()
			qLen := len(c.queue)
			workers := c.workers
			c.mu.Unlock()

			queueSize.WithLabelValues(c.geo).Set(float64(qLen))
			workersActive.WithLabelValues(c.geo).Set(float64(workers))

			// Логируем статистику из БД
			var uncheckedCount, vpnsCount int
			c.db.QueryRow(`
				SELECT COUNT(*) FROM scanned_addresses WHERE geo = $1 AND is_checked = FALSE
			`, c.geo).Scan(&uncheckedCount)

			c.db.QueryRow(`
				SELECT COUNT(*) FROM vpns WHERE geo = $1
			`, c.geo).Scan(&vpnsCount)

			log.Printf("📈 [%s] Queue: %d, Workers: %d, Unchecked: %d, VPNs: %d",
				c.geo, qLen, workers, uncheckedCount, vpnsCount)
		}
	}
}