package main

import (
    "bytes"
    "context"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "net/url"
    "regexp"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    socks "golang.org/x/net/proxy"
)

// ============================================
// Структуры
// ============================================

type Proxy struct {
    Host      string `json:"host"`
    Port      int    `json:"port"`
    Protocol  string `json:"protocol"`
    Geo       string `json:"geo"`
    Anonymity string `json:"anonymity"`
    SpeedMs   int    `json:"speed_ms"`
    IsAlive   bool   `json:"is_alive"`
}

type GeoInfo struct {
    Status      string `json:"status"`
    Country     string `json:"country"`
    CountryCode string `json:"countryCode"`
    Region      string `json:"region"`
    City        string `json:"city"`
    ISP         string `json:"isp"`
    Query       string `json:"query"`
}

type CheckResult struct {
    Proxy   *Proxy
    Success bool
    Error   string
}

type ProxyChecker struct {
    realIP           string
    sources          []string
    timeout          time.Duration
    workerCount      int
    socksDialerCache map[string]socks.Dialer
    cacheMu          sync.RWMutex

    // Статистика
    checked   int32
    alive     int32
    dead      int32
    startTime time.Time
}

// ============================================
// Конструктор
// ============================================

func NewProxyChecker() *ProxyChecker {
    return &ProxyChecker{
        sources: []string{
            // SOCKS5
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
            "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5",
            "https://www.proxy-list.download/api/v1/get?type=socks5",

            // HTTP
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
            "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
            "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&format=text",
            "https://www.proxy-list.download/api/v1/get?type=http",
        },
        timeout:     6 * time.Second,
        workerCount: 64, // ← оптимально для 4 ГБ RAM
        socksDialerCache: make(map[string]socks.Dialer),
    }
}

// ============================================
// Проверка порта
// ============================================

func isValidProxyPort(port int, proto string) bool {
    if port < 1 || port > 65535 {
        return false
    }
    // Известные прокси-порты
    common := map[int]bool{
        80: true, 8080: true, 3128: true, 8888: true, // HTTP
        1080: true, 9050: true, 9150: true, 4145: true, // SOCKS
    }
    if common[port] {
        return true
    }
    // Диапазоны: разрешаем 1024–9999 и 50001–65535, но блокируем 10000–50000 (часто масс-скан/мусор)
    if port >= 1024 && port <= 9999 {
        return true
    }
    if port >= 50001 && port <= 65535 {
        return true
    }
    return false
}

// ============================================
// Главный цикл
// ============================================

func (pc *ProxyChecker) Run() {
    log.Println("🚀 Proxy Checker запущен")
    log.Println("📊 Воркеров:", pc.workerCount)

    pc.getRealIP()

    for {
        log.Println("\n" + strings.Repeat("=", 60))
        log.Println("🔄 НАЧАЛО ЦИКЛА ПРОВЕРКИ")
        log.Println(strings.Repeat("=", 60))

        pc.startTime = time.Now()
        atomic.StoreInt32(&pc.checked, 0)
        atomic.StoreInt32(&pc.alive, 0)
        atomic.StoreInt32(&pc.dead, 0)

        log.Println("\n1️⃣ Сбор прокси...")
        scrapedProxies := pc.collectProxies()
        log.Printf("   ✅ Собрано %d новых прокси\n", len(scrapedProxies))

        log.Println("\n2️⃣ Загрузка из БД...")
        dbProxies := pc.getProxiesFromDB()
        log.Printf("   ✅ Загружено %d из БД\n", len(dbProxies))

        log.Println("\n3️⃣ Объединение и фильтрация...")
        allProxies := pc.mergeAndDeduplicate(scrapedProxies, dbProxies)
        log.Printf("   ✅ Всего уникальных: %d\n", len(allProxies))

        if len(allProxies) == 0 {
            log.Println("   ⚠️ Нет прокси")
            time.Sleep(10 * time.Minute)
            continue
        }

        log.Println("\n4️⃣ Проверка...")
        alive, dead := pc.checkAllProxiesParallel(allProxies)

        elapsed := time.Since(pc.startTime)
        rate := float64(len(allProxies)) / elapsed.Seconds()
        log.Printf("\n   ✅ Живых: %d | ❌ Мёртвых: %d | ⏱️ %v | 📈 %.1f прокси/сек\n",
            len(alive), len(dead), elapsed.Round(time.Second), rate)

        log.Println("\n5️⃣ Обновление БД...")
        pc.updateDatabase(alive, dead)

        log.Println("\n💤 Сон 10 мин...")
        time.Sleep(10 * time.Minute)
    }
}

// ============================================
// Сбор и парсинг
// ============================================

func (pc *ProxyChecker) collectProxies() []*Proxy {
    var all []*Proxy
    var mu sync.Mutex
    var wg sync.WaitGroup

    for _, src := range pc.sources {
        wg.Add(1)
        go func(url string) {
            defer wg.Done()
            proxies := pc.fetchFromSource(url)
            if len(proxies) > 0 {
                mu.Lock()
                all = append(all, proxies...)
                mu.Unlock()
                log.Printf("   📥 %d из %s", len(proxies), shortURL(url))
            }
        }(src)
    }
    wg.Wait()
    return all
}

func shortURL(u string) string {
    if len(u) <= 40 {
        return u
    }
    return "..." + u[len(u)-37:]
}

func (pc *ProxyChecker) fetchFromSource(url string) []*Proxy {
    client := &http.Client{Timeout: 15 * time.Second}
    resp, err := client.Get(url)
    if err != nil || resp == nil || resp.StatusCode != 200 {
        return nil
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    return pc.parseProxies(string(body), url)
}

func (pc *ProxyChecker) parseProxies(content string, sourceURL string) []*Proxy {
    re := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+):(\d{2,5})`)
    matches := re.FindAllStringSubmatch(content, -1)

    var proxies []*Proxy
    seen := make(map[string]bool)

    proto := "http"
    if strings.Contains(strings.ToLower(sourceURL), "socks5") {
        proto = "socks5"
    }

    for _, m := range matches {
        if len(m) < 3 {
            continue
        }
        host, portStr := m[1], m[2]
        port, err := strconv.Atoi(portStr)
        if err != nil {
            continue
        }
        key := fmt.Sprintf("%s:%d", host, port)
        if seen[key] {
            continue
        }

        // ← Фильтр портов
        if !isValidProxyPort(port, proto) {
            continue
        }

        seen[key] = true
        proxies = append(proxies, &Proxy{
            Host:     host,
            Port:     port,
            Protocol: proto,
        })
    }
    return proxies
}

// ============================================
// Загрузка из БД
// ============================================

func (pc *ProxyChecker) getProxiesFromDB() []*Proxy {
    resp, err := http.Get("http://localhost:8000/api/proxy-list-all?limit=100000")
    if err != nil || resp.StatusCode != 200 {
        log.Println("   ⚠️ DB load error:", err)
        return nil
    }
    defer resp.Body.Close()

    var data struct{ Proxies []Proxy }
    if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
        log.Println("   ⚠️ DB JSON error:", err)
        return nil
    }

    result := make([]*Proxy, len(data.Proxies))
    for i := range data.Proxies {
        result[i] = &data.Proxies[i]
    }
    return result
}

// ============================================
// Объединение
// ============================================

func (pc *ProxyChecker) mergeAndDeduplicate(scraped, fromDB []*Proxy) []*Proxy {
    unique := make(map[string]*Proxy)

    for _, p := range fromDB {
        key := fmt.Sprintf("%s:%d", p.Host, p.Port)
        unique[key] = p
    }
    for _, p := range scraped {
        key := fmt.Sprintf("%s:%d", p.Host, p.Port)
        if _, exists := unique[key]; !exists {
            unique[key] = p
        }
    }

    result := make([]*Proxy, 0, len(unique))
    for _, p := range unique {
        result = append(result, p)
    }
    return result
}

// ============================================
// Проверка (оптимизированная)
// ============================================

func (pc *ProxyChecker) checkAllProxiesParallel(proxies []*Proxy) ([]*Proxy, []*Proxy) {
    results := make(chan CheckResult, len(proxies))
    queue := make(chan *Proxy, len(proxies))
    for _, p := range proxies {
        queue <- p
    }
    close(queue)

    var wg sync.WaitGroup
    for i := 0; i < pc.workerCount; i++ {
        wg.Add(1)
        go pc.worker(queue, results, &wg)
    }

    go func() {
        wg.Wait()
        close(results)
    }()

    var alive, dead []*Proxy
    for res := range results {
        if res.Success {
            alive = append(alive, res.Proxy)
        } else {
            dead = append(dead, res.Proxy)
        }
    }
    return alive, dead
}

func (pc *ProxyChecker) worker(queue <-chan *Proxy, results chan<- CheckResult, wg *sync.WaitGroup) {
    defer wg.Done()
    for proxy := range queue {
        results <- pc.checkProxy(proxy)

        checked := atomic.AddInt32(&pc.checked, 1)
        if checked%100 == 0 {
            alive := atomic.LoadInt32(&pc.alive)
            dead := atomic.LoadInt32(&pc.dead)
            log.Printf("   📊 %d | ✅ %d | ❌ %d", checked, alive, dead)
        }
    }
}

func (pc *ProxyChecker) checkProxy(proxy *Proxy) CheckResult {
    var client *http.Client
    var proxyIP string
    successCount := 0

    protocol := strings.ToLower(proxy.Protocol)
    switch protocol {
    case "http", "https":
        u, err := url.Parse(fmt.Sprintf("http://%s:%d", proxy.Host, proxy.Port))
        if err != nil {
            return CheckResult{Proxy: proxy, Success: false, Error: "url parse"}
        }
        client = &http.Client{
            Transport: &http.Transport{
                Proxy: http.ProxyURL(u),
                DialContext: (&net.Dialer{
                    Timeout:   pc.timeout,
                    KeepAlive: 0,
                }).DialContext,
                DisableKeepAlives:     true,
                MaxIdleConns:          1,
                TLSHandshakeTimeout:   pc.timeout,
                ResponseHeaderTimeout: pc.timeout,
                IdleConnTimeout:       1 * time.Second,
                TLSClientConfig: &tls.Config{
                    InsecureSkipVerify: false,
                },
            },
            Timeout: pc.timeout,
        }

    case "socks5":
        key := fmt.Sprintf("socks5://%s:%d", proxy.Host, proxy.Port)

        pc.cacheMu.RLock()
        dialer, ok := pc.socksDialerCache[key]
        pc.cacheMu.RUnlock()

        if !ok {
            pc.cacheMu.Lock()
            if d, exists := pc.socksDialerCache[key]; exists {
                dialer = d
            } else {
                var err error
                dialer, err = socks.SOCKS5("tcp", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port), nil, &net.Dialer{
                    Timeout:   pc.timeout,
                    KeepAlive: 0,
                })
                if err != nil {
                    pc.cacheMu.Unlock()
                    return CheckResult{Proxy: proxy, Success: false, Error: "socks5 init"}
                }
                pc.socksDialerCache[key] = dialer
            }
            pc.cacheMu.Unlock()
        }

        client = &http.Client{
            Transport: &http.Transport{
                DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
                    return dialer.Dial(network, addr)
                },
                DisableKeepAlives:     true,
                MaxIdleConns:          1,
                TLSHandshakeTimeout:   pc.timeout,
                ResponseHeaderTimeout: pc.timeout,
                IdleConnTimeout:       1 * time.Second,
                TLSClientConfig: &tls.Config{
                    InsecureSkipVerify: false,
                },
            },
            Timeout: pc.timeout,
        }

    default:
        return CheckResult{Proxy: proxy, Success: false, Error: "unknown proto"}
    }

    // ← Только 2 проверки: быстрая + надёжная
    targets := []string{
        "http://api.ipify.org",
        "https://httpbin.org/ip",
    }

    for _, rawURL := range targets {
        resp, err := client.Get(rawURL)
        var ip string
        ok := false

        if err == nil && resp != nil && resp.StatusCode == 200 {
            body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
            resp.Body.Close()

            if strings.Contains(rawURL, "httpbin") {
                var data struct{ Origin string }
                if json.Unmarshal(body, &data) == nil {
                    ip = strings.TrimSpace(strings.Split(data.Origin, ",")[0])
                    ok = net.ParseIP(ip) != nil
                }
            } else {
                ip = strings.TrimSpace(string(body))
                ok = net.ParseIP(ip) != nil
            }

            if ok && ip != pc.realIP {
                successCount++
                if proxyIP == "" {
                    proxyIP = ip
                }
            }
        }
    }

    // ← Оба запроса должны дать foreign IP
    if successCount < 2 {
        return CheckResult{Proxy: proxy, Success: false, Error: "no foreign IP"}
    }

    anonymity := "anonymous"
    if proxyIP == "" || proxyIP == pc.realIP {
        anonymity = "transparent"
    }

    geo := pc.getGeoInfo(proxyIP)
    if geo == "" {
        geo = "XX"
    }

    proxy.IsAlive = true
    proxy.SpeedMs = 1000
    proxy.Anonymity = anonymity
    proxy.Geo = geo

    atomic.AddInt32(&pc.alive, 1)
    return CheckResult{Proxy: proxy, Success: true}
}

// ============================================
// GEO
// ============================================

func (pc *ProxyChecker) getGeoInfo(ip string) string {
    if ip == "" {
        return "XX"
    }
    client := &http.Client{Timeout: 3 * time.Second}
    resp, err := client.Get("http://ip-api.com/json/" + url.PathEscape(ip))
    if err != nil || resp == nil || resp.StatusCode != 200 {
        return "XX"
    }
    defer resp.Body.Close()

    var g GeoInfo
    json.NewDecoder(resp.Body).Decode(&g)
    if g.Status == "success" && g.CountryCode != "" {
        return g.CountryCode
    }
    return "XX"
}

func (pc *ProxyChecker) getRealIP() {
    resp, err := http.Get("http://api.ipify.org")
    if err != nil {
        pc.realIP = "127.0.0.1"
        log.Println("   ⚠️ realIP fallback to 127.0.0.1")
        return
    }
    defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    pc.realIP = strings.TrimSpace(string(body))
    log.Println("🌐 Real IP:", pc.realIP)
}

// ============================================
// Обновление БД
// ============================================

func (pc *ProxyChecker) updateDatabase(alive, dead []*Proxy) {
    batchSize := 100

    // Живые
    for i := 0; i < len(alive); i += batchSize {
        end := i + batchSize
        if end > len(alive) {
            end = len(alive)
        }
        batch := alive[i:end]
        payload := make([]map[string]interface{}, len(batch))
        for j, p := range batch {
            payload[j] = map[string]interface{}{
                "host":      p.Host,
                "port":      p.Port,
                "geo":       p.Geo,
                "anonymity": p.Anonymity,
                "speed_ms":  p.SpeedMs,
                "is_alive":  true,
            }
        }
        pc.postToAPI("http://localhost:8000/api/proxy-batch-update", payload)
    }
    log.Printf("   ✅ Обновлено живых: %d", len(alive))

    // Мёртвые — помечаем
    for i := 0; i < len(dead); i += batchSize {
        end := i + batchSize
        if end > len(dead) {
            end = len(dead)
        }
        batch := dead[i:end]
        payload := make([]map[string]interface{}, len(batch))
        for j, p := range batch {
            payload[j] = map[string]interface{}{
                "host":      p.Host,
                "port":      p.Port,
                "is_alive":  false,
                "geo":       "XX",
                "anonymity": "anonymous",
                "speed_ms":  0,
            }
        }
        pc.postToAPI("http://localhost:8000/api/proxy-batch-update", payload)
    }
    log.Printf("   ❌ Помечено мёртвых: %d", len(dead))
}

func (pc *ProxyChecker) postToAPI(url string, data interface{}) {
    jsonData, _ := json.Marshal(data)
    resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
    if err != nil {
        log.Printf("   ⚠️ API error: %v", err)
        return
    }
    resp.Body.Close()
    if resp.StatusCode != 200 {
        log.Printf("   ⚠️ API %d", resp.StatusCode)
    }
}

// ============================================
// MAIN
// ============================================

func main() {
    log.SetFlags(log.Ltime)
    checker := NewProxyChecker()
    checker.Run()
}
