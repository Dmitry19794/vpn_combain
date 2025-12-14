package main

import (
    "bytes"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "net"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"
)

type Proxy struct {
    ID          string `json:"id,omitempty"`
    Host        string `json:"host"`
    Port        string `json:"port"`
    Protocol    string `json:"protocol,omitempty"`
    IsWorking   bool   `json:"is_alive"`
    Speed       time.Duration
    SpeedMs     int    `json:"speed_ms"`          // ← добавлено
    LastCheck   time.Time `json:"last_check,omitempty"`
    Country     string `json:"geo"`               // ← geo → Country в Go, но geo в JSON
    Geo         string `json:"-"`                 // ← для обратной совместимости, если нужно
    Anonymity   string `json:"anonymity,omitempty"`
    ChecksPassed int   `json:"checks_passed,omitempty"`
}

type ProxyCrawler struct {
    proxies     map[string]*Proxy
    mu          sync.RWMutex
    sources     []string
    checkURLs   []string
    timeout     time.Duration
    workerCount int
    realIP      string
}

func NewProxyCrawler() *ProxyCrawler {
    pc := &ProxyCrawler{
        proxies: make(map[string]*Proxy),
        sources: []string{
            // GitHub источники
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
            "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
            "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
            "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
            "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/RAW.txt",
            "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
            "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/https.txt",

            // CDN
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt",

            // API
            "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&proxy_format=protocolipport&format=text",
            "https://www.proxy-list.download/api/v1/get?type=http",
            "https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=10000&country=all",
        },
        checkURLs: []string{
            "http://api.ipify.org",
            "http://icanhazip.com",
        },
        timeout:     3 * time.Second,
        workerCount: 300,
    }
    pc.realIP = pc.getRealIP()
    return pc
}

func (pc *ProxyCrawler) getRealIP() string {
    resp, err := http.Get("http://api.ipify.org")
    if err != nil {
        return ""
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return ""
    }
    ip := strings.TrimSpace(string(body))
    fmt.Printf("Ваш реальный IP: %s\n", ip)
    return ip
}

func (pc *ProxyCrawler) crawlProxies() {
    fmt.Printf("=== ЭТАП 1: Сбор прокси из %d источников ===\n", len(pc.sources))
    startTime := time.Now()

    allProxies := make([]*Proxy, 0)
    var collectMu sync.Mutex
    var collectWg sync.WaitGroup

    for idx, source := range pc.sources {
        collectWg.Add(1)
        go func(index int, src string) {
            defer collectWg.Done()
            fmt.Printf("[%d/%d] Загрузка: %s\n", index+1, len(pc.sources), src)
            proxies := pc.fetchFromSource(src)
            if len(proxies) > 0 {
                fmt.Printf("  ✓ Найдено %d прокси\n", len(proxies))
                collectMu.Lock()
                allProxies = append(allProxies, proxies...)
                collectMu.Unlock()
            } else {
                fmt.Printf("  ✗ Прокси не найдены или ошибка загрузки\n")
            }
        }(idx, source)
    }
    collectWg.Wait()
    collectTime := time.Since(startTime)

    fmt.Printf("\n✓ Сбор завершен за %v\n", collectTime.Round(time.Second))
    fmt.Printf("Всего собрано: %d прокси\n", len(allProxies))

    fmt.Printf("\n=== ЭТАП 2: Проверка прокси (%d воркеров) ===\n", pc.workerCount)
    checkStart := time.Now()

    var checkWg sync.WaitGroup
    proxyChan := make(chan *Proxy, 5000)

    for i := 0; i < pc.workerCount; i++ {
        checkWg.Add(1)
        go pc.checkWorker(&checkWg, proxyChan)
    }

    for _, proxy := range allProxies {
        proxyChan <- proxy
    }
    close(proxyChan)
    checkWg.Wait()

    checkTime := time.Since(checkStart)
    totalTime := time.Since(startTime)
    fmt.Printf("\n✓ Проверка завершена за %v\n", checkTime.Round(time.Second))
    fmt.Printf("✓ Общее время: %v\n", totalTime.Round(time.Second))
    pc.printStats()
}

func (pc *ProxyCrawler) fetchFromSource(sourceURL string) []*Proxy {
    client := &http.Client{Timeout: 15 * time.Second}
    resp, err := client.Get(sourceURL)
    if err != nil {
        fmt.Printf("Ошибка получения %s: %v\n", sourceURL, err)
        return nil
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        fmt.Printf("Ошибка: статус %d для %s\n", resp.StatusCode, sourceURL)
        return nil
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil
    }
    return pc.parseProxies(string(body))
}

func (pc *ProxyCrawler) parseProxies(content string) []*Proxy {
    re := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})`)
    matches := re.FindAllStringSubmatch(content, -1)

    var proxies []*Proxy
    seen := make(map[string]bool)

    for _, match := range matches {
        if len(match) >= 3 {
            host := match[1]
            port := match[2]
            key := host + ":" + port
            if !seen[key] {
                seen[key] = true
                proxies = append(proxies, &Proxy{
                    Host:     host,
                    Port:     port,
                    Protocol: "http",
                })
            }
        }
    }
    return proxies
}

func (pc *ProxyCrawler) checkWorker(wg *sync.WaitGroup, proxyChan <-chan *Proxy) {
    defer wg.Done()
    for proxy := range proxyChan {
        pc.checkProxy(proxy)
    }
}

func (pc *ProxyCrawler) checkProxy(proxy *Proxy) {
    proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%s", proxy.Host, proxy.Port))
    if err != nil {
        return
    }

    client := &http.Client{
        Transport: &http.Transport{
            Proxy: http.ProxyURL(proxyURL),
            DialContext: (&net.Dialer{
                Timeout:   3 * time.Second,
                KeepAlive: 0,
            }).DialContext,
            DisableKeepAlives:     true,
            MaxIdleConns:          1,
            IdleConnTimeout:       1 * time.Second,
            TLSHandshakeTimeout:   3 * time.Second,
            ExpectContinueTimeout: 1 * time.Second,
        },
        Timeout: 3 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }

    var proxyIP string
    var speeds []time.Duration
    attemptPassed := 0

    for _, checkURL := range pc.checkURLs {
        attemptStart := time.Now()
        resp, err := client.Get(checkURL)
        if err != nil {
            continue
        }

        body, err := io.ReadAll(io.LimitReader(resp.Body, 10240))
        resp.Body.Close()

        if err != nil || resp.StatusCode != 200 {
            continue
        }

        ip := strings.TrimSpace(string(body))
        if len(ip) > 7 && len(ip) < 50 && strings.Contains(ip, ".") {
            if proxyIP == "" {
                proxyIP = ip
            }
            if ip != pc.realIP && ip != "" {
                attemptPassed++
                speeds = append(speeds, time.Since(attemptStart))
            }
        }
    }

    if attemptPassed >= 2 && len(speeds) >= 2 {
        var totalSpeed time.Duration
        for _, s := range speeds {
            totalSpeed += s
        }
        avgSpeed := totalSpeed / time.Duration(len(speeds))
        if avgSpeed > 3*time.Second {
            return
        }

        anonymity := "anonymous"
        if proxyIP == pc.realIP {
            anonymity = "transparent"
        }
        country := pc.getCountry(proxyIP)

        proxy.IsWorking = true
        proxy.Speed = avgSpeed
        proxy.LastCheck = time.Now()
        proxy.ChecksPassed = len(speeds)
        proxy.Anonymity = anonymity
        proxy.Country = country

        pc.mu.Lock()
        pc.proxies[proxy.Host+":"+proxy.Port] = proxy
        pc.mu.Unlock()

        fmt.Printf("✅ %s:%s | %s | %s | %v\n",
            proxy.Host, proxy.Port, country, anonymity, avgSpeed.Round(time.Millisecond))
    } else {
        pc.mu.Lock()
        key := proxy.Host + ":" + proxy.Port
        if existing, ok := pc.proxies[key]; ok {
            existing.IsWorking = false
        }
        pc.mu.Unlock()
    }
}

// === NEW: recheck from DB ===
func (pc *ProxyCrawler) RecheckFromDB() {
    fmt.Println("🔁 Начинаем ревалидацию прокси из БД...")

    resp, err := http.Get("http://localhost:8000/api/proxy-list-all?limit=50000")
    if err != nil {
        fmt.Printf("❌ Не удалось получить прокси из БД: %v\n", err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        body, _ := io.ReadAll(resp.Body)
        fmt.Printf("❌ API вернул статус %d: %s\n", resp.StatusCode, string(body))
        return
    }

    var data struct {
        Proxies []Proxy `json:"proxies"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
        fmt.Printf("❌ Ошибка парсинга JSON: %v\n", err)
        return
    }

    fmt.Printf("📥 Получено %d прокси из БД\n", len(data.Proxies))
    if len(data.Proxies) == 0 {
        fmt.Println("ℹ️  В БД нет прокси — пропускаем ревалидацию")
        return
    }

    var wg sync.WaitGroup
    proxyChan := make(chan *Proxy, 1000)

    for i := 0; i < pc.workerCount; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for p := range proxyChan {
                pc.checkProxyAndUpdate(p)
            }
        }()
    }

    for i, p := range data.Proxies {
        proxy := &Proxy{
            Host:      p.Host,
            Port:      p.Port,
            Protocol:  "http",
            Country:   p.Country,
            Anonymity: p.Anonymity,
            Speed:     time.Duration(p.SpeedMs) * time.Millisecond,
        }
        proxyChan <- proxy

        if (i+1)%1000 == 0 {
            fmt.Printf("📤 Отправлено на проверку: %d/%d\n", i+1, len(data.Proxies))
        }
    }
    close(proxyChan)
    wg.Wait()

    fmt.Println("✅ Ревалидация завершена")
}

func (pc *ProxyCrawler) checkProxyAndUpdate(proxy *Proxy) {
    proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%s", proxy.Host, proxy.Port))
    if err != nil {
        return
    }

    client := &http.Client{
        Transport: &http.Transport{
            Proxy: http.ProxyURL(proxyURL),
            DialContext: (&net.Dialer{
                Timeout:   3 * time.Second,
                KeepAlive: 0,
            }).DialContext,
            DisableKeepAlives:     true,
            MaxIdleConns:          1,
            IdleConnTimeout:       1 * time.Second,
            TLSHandshakeTimeout:   3 * time.Second,
            ExpectContinueTimeout: 1 * time.Second,
        },
        Timeout: 3 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }

    var proxyIP string
    var speeds []time.Duration
    attemptPassed := 0

    for _, checkURL := range pc.checkURLs {
        attemptStart := time.Now()
        resp, err := client.Get(checkURL)
        if err != nil {
            continue
        }

        body, err := io.ReadAll(io.LimitReader(resp.Body, 10240))
        resp.Body.Close()

        if err != nil || resp.StatusCode != 200 {
            continue
        }

        ip := strings.TrimSpace(string(body))
        if len(ip) > 7 && len(ip) < 50 && strings.Contains(ip, ".") {
            if proxyIP == "" {
                proxyIP = ip
            }
            if ip != pc.realIP && ip != "" {
                attemptPassed++
                speeds = append(speeds, time.Since(attemptStart))
            }
        }
    }

    isAlive := attemptPassed >= 2 && len(speeds) >= 2
    var avgSpeed time.Duration
    if isAlive {
        for _, s := range speeds {
            avgSpeed += s
        }
        avgSpeed /= time.Duration(len(speeds))
        if avgSpeed > 3*time.Second {
            isAlive = false
        }
    }

    anonymity := "anonymous"
    if proxyIP == pc.realIP {
        anonymity = "transparent"
    }
    country := pc.getCountry(proxyIP)

    updatePayload := map[string]interface{}{
        "host":      proxy.Host,
        "port":      proxy.Port,
        "geo":       country,
        "anonymity": anonymity,
        "speed_ms":  int(avgSpeed.Milliseconds()),
        "is_alive":  isAlive,
    }

    jsonData, _ := json.Marshal([]map[string]interface{}{updatePayload})
    _, err = http.Post(
        "http://localhost:8000/api/proxy-batch-update",
        "application/json",
        bytes.NewBuffer(jsonData),
    )
    if err != nil {
        fmt.Printf("⚠️  Не удалось обновить %s:%s: %v\n", proxy.Host, proxy.Port, err)
        return
    }

    if isAlive {
        fmt.Printf("✅ %s:%s | %s | %s | %v\n",
            proxy.Host, proxy.Port, country, anonymity, avgSpeed.Round(time.Millisecond))
    } else {
        fmt.Printf("❌ %s:%s\n", proxy.Host, proxy.Port)
    }
}

func (pc *ProxyCrawler) getCountry(ip string) string {
    return "unknown"
}

func (pc *ProxyCrawler) printStats() {
    pc.mu.RLock()
    defer pc.mu.RUnlock()

    working := 0
    var totalSpeed time.Duration
    countryStats := make(map[string]int)
    anonymityStats := make(map[string]int)

    for _, proxy := range pc.proxies {
        if proxy.IsWorking {
            working++
            totalSpeed += proxy.Speed
            countryStats[proxy.Country]++
            anonymityStats[proxy.Anonymity]++
        }
    }

    fmt.Printf("\n=== Статистика ===\n")
    fmt.Printf("Всего прокси в базе: %d\n", len(pc.proxies))
    fmt.Printf("Рабочих прокси: %d\n", working)
    if working > 0 {
        avgSpeed := totalSpeed / time.Duration(working)
        fmt.Printf("Средняя скорость: %v\n", avgSpeed.Round(time.Millisecond))
    }

    fmt.Printf("\nПо странам:\n")
    for country, count := range countryStats {
        fmt.Printf("  %s: %d\n", country, count)
    }

    fmt.Printf("\nПо анонимности:\n")
    for anon, count := range anonymityStats {
        fmt.Printf("  %s: %d\n", anon, count)
    }
    fmt.Println()
}

func (pc *ProxyCrawler) GetWorkingProxies() []*Proxy {
    pc.mu.RLock()
    defer pc.mu.RUnlock()

    var working []*Proxy
    for _, proxy := range pc.proxies {
        if proxy.IsWorking {
            working = append(working, proxy)
        }
    }
    return working
}

func (pc *ProxyCrawler) ExportToFile(filename string) error {
    working := pc.GetWorkingProxies()

    var content strings.Builder
    content.WriteString("# Рабочие прокси | Формат: IP:PORT | Country | Anonymity | Speed\n")
    content.WriteString("# Сгенерировано: " + time.Now().Format("2006-01-02 15:04:05") + "\n\n")

    for _, proxy := range working {
        content.WriteString(fmt.Sprintf("%s:%s\n", proxy.Host, proxy.Port))
    }

    err := os.WriteFile(filename, []byte(content.String()), 0644)
    if err != nil {
        return fmt.Errorf("ошибка сохранения файла: %v", err)
    }

    var detailedContent strings.Builder
    detailedContent.WriteString("# Детальная информация о прокси\n")
    detailedContent.WriteString("# IP:PORT | Country | Anonymity | Speed | Checks\n\n")

    for _, proxy := range working {
        detailedContent.WriteString(fmt.Sprintf("%s:%s | %s | %s | %v | %d/3\n",
            proxy.Host, proxy.Port, proxy.Country, proxy.Anonymity,
            proxy.Speed.Round(time.Millisecond), proxy.ChecksPassed))
    }

    detailedFilename := strings.Replace(filename, ".txt", "_detailed.txt", 1)
    os.WriteFile(detailedFilename, []byte(detailedContent.String()), 0644)

    fmt.Printf("✓ Экспортировано %d рабочих прокси в %s\n", len(working), filename)
    fmt.Printf("✓ Детальная информация сохранена в %s\n", detailedFilename)
    return nil
}

// === NEW: collect-only helpers ===
func (pc *ProxyCrawler) collectProxies() []*Proxy {
    var allProxies []*Proxy
    var mu sync.Mutex
    var wg sync.WaitGroup

    for i, src := range pc.sources {
        wg.Add(1)
        go func(idx int, url string) {
            defer wg.Done()
            proxies := pc.fetchFromSource(url)
            if len(proxies) > 0 {
                mu.Lock()
                allProxies = append(allProxies, proxies...)
                mu.Unlock()
            }
        }(i, src)
    }
    wg.Wait()
    return allProxies
}

func (pc *ProxyCrawler) sendNewProxiesToDB(proxies []*Proxy) {
    if len(proxies) == 0 {
        return
    }

    batch := make([]map[string]interface{}, 0, 500)
    for _, p := range proxies {
        batch = append(batch, map[string]interface{}{
            "host":      p.Host,
            "port":      p.Port,
            "geo":       "??",
            "anonymity": "unknown",
            "speed_ms":  0,
            "is_alive":  false,
        })
        if len(batch) >= 500 {
            pc.sendBatchToAPI(batch)
            batch = batch[:0]
        }
    }
    if len(batch) > 0 {
        pc.sendBatchToAPI(batch)
    }
}

func (pc *ProxyCrawler) sendBatchToAPI(batch []map[string]interface{}) {
    data, _ := json.Marshal(batch)
    resp, err := http.Post(
        "http://localhost:8000/api/proxy-batch",
        "application/json",
        bytes.NewBuffer(data),
    )
    if err != nil {
        fmt.Printf("⚠️ API send failed: %v\n", err)
        return
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        body, _ := io.ReadAll(resp.Body)
        fmt.Printf("⚠️ API error %d: %s\n", resp.StatusCode, string(body))
    } else {
        fmt.Printf("✅ Sent %d proxies to DB\n", len(batch))
    }
}

// === MAIN ===
func main() {
    fmt.Println("=== Proxy Crawler & Checker ===")

    recheckDB := flag.Bool("recheck-db", false, "Проверить ВСЕ прокси из БД")
    collectOnly := flag.Bool("collect-only", false, "Собрать новые прокси (без проверки)")
    flag.Parse()

    crawler := NewProxyCrawler()

    if *recheckDB {
        fmt.Println("🔧 Режим: ревалидация существующих прокси")
        crawler.RecheckFromDB()
        return
    }

    if *collectOnly {
        fmt.Println("📥 Режим: сбор новых прокси")
        proxies := crawler.collectProxies()
        fmt.Printf("✅ Собрано %d новых прокси\n", len(proxies))
        crawler.sendNewProxiesToDB(proxies)
        return
    }

    fmt.Println("🔄 Режим: полный цикл (сбор + проверка)")
    crawler.crawlProxies()
    crawler.ExportToFile("working_proxies.txt")
}
