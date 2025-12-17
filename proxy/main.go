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
	SpeedMs     int    `json:"speed_ms"`
	LastCheck   time.Time `json:"last_check,omitempty"`
	Country     string `json:"geo"`
	Geo         string `json:"-"`
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
			"https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
			"https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt",
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
	fmt.Fprintln(os.Stdout, "Ваш реальный IP:", ip)
	return ip
}

func (pc *ProxyCrawler) RecheckFromDB() {
	fmt.Fprintln(os.Stdout, "🔁 Начинаем ревалидацию прокси из БД...")

	resp, err := http.Get("http://localhost:8000/api/proxy-list-all?limit=100000")
	if err != nil {
		fmt.Fprintf(os.Stdout, "❌ Не удалось получить прокси из БД: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stdout, "❌ API вернул статус %d: %s\n", resp.StatusCode, string(body))
		return
	}

	var data struct {
		Proxies []Proxy `json:"proxies"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		fmt.Fprintf(os.Stdout, "❌ Ошибка парсинга JSON: %v\n", err)
		return
	}

	fmt.Fprintf(os.Stdout, "📥 Получено %d прокси из БД\n", len(data.Proxies))
	if len(data.Proxies) == 0 {
		fmt.Fprintln(os.Stdout, "ℹ️  В БД нет прокси — пропускаем ревалидацию")
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
			fmt.Fprintf(os.Stdout, "📤 Отправлено на проверку: %d/%d\n", i+1, len(data.Proxies))
		}
	}
	close(proxyChan)
	wg.Wait()

	fmt.Fprintln(os.Stdout, "✅ Ревалидация завершена: в БД остались только живые прокси")
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

	if isAlive {
		// ✅ Живой → обновляем в БД
		updatePayload := map[string]interface{}{
			"host":      proxy.Host,
			"port":      proxy.Port,
			"geo":       country,
			"anonymity": anonymity,
			"speed_ms":  int(avgSpeed.Milliseconds()),
			"is_alive":  true,
		}
		jsonData, _ := json.Marshal([]map[string]interface{}{updatePayload})
		http.Post("http://localhost:8000/api/proxy-batch-update", "application/json", bytes.NewBuffer(jsonData))

		fmt.Fprintf(os.Stdout, "✅ %s:%s | %s | %s | %v\n",
			proxy.Host, proxy.Port, country, anonymity, avgSpeed.Round(time.Millisecond))
	} else {
		// ❌ Мёртвый → УДАЛЯЕМ из БД
		deletePayload := []map[string]interface{}{{
			"host": proxy.Host,
			"port": proxy.Port,
		}}
		jsonData, _ := json.Marshal(deletePayload)
		http.Post("http://localhost:8000/api/proxy-delete", "application/json", bytes.NewBuffer(jsonData))

		fmt.Fprintf(os.Stdout, "❌ %s:%s\n", proxy.Host, proxy.Port)
	}
}

func (pc *ProxyCrawler) getCountry(ip string) string {
	return "unknown"
}

// collectProxies и sendNewProxiesToDB оставлены для совместимости
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
	http.Post("http://localhost:8000/api/proxy-batch", "application/json", bytes.NewBuffer(data))
}

func (pc *ProxyCrawler) fetchFromSource(sourceURL string) []*Proxy {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(sourceURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
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

func main() {
	fmt.Fprintln(os.Stdout, "=== Proxy Checker (Recheck-Only Mode) ===")

	recheckDB := flag.Bool("recheck-db", false, "Проверить ВСЕ прокси из БД и оставить только живые")
	flag.Parse()

	crawler := NewProxyCrawler()

	if *recheckDB {
		fmt.Fprintln(os.Stdout, "🔧 Режим: ревалидация + удаление мёртвых прокси")
		crawler.RecheckFromDB()
		return
	}

	// По умолчанию — ничего не делать. Только --recheck-db работает.
	fmt.Fprintln(os.Stdout, "ℹ️  Используйте --recheck-db для запуска")
}
