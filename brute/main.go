// vpn/brute/main.go
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ============================================
// Конфигурация
// ============================================
type Config struct {
	DBHost      string
	DBPort      int
	DBUser      string
	DBPassword  string
	DBName      string
	Geo         string
	MaxWorkers  int
	MetricsPort int
}

func main() {
	// Парсинг аргументов командной строки
	config := parseFlags()

	// Настройка логирования
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("🚀 Starting VPN Brute Service v1.0")
	log.Printf("📍 GEO: %s", config.Geo)
	log.Printf("👷 Max Workers: %d", config.MaxWorkers)

	// Подключение к БД
	db, err := connectDB(config)
	if err != nil {
		log.Fatalf("❌ Database connection failed: %v", err)
	}
	defer db.Close()

	log.Printf("✅ Connected to database")

	// Создаём контекст с возможностью отмены
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Запускаем Prometheus metrics сервер
	go startMetricsServer(config.MetricsPort)

	// Создаём и запускаем brute service
	bruteService := NewBruteService(db, config.Geo, config.MaxWorkers)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		if err := bruteService.Run(ctx); err != nil {
			log.Printf("❌ Brute service error: %v", err)
		}
	}()

	// Ожидаем сигнал завершения
	<-sigChan
	log.Printf("🛑 Shutdown signal received, gracefully stopping...")

	cancel() // Отменяем контекст

	// Даём время на graceful shutdown (максимум 30 секунд)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("✅ Brute service stopped gracefully")
	case <-time.After(30 * time.Second):
		log.Printf("⚠️ Forced shutdown after 30s timeout")
	}

	log.Printf("👋 Goodbye!")
}

// ============================================
// Парсинг флагов
// ============================================
func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.DBHost, "db-host", getEnv("DB_HOST", "localhost"), "Database host")
	flag.IntVar(&config.DBPort, "db-port", 5434, "Database port")
	flag.StringVar(&config.DBUser, "db-user", getEnv("DB_USER", "brute"), "Database user")
	flag.StringVar(&config.DBPassword, "db-pass", getEnv("DB_PASS", "securepass123"), "Database password")
	flag.StringVar(&config.DBName, "db-name", getEnv("DB_NAME", "brute_system"), "Database name")
	flag.StringVar(&config.Geo, "geo", getEnv("GEO", "US"), "Geography (US, EU, ASIA)")
	flag.IntVar(&config.MaxWorkers, "max-workers", 20, "Maximum concurrent brute workers")
	flag.IntVar(&config.MetricsPort, "metrics-port", 9091, "Prometheus metrics port")

	flag.Parse()

	return config
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// ============================================
// Подключение к БД
// ============================================
func connectDB(config *Config) (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		config.DBHost, config.DBPort, config.DBUser, config.DBPassword, config.DBName,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	// Настройка connection pool
	db.SetMaxOpenConns(30)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(time.Hour)

	// Проверка подключения
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}

	return db, nil
}

// ============================================
// Prometheus metrics сервер
// ============================================
func startMetricsServer(port int) {
	http.Handle("/metrics", promhttp.Handler())

	// Health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "healthy",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	addr := fmt.Sprintf(":%d", port)
	log.Printf("📊 Metrics server starting on %s", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("❌ Metrics server failed: %v", err)
	}
}
