package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq" // driver postgres
)

// Estrutura de cada check
type CheckResult struct {
	Service string `json:"service"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
	Latency string `json:"latency"`
}

// Config básica
var (
	httpTargets = []string{
		"https://www.google.com",
		"http://localhost:8080/health",
	}

	postgresDSN = os.Getenv("POSTGRES_DSN") // exemplo: "postgres://user:pass@localhost:5432/db?sslmode=disable"
)

func main() {
	http.HandleFunc("/status", statusHandler)

	port := getEnv("PORT", "9090")
	log.Printf("Health Aggregator rodando na porta %s 🚀", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	var results []CheckResult

	// Checa HTTP
	for _, url := range httpTargets {
		results = append(results, checkHTTP(url))
	}

	// Checa Postgres
	if postgresDSN != "" {
		results = append(results, checkPostgres(postgresDSN))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func checkHTTP(url string) CheckResult {
	start := time.Now()
	resp, err := http.Get(url)
	latency := time.Since(start)

	if err != nil {
		return CheckResult{Service: url, Status: "DOWN", Detail: err.Error(), Latency: latency.String()}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return CheckResult{Service: url, Status: "UNHEALTHY", Detail: resp.Status, Latency: latency.String()}
	}
	return CheckResult{Service: url, Status: "UP", Latency: latency.String()}
}

func checkPostgres(dsn string) CheckResult {
	start := time.Now()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return CheckResult{Service: "Postgres", Status: "DOWN", Detail: err.Error(), Latency: time.Since(start).String()}
	}
	defer db.Close()

	err = db.Ping()
	latency := time.Since(start)
	if err != nil {
		return CheckResult{Service: "Postgres", Status: "DOWN", Detail: err.Error(), Latency: latency.String()}
	}
	return CheckResult{Service: "Postgres", Status: "UP", Latency: latency.String()}
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}
