# quick-infra-debugger

Um utilitário CLI em Go para testes rápidos de conectividade e diagnóstico de infraestrutura: HTTP, TCP, TLS, Postgres, Redis e Kafka (simulação). Ideal para consultores que chegam em um cliente e precisam verificar rapidamente se serviços estão alcançáveis.

---

## go.mod

module github.com/seuusuario/quick-infra-debugger

go 1.22

require (
	github.com/go-redis/redis/v9 v9.1.0
	github.com/lib/pq v1.10.10
	github.com/segmentio/kafka-go v0.4.28
)


## cmd/debugger/main.go

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/seuusuario/quick-infra-debugger/internal/checks"
)

var (
	flagTargets = flag.String("targets", "", "Lista de targets separados por vírgula. Formatos: http://host:port/path, tcp://host:port, tls://host:port, pg://user:pass@host:port/db, redis://host:port, kafka://host:port/topic")
	flagTimeout = flag.Duration("timeout", 5*time.Second, "Timeout por tentativa")
	flagFormat  = flag.String("format", "table", "Saída: table|json")
)

func main() {
	flag.Parse()
	if strings.TrimSpace(*flagTargets) == "" {
		fmt.Fprintln(os.Stderr, "erro: informe --targets\nex: --targets http://example.com/health,tcp://10.0.0.1:22,pg://postgres:pass@db:5432/mydb")
		os.Exit(2)
	}

	ctx := context.Background()
	targets := strings.Split(*flagTargets, ",")

	results := make([]checks.Result, 0, len(targets))
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		r := checks.Run(ctx, t, *flagTimeout)
		results = append(results, r)
	}

	// imprimir
	switch strings.ToLower(*flagFormat) {
	case "json":
		checks.PrintJSON(os.Stdout, results)
	default:
		checks.PrintTable(os.Stdout, results)
	}
}


## internal/checks/checks.go

package checks

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-redis/redis/v9"
	_ "github.com/lib/pq"
	"github.com/segmentio/kafka-go"
)

// Result descreve o que cada check retornou
type Result struct {
	Target     string `json:"target"`
	Kind       string `json:"kind"`
	Status     string `json:"status"` // OK | FAIL
	Detail     string `json:"detail,omitempty"`
	LatencyMs  int64  `json:"latency_ms"`
	CheckedAt  string `json:"checked_at"`
}

func Run(ctx context.Context, rawTarget string, timeout time.Duration) Result {
	start := time.Now()
	u, err := url.Parse(rawTarget)
	if err != nil {
		return Result{Target: rawTarget, Kind: "unknown", Status: "FAIL", Detail: fmt.Sprintf("parse error: %v", err), LatencyMs: elapsedMs(start), CheckedAt: time.Now().Format(time.RFC3339)}
	}

	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		res := checkHTTP(ctx, rawTarget, timeout)
		res.Kind = "http"
		res.LatencyMs = elapsedMs(start)
		res.CheckedAt = time.Now().Format(time.RFC3339)
		return res
	case "tcp":
		res := checkTCP(ctx, u.Host, timeout)
		res.Kind = "tcp"
		res.Target = rawTarget
		res.LatencyMs = elapsedMs(start)
		res.CheckedAt = time.Now().Format(time.RFC3339)
		return res
	case "tls":
		res := checkTLS(ctx, u.Host, timeout)
		res.Kind = "tls"
		res.Target = rawTarget
		res.LatencyMs = elapsedMs(start)
		res.CheckedAt = time.Now().Format(time.RFC3339)
		return res
	case "pg", "postgres", "postgresql":
		res := checkPostgres(ctx, rawTarget, timeout)
		res.Kind = "postgres"
		res.LatencyMs = elapsedMs(start)
		res.CheckedAt = time.Now().Format(time.RFC3339)
		return res
	case "redis":
		res := checkRedis(ctx, u.Host, timeout)
		res.Kind = "redis"
		res.Target = rawTarget
		res.LatencyMs = elapsedMs(start)
		res.CheckedAt = time.Now().Format(time.RFC3339)
		return res
	case "kafka":
		// kafka://host:port/topic
		res := checkKafka(ctx, u.Host, strings.TrimPrefix(u.Path, "/"), timeout)
		res.Kind = "kafka"
		res.Target = rawTarget
		res.LatencyMs = elapsedMs(start)
		res.CheckedAt = time.Now().Format(time.RFC3339)
		return res
	default:
		return Result{Target: rawTarget, Kind: u.Scheme, Status: "FAIL", Detail: "scheme não suportado", LatencyMs: elapsedMs(start), CheckedAt: time.Now().Format(time.RFC3339)}
	}
}

func elapsedMs(start time.Time) int64 { return time.Since(start).Milliseconds() }

// checkHTTP realiza GET simples com timeout e mede status code
func checkHTTP(ctx context.Context, rawURL string, timeout time.Duration) Result {
	client := &http.Client{Timeout: timeout}
	start := time.Now()
	resp, err := client.Get(rawURL)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return Result{Target: rawURL, Status: "FAIL", Detail: err.Error(), LatencyMs: lat}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return Result{Target: rawURL, Status: "OK", Detail: resp.Status, LatencyMs: lat}
	}
	return Result{Target: rawURL, Status: "FAIL", Detail: resp.Status, LatencyMs: lat}
}

// checkTCP tenta abrir conexão TCP simples
func checkTCP(ctx context.Context, host string, timeout time.Duration) Result {
	start := time.Now()
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return Result{Target: host, Status: "FAIL", Detail: err.Error(), LatencyMs: lat}
	}
	conn.Close()
	return Result{Target: host, Status: "OK", LatencyMs: lat}
}

// checkTLS faz handshake TLS e retorna informação do certificado
func checkTLS(ctx context.Context, host string, timeout time.Duration) Result {
	start := time.Now()
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return Result{Target: host, Status: "FAIL", Detail: err.Error(), LatencyMs: lat}
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		detail := fmt.Sprintf("subject=%s; issuer=%s; validFrom=%s; validTo=%s", cert.Subject.CommonName, cert.Issuer.CommonName, cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
		return Result{Target: host, Status: "OK", Detail: detail, LatencyMs: lat}
	}
	return Result{Target: host, Status: "OK", Detail: "handshake ok (no cert details)", LatencyMs: lat}
}

// checkPostgres abre conexão e executa SELECT 1
func checkPostgres(ctx context.Context, dsn string, timeout time.Duration) Result {
	start := time.Now()
	// dsn esperado: pg://user:pass@host:port/db
	// converter para lib pq usa postgres://
	dsn2 := strings.Replace(dsn, "pg://", "postgres://", 1)
	db, err := sql.Open("postgres", dsn2)
	if err != nil {
		return Result{Target: dsn, Status: "FAIL", Detail: err.Error(), LatencyMs: time.Since(start).Milliseconds()}
	}
	defer db.Close()
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := db.PingContext(ctx2); err != nil {
		return Result{Target: dsn, Status: "FAIL", Detail: err.Error(), LatencyMs: time.Since(start).Milliseconds()}
	}
	return Result{Target: dsn, Status: "OK", Detail: "ping ok", LatencyMs: time.Since(start).Milliseconds()}
}

// checkRedis tenta PING
func checkRedis(ctx context.Context, host string, timeout time.Duration) Result {
	start := time.Now()
	opt := &redis.Options{Addr: host}
	rdb := redis.NewClient(opt)
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, err := rdb.Ping(ctx2).Result()
	if err != nil {
		return Result{Target: host, Status: "FAIL", Detail: err.Error(), LatencyMs: time.Since(start).Milliseconds()}
	}
	return Result{Target: host, Status: "OK", Detail: res, LatencyMs: time.Since(start).Milliseconds()}
}

// checkKafka faz uma tentativa simples de abrir conexão ao broker e ler metadata
func checkKafka(ctx context.Context, host string, topic string, timeout time.Duration) Result {
	start := time.Now()
	d := &kafka.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return Result{Target: host, Status: "FAIL", Detail: err.Error(), LatencyMs: time.Since(start).Milliseconds()}
	}
	defer conn.Close()
	// metadata (se topic não vazio, tenta buscar particion info)
	if topic != "" {
		p, err := conn.ReadPartitions(topic)
		if err != nil {
			// ainda considerar sucesso se broker respondeu
			return Result{Target: host, Status: "OK", Detail: fmt.Sprintf("connected; metadata error: %v", err), LatencyMs: time.Since(start).Milliseconds()}
		}
		return Result{Target: host, Status: "OK", Detail: fmt.Sprintf("connected; partitions=%d", len(p)), LatencyMs: time.Since(start).Milliseconds()}
	}
	return Result{Target: host, Status: "OK", Detail: "connected", LatencyMs: time.Since(start).Milliseconds()}
}

// Print helpers
func PrintJSON(w io.Writer, results []Result) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(results)
}

func PrintTable(w io.Writer, results []Result) {
	fmt.Fprintln(w, "Target\tKind\tStatus\tLatency_ms\tDetail")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", r.Target, r.Kind, r.Status, r.LatencyMs, sanitize(r.Detail))
	}
}

func sanitize(s string) string { if len(s) > 80 { return s[:77] + "..." } return s }
