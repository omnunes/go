# Project: config-validator-cli

## go.mod

module github.com/seuusuario/config-validator-cli

go 1.22.5

require (
	github.com/joho/godotenv v1.5.1
	github.com/santhosh-tekuri/jsonschema/v5 v5.3.1
	gopkg.in/yaml.v3 v3.0.1
)


## cmd/configval/main.go

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/seuusuario/config-validator-cli/internal/format"
	"github.com/seuusuario/config-validator-cli/internal/validator"
)

var (
	flagConfig     = flag.String("config", "", "Caminho do arquivo de configuração (.yaml, .yml, .json)")
	flagSchema     = flag.String("schema", "", "Caminho do arquivo JSON Schema (opcional)")
	flagFormat     = flag.String("format", "table", "Formato de saída: table|json")
	flagEnvFile    = flag.String("env", "", "Caminho de um arquivo .env para carregar variáveis (opcional)")
	flagStrict     = flag.Bool("strict", false, "Falhar (exit 1) em qualquer aviso")
	flagReqKeys    = flag.String("required", "", "Lista de chaves obrigatórias separadas por vírgula (opcional)")
	flagFailOnWarn = flag.Bool("fail-on-warn", false, "Sinônimo de --strict (depreciado)")
)

func main() {
	flag.Parse()

	if *flagConfig == "" {
		fmt.Fprintln(os.Stderr, "erro: informe --config <arquivo>")
		flag.Usage()
		os.Exit(2)
	}

	opts := validator.Options{
		SchemaPath: *flagSchema,
		EnvPath:    *flagEnvFile,
	}

	if *flagFailOnWarn {
		*flagStrict = true
	}

	var reqKeys []string
	if strings.TrimSpace(*flagReqKeys) != "" {
		reqKeys = splitAndTrim(*flagReqKeys)
	}

	result := validator.Run(*flagConfig, reqKeys, opts)

	switch strings.ToLower(*flagFormat) {
	case "json":
		format.PrintJSON(os.Stdout, result)
	default:
		format.PrintTable(os.Stdout, result)
	}

	if result.HasErrors() || (*flagStrict && result.HasWarnings()) {
		os.Exit(1)
	}
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}


## internal/validator/types.go

package validator

// Severity indica o nível de um achado
// "warning" para questões não bloqueantes e "error" para falhas.
type Severity string

const (
	Warning Severity = "warning"
	Error   Severity = "error"
)

type Finding struct {
	Key      string   `json:"key"`
	Message  string   `json:"message"`
	Severity Severity `json:"severity"`
}

type Result struct {
	ConfigPath string    `json:"configPath"`
	SchemaPath string    `json:"schemaPath,omitempty"`
	Findings   []Finding `json:"findings"`
	Summary    Summary   `json:"summary"`
}

type Summary struct {
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
}

func (r *Result) addFinding(f Finding) {
	r.Findings = append(r.Findings, f)
	if f.Severity == Error {
		r.Summary.Errors++
	} else {
		r.Summary.Warnings++
	}
}

func (r *Result) HasErrors() bool   { return r.Summary.Errors > 0 }
func (r *Result) HasWarnings() bool { return r.Summary.Warnings > 0 }

// Options controla comportamento do validador

type Options struct {
	SchemaPath string
	EnvPath    string
}


## internal/validator/run.go

package validator

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/seuusuario/config-validator-cli/internal/util"
)

// Run executa o fluxo completo: carregar config, interpolar env, validar schema e regras básicas
func Run(configPath string, requiredKeys []string, opts Options) Result {
	res := Result{ConfigPath: configPath, SchemaPath: opts.SchemaPath}

	// 1) Carregar .env se houver
	if opts.EnvPath != "" {
		if err := util.LoadDotEnv(opts.EnvPath); err != nil {
			res.addFinding(Finding{Severity: Warning, Message: fmt.Sprintf("falha ao carregar .env: %v", err)})
		}
	}

	// 2) Ler arquivo
	raw, err := os.ReadFile(configPath)
	if err != nil {
		res.addFinding(Finding{Severity: Error, Message: fmt.Sprintf("não foi possível ler arquivo: %v", err)})
		return res
	}

	// 3) Detectar tipo
	ext := filepath.Ext(configPath)

	// 4) Decodificar para map[string]any
	var cfg map[string]any
	switch ext {
	case ".yaml", ".yml":
		cfg, err = util.ParseYAML(raw)
	case ".json":
		cfg, err = util.ParseJSON(raw)
	default:
		res.addFinding(Finding{Severity: Error, Message: fmt.Sprintf("extensão não suportada: %s", ext)})
		return res
	}
	if err != nil {
		res.addFinding(Finding{Severity: Error, Message: fmt.Sprintf("erro de parsing: %v", err)})
		return res
	}

	// 5) Interpolar variáveis de ambiente
	cfg = util.InterpolateEnv(cfg)

	// 6) Validar chaves obrigatórias simples
	for _, k := range requiredKeys {
		if !util.HasKey(cfg, k) {
			res.addFinding(Finding{Severity: Error, Key: k, Message: "chave obrigatória ausente"})
		}
	}

	// 7) Validar via JSON Schema (se fornecido)
	if opts.SchemaPath != "" {
		if err := ValidateWithSchema(cfg, opts.SchemaPath); err != nil {
			res.addFinding(Finding{Severity: Error, Message: fmt.Sprintf("schema inválido: %v", err)})
		}
	}

	return res
}

// toJSON é um utilitário para reserializar o mapa e garantir types estáveis (útil para libs de schema)
func toJSON(v any) ([]byte, error) { return json.Marshal(v) }

// readerFrom retorna um io.Reader a partir de bytes (para compor com libs externas)
func readerFrom(b []byte) io.Reader { return bytesReader(b) }

// bytesReader evita import direto de bytes em múltiplos arquivos
func bytesReader(b []byte) io.Reader { return &sliceReader{b: b} }

type sliceReader struct{ b []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	n := copy(p, r.b)
	r.b = r.b[n:]
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}


## internal/validator/schema.go

package validator

import (
	"fmt"
	"os"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/seuusuario/config-valid