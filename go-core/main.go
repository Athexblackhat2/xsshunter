package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/valyala/fasthttp"
)

type Config struct {
	Port         int
	CallbackPort int
	CallbackHost string
}

var cfg Config

type CrawlRequest struct {
	URL      string `json:"url"`
	Depth    int    `json:"depth"`
	JSCrawl  bool   `json:"js_crawl"`
	MaxPages int    `json:"max_pages"`
}

type Endpoint struct {
	URL    string            `json:"url"`
	Method string            `json:"method"`
	Params map[string]string `json:"params"`
	Body   string            `json:"body"`
	Source string            `json:"source"` // "link", "form", "js", "param"
}

type CrawlResponse struct {
	Success   bool       `json:"success"`
	Endpoints []Endpoint `json:"endpoints"`
	Count     int        `json:"count"`
	Duration  string     `json:"duration"`
	Error     string     `json:"error,omitempty"`
}

type FireRequest struct {
	Endpoints []Endpoint `json:"endpoints"`
	Payloads  []Payload  `json:"payloads"`
	Headers   []string   `json:"headers"`
	Proxy     string     `json:"proxy"`
	Timeout   int        `json:"timeout_ms"`
	Workers   int        `json:"workers"`
}

type Payload struct {
	ID      string `json:"id"`
	Raw     string `json:"raw"`
	Context string `json:"context"`
	Vendor  string `json:"vendor,omitempty"`
}

type FireResult struct {
	PayloadID  string `json:"payload_id"`
	Payload    string `json:"payload"`
	URL        string `json:"url"`
	Method     string `json:"method"`
	Param      string `json:"param"`
	StatusCode int    `json:"status_code"`
	Reflected  bool   `json:"reflected"`
	Evidence   string `json:"evidence"`
	Duration   string `json:"duration"`
}

type FireResponse struct {
	Success bool         `json:"success"`
	Results []FireResult `json:"results"`
	Total   int          `json:"total"`
	Hits    int          `json:"hits"`
	Error   string       `json:"error,omitempty"`
}

type CallbackInfo struct {
	Token     string `json:"token"`
	CallbackURL string `json:"callback_url"`
}

// =========================================================
// Global HTTP client (fasthttp - fast)
// =========================================================
var httpClient *fasthttp.Client

// =========================================================
// Main
// =========================================================
func main() {
	// Flags
	port := flag.Int("port", 8080, "Go core API port")
	cbPort := flag.Int("callback-port", 8888, "Blind XSS callback port")
	cbHost := flag.String("callback-host", "127.0.0.1", "Callback server host")
	flag.Parse()

	cfg = Config{
		Port:         *port,
		CallbackPort: *cbPort,
		CallbackHost: *cbHost,
	}

	// Init HTTP client
	httpClient = &fasthttp.Client{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		MaxConnsPerHost: 500,
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("[+] XSSHunter Go Core starting...")
	log.Printf("[+] API port: %d", cfg.Port)
	log.Printf("[+] Callback port: %d", cfg.CallbackPort)

	// Start callback server (blind XSS)
	go StartCallbackServer(cfg.CallbackHost, cfg.CallbackPort)

	// Start main API server
	go startAPIServer(cfg.Port)

	// Wait for shutdown signal
	waitForShutdown()
}

// =========================================================
// API Server (main Go core)
// =========================================================
func startAPIServer(port int) {
	handler := func(ctx *fasthttp.RequestCtx) {
		ctx.Response.Header.Set("Content-Type", "application/json")
		ctx.Response.Header.Set("Server", "XSSHunter-Core")

		path := string(ctx.Path())
		method := string(ctx.Method())

		switch {
		case path == "/health" && method == "GET":
			handleHealth(ctx)
		case path == "/crawl" && method == "POST":
			handleCrawl(ctx)
		case path == "/fire" && method == "POST":
			handleFire(ctx)
		case path == "/callback/info" && method == "GET":
			handleCallbackInfo(ctx)
		default:
			ctx.SetStatusCode(404)
			writeJSON(ctx, map[string]interface{}{
				"error": "not found",
				"path":  path,
			})
		}
	}

	server := &fasthttp.Server{
		Handler:            handler,
		Name:               "XSSHunter-Core",
		MaxRequestBodySize: 50 * 1024 * 1024, // 50MB
		ReadTimeout:        30 * time.Second,
		WriteTimeout:       60 * time.Second,
	}

	addr := fmt.Sprintf(":%d", port)
	log.Printf("[+] API server listening on %s", addr)
	if err := server.ListenAndServe(addr); err != nil {
		log.Fatalf("[-] API server failed: %v", err)
	}
}

// =========================================================
// Handlers
// =========================================================
func handleHealth(ctx *fasthttp.RequestCtx) {
	writeJSON(ctx, map[string]interface{}{
		"status":    "ok",
		"service":   "xsshunter-core",
		"time":      time.Now().Format(time.RFC3339),
		"callback":  fmt.Sprintf("http://%s:%d", cfg.CallbackHost, cfg.CallbackPort),
	})
}

func handleCrawl(ctx *fasthttp.RequestCtx) {
	start := time.Now()

	var req CrawlRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		writeJSON(ctx, CrawlResponse{
			Success: false,
			Error:   "invalid json: " + err.Error(),
		})
		return
	}

	if req.URL == "" {
		writeJSON(ctx, CrawlResponse{
			Success: false,
			Error:   "url is required",
		})
		return
	}

	// Defaults
	if req.Depth == 0 {
		req.Depth = 2
	}
	if req.MaxPages == 0 {
		req.MaxPages = 100
	}

	log.Printf("[*] Crawling: %s (depth=%d, max=%d)", req.URL, req.Depth, req.MaxPages)

	endpoints, err := Crawl(req)
	duration := time.Since(start).String()

	if err != nil {
		writeJSON(ctx, CrawlResponse{
			Success:  false,
			Error:    err.Error(),
			Duration: duration,
		})
		return
	}

	log.Printf("[+] Crawl done: %d endpoints in %s", len(endpoints), duration)

	writeJSON(ctx, CrawlResponse{
		Success:   true,
		Endpoints: endpoints,
		Count:     len(endpoints),
		Duration:  duration,
	})
}

func handleFire(ctx *fasthttp.RequestCtx) {
	start := time.Now()

	var req FireRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		writeJSON(ctx, FireResponse{
			Success: false,
			Error:   "invalid json: " + err.Error(),
		})
		return
	}

	if len(req.Endpoints) == 0 || len(req.Payloads) == 0 {
		writeJSON(ctx, FireResponse{
			Success: false,
			Error:   "endpoints and payloads required",
		})
		return
	}

	// Defaults
	if req.Timeout == 0 {
		req.Timeout = 10000
	}
	if req.Workers == 0 {
		req.Workers = 50
	}

	log.Printf("[*] Firing %d payloads × %d endpoints (workers=%d)",
		len(req.Payloads), len(req.Endpoints), req.Workers)

	results := Fire(req)

	duration := time.Since(start).String()
	hits := 0
	for _, r := range results {
		if r.Reflected {
			hits++
		}
	}

	log.Printf("[+] Fire done: %d requests, %d hits in %s",
		len(results), hits, duration)

	writeJSON(ctx, FireResponse{
		Success: true,
		Results: results,
		Total:   len(results),
		Hits:    hits,
	})
}

func handleCallbackInfo(ctx *fasthttp.RequestCtx) {
	info := CallbackInfo{
		CallbackURL: fmt.Sprintf("http://%s:%d", cfg.CallbackHost, cfg.CallbackPort),
	}
	writeJSON(ctx, info)
}

// =========================================================
// Helpers
// =========================================================
func writeJSON(ctx *fasthttp.RequestCtx, data interface{}) {
	body, err := json.Marshal(data)
	if err != nil {
		ctx.SetStatusCode(500)
		ctx.SetBodyString(`{"error":"json marshal failed"}`)
		return
	}
	ctx.SetBody(body)
}

// =========================================================
// Graceful Shutdown
// =========================================================
func waitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	log.Printf("[!] Received signal: %v — shutting down...", sig)

	// Give time for in-flight requests
	time.Sleep(500 * time.Millisecond)
	log.Printf("[+] Goodbye.")
}