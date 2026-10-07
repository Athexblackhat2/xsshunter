package main

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valyala/fasthttp"
)

type job struct {
	Endpoint Endpoint
	Payload  Payload
	Param    string
	Method   string
}

func Fire(req FireRequest) []FireResult {
	var (
		results   []FireResult
		mu        sync.Mutex
		total     int64
		hits      int64
		blocked   int64
	)

	jobs := make(chan job, 1000)
	var wg sync.WaitGroup

	workers := req.Workers
	if workers <= 0 {
		workers = 50
	}
	if workers > 200 {
		workers = 200
	}

	timeout := time.Duration(req.Timeout) * time.Millisecond
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	customHeaders := parseHeaders(req.Headers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				res := fireOne(j, timeout, customHeaders)
				atomic.AddInt64(&total, 1)

				if res.Reflected {
					atomic.AddInt64(&hits, 1)
				}
				if res.StatusCode == 403 || res.StatusCode == 406 || res.StatusCode == 429 {
					atomic.AddInt64(&blocked, 1)
				}

				mu.Lock()
				results = append(results, res)
				mu.Unlock()
			}
		}()
	}

	go func() {
		for _, ep := range req.Endpoints {
			for _, p := range req.Payloads {

				// If endpoint has no params, inject into URL as ?x=payload
				if len(ep.Params) == 0 {
					jobs <- job{
						Endpoint: ep,
						Payload:  p,
						Param:    "__xss__",
						Method:   ep.Method,
					}
					continue
				}

				// Inject into each param
				for param := range ep.Params {
					jobs <- job{
						Endpoint: ep,
						Payload:  p,
						Param:    param,
						Method:   ep.Method,
					}
				}
			}
		}
		close(jobs)
	}()

	wg.Wait()

	fmt.Printf("[+] Fired %d requests | %d reflected | %d blocked\n",
		atomic.LoadInt64(&total),
		atomic.LoadInt64(&hits),
		atomic.LoadInt64(&blocked))

	return results
}

// =========================================================
// Fire one payload against one endpoint param
// =========================================================
func fireOne(j job, timeout time.Duration, customHeaders map[string]string) FireResult {
	start := time.Now()

	result := FireResult{
		PayloadID: j.Payload.ID,
		Payload:   j.Payload.Raw,
		URL:       j.Endpoint.URL,
		Method:    j.Method,
		Param:     j.Param,
	}

	// Build request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Headers
	req.Header.SetMethod(j.Method)
	req.Header.SetUserAgent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	// Custom headers (auth, cookies, etc.)
	for k, v := range customHeaders {
		req.Header.Set(k, v)
	}

	payload := j.Payload.Raw

	// ---------------------------------------------------------
	// Build request based on method
	// ---------------------------------------------------------
	switch j.Method {
	case "POST":
		buildPostRequest(req, j, payload)
	default:
		buildGetRequest(req, j, payload)
	}

	// ---------------------------------------------------------
	// Send
	// ---------------------------------------------------------
	err := httpClient.DoTimeout(req, resp, timeout)
	if err != nil {
		result.Evidence = "request error: " + err.Error()
		result.Duration = time.Since(start).String()
		return result
	}

	result.StatusCode = resp.StatusCode()
	body := string(resp.Body())
	bodyLower := strings.ToLower(body)

	// ---------------------------------------------------------
	// Reflection detection
	// ---------------------------------------------------------
	reflected := detectReflection(body, bodyLower, payload)

	if reflected {
		result.Reflected = true
		result.Evidence = extractEvidence(body, payload)
	}

	// WAF detection
	if isWAFBlock(resp.StatusCode(), body, resp.Header.Peek("Server")) {
		result.Evidence = "WAF_BLOCKED: " + result.Evidence
	}

	result.Duration = time.Since(start).String()
	return result
}

// =========================================================
// Build GET request with payload in query
// =========================================================
func buildGetRequest(req *fasthttp.Request, j job, payload string) {
	// Parse existing params
	params := make(map[string]string)
	for k, v := range j.Endpoint.Params {
		params[k] = v
	}
	// Inject
	params[j.Param] = payload

	// Build query string
	var parts []string
	for k, v := range params {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
	}

	fullURL := j.Endpoint.URL
	if !strings.Contains(fullURL, "?") {
		fullURL += "?"
	} else {
		fullURL += "&"
	}
	fullURL += strings.Join(parts, "&")

	req.SetRequestURI(fullURL)
}

// =========================================================
// Build POST request with payload in body
// =========================================================
func buildPostRequest(req *fasthttp.Request, j job, payload string) {
	params := make(map[string]string)
	for k, v := range j.Endpoint.Params {
		params[k] = v
	}
	params[j.Param] = payload

	// form-urlencoded
	var parts []string
	for k, v := range params {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
	}
	body := strings.Join(parts, "&")

	req.SetRequestURI(j.Endpoint.URL)
	req.Header.SetContentType("application/x-www-form-urlencoded")
	req.SetBodyString(body)
}

// =========================================================
// Reflection detection — multiple strategies
// =========================================================
func detectReflection(body, bodyLower, payload string) bool {
	if payload == "" {
		return false
	}

	// 1. Exact match
	if strings.Contains(body, payload) {
		return true
	}

	// 2. Case-insensitive exact
	if strings.Contains(bodyLower, strings.ToLower(payload)) {
		return true
	}

	// 3. URL-decoded match
	if decoded, err := url.QueryUnescape(payload); err == nil && decoded != payload {
		if strings.Contains(body, decoded) {
			return true
		}
	}

	// 4. HTML entity decoded (basic: &#60; &#x3c;)
	decoded := decodeHTMLEntities(payload)
	if decoded != payload && strings.Contains(body, decoded) {
		return true
	}

	// 5. Key portion match — check for signature fragments
	// (e.g., "onerror=alert" even if quotes escaped)
	signature := extractSignature(payload)
	if signature != "" && strings.Contains(bodyLower, strings.ToLower(signature)) {
		return true
	}

	return false
}

// =========================================================
// Extract evidence snippet — context around reflection
// =========================================================
func extractEvidence(body, payload string) string {
	idx := strings.Index(body, payload)
	if idx == -1 {
		// try case-insensitive
		idx = strings.Index(strings.ToLower(body), strings.ToLower(payload))
	}
	if idx == -1 {
		return ""
	}

	// Grab 100 chars before + 100 after
	start := idx - 100
	if start < 0 {
		start = 0
	}
	end := idx + len(payload) + 100
	if end > len(body) {
		end = len(body)
	}

	snippet := body[start:end]
	// Clean newlines
	snippet = strings.ReplaceAll(snippet, "\n", " ")
	snippet = strings.ReplaceAll(snippet, "\r", " ")
	return "..." + snippet + "..."
}

// =========================================================
// Decode common HTML entities
// =========================================================
func decodeHTMLEntities(s string) string {
	r := strings.NewReplacer(
		"&lt;", "<",
		"&gt;", ">",
		"&quot;", "\"",
		"&#39;", "'",
		"&apos;", "'",
		"&amp;", "&",
		"&#60;", "<",
		"&#62;", ">",
		"&#x3c;", "<",
		"&#x3C;", "<",
		"&#x3e;", ">",
		"&#x3E;", ">",
	)
	return r.Replace(s)
}

// =========================================================
// Extract signature — key marker from payload
// =========================================================
func extractSignature(payload string) string {
	// Common XSS markers
	markers := []string{
		"onerror=", "onload=", "onfocus=", "onmouseover=",
		"ontoggle=", "onstart=", "onbegin=", "onplay=",
		"alert(", "alert`", "confirm(", "prompt(",
		"<script", "<svg", "<img", "<iframe", "<details",
		"javascript:", "eval(",
	}
	lower := strings.ToLower(payload)
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return m
		}
	}
	return ""
}

// =========================================================
// WAF block detection
// =========================================================
func isWAFBlock(status int, body string, server []byte) bool {
	// Status-based
	if status == 403 || status == 406 || status == 429 || status == 503 {
		return true
	}

	// Body-based signatures
	bodyLower := strings.ToLower(body)
	wafSignatures := []string{
		"cloudflare", "access denied", "blocked",
		"request rejected", "security policy",
		"mod_security", "modsecurity", "akamai",
		"incapsula", "imperva", "sucuri", "f5 networks",
		"barracuda", "fortiweb", "wordfence",
		"web application firewall",
	}
	for _, sig := range wafSignatures {
		if strings.Contains(bodyLower, sig) {
			return true
		}
	}

	// Header-based
	serverLower := strings.ToLower(string(server))
	for _, sig := range []string{"cloudflare", "akamai", "sucuri", "imperva"} {
		if strings.Contains(serverLower, sig) {
			return true
		}
	}

	return false
}

// =========================================================
// Parse custom headers from []string{"Name: Value"}
// =========================================================
func parseHeaders(headers []string) map[string]string {
	out := make(map[string]string)
	for _, h := range headers {
		if i := strings.Index(h, ":"); i != -1 {
			k := strings.TrimSpace(h[:i])
			v := strings.TrimSpace(h[i+1:])
			if k != "" {
				out[k] = v
			}
		}
	}
	return out
}