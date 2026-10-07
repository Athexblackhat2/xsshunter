package main

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
)

// =========================================================
// Crawler — colly-based, extracts endpoints + params + JS
// =========================================================

// Regex patterns for JS endpoint extraction
var (
	reJSURL     = regexp.MustCompile(`(?:"|')((?:https?:)?//[^"'\s]+|/[a-zA-Z0-9_\-/\.]+\?[^"'\s]+)(?:"|')`)
	reJSFetch   = regexp.MustCompile(`(?:fetch|axios\.(?:get|post|put|delete)|\.open)\s*\(\s*["']([^"']+)["']`)
	reJSVar     = regexp.MustCompile(`(?:url|endpoint|api|path|href|src)\s*[:=]\s*["']([^"']+)["']`)
	reFormAction = regexp.MustCompile(`(?i)<form[^>]+action=["']([^"']*)["']`)
	reScriptSrc = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
)

// =========================================================
// Main Crawl function — called from main.go
// =========================================================
func Crawl(req CrawlRequest) ([]Endpoint, error) {
	var (
		mu        sync.Mutex
		endpoints []Endpoint
		seen      = make(map[string]bool) // dedup
		seenJS    = make(map[string]bool)
		jsFiles   []string
		baseHost  string
	)

	// Extract base host for scope enforcement
	baseHost = extractHost(req.URL)
	if baseHost == "" {
		return nil, fmt.Errorf("invalid url: %s", req.URL)
	}

	// ---------------------------------------------------------
	// Colly collector setup
	// ---------------------------------------------------------
	c := colly.NewCollector(
		colly.AllowedDomains(baseHost),
		colly.MaxDepth(req.Depth),
		colly.Async(true),
		colly.UserAgent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"),
	)

	// Concurrency limits
	_ = c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: 10,
		Delay:       100 * time.Millisecond,
		RandomDelay: 50 * time.Millisecond,
	})

	// Timeouts
	c.SetRequestTimeout(15 * time.Second)

	// ---------------------------------------------------------
	// Helper: add endpoint with dedup
	// ---------------------------------------------------------
	addEndpoint := func(ep Endpoint) {
		mu.Lock()
		defer mu.Unlock()

		key := ep.Method + "|" + ep.URL
		// add param keys to key for uniqueness
		if len(ep.Params) > 0 {
			keys := make([]string, 0, len(ep.Params))
			for k := range ep.Params {
				keys = append(keys, k)
			}
			key += "|" + strings.Join(keys, ",")
		}

		if seen[key] {
			return
		}
		if len(endpoints) >= req.MaxPages*3 {
			return
		}
		seen[key] = true
		endpoints = append(endpoints, ep)
	}

	// ---------------------------------------------------------
	// 1. Links with query params
	// ---------------------------------------------------------
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Request.AbsoluteURL(e.Attr("href"))
		if link == "" || !isSameHost(link, baseHost) {
			return
		}

		// Only interested in URLs with params (injection points)
		if strings.Contains(link, "?") {
			params := parseQueryParams(link)
			if len(params) > 0 {
				addEndpoint(Endpoint{
					URL:    stripQuery(link),
					Method: "GET",
					Params: params,
					Source: "link",
				})
			}
		}
	})

	// ---------------------------------------------------------
	// 2. Forms — most common injection point
	// ---------------------------------------------------------
	c.OnHTML("form", func(e *colly.HTMLElement) {
		action := e.Request.AbsoluteURL(e.Attr("action"))
		if action == "" {
			action = e.Request.URL.String()
		}
		if !isSameHost(action, baseHost) {
			return
		}

		method := strings.ToUpper(e.Attr("method"))
		if method == "" {
			method = "GET"
		}

		params := make(map[string]string)

		// Inputs, textareas, selects
		e.ForEach("input, textarea, select", func(_ int, el *colly.HTMLElement) {
			name := el.Attr("name")
			if name == "" {
				return
			}
			val := el.Attr("value")
			params[name] = val
		})

		if len(params) > 0 {
			addEndpoint(Endpoint{
				URL:    stripQuery(action),
				Method: method,
				Params: params,
				Source: "form",
			})
		}
	})

	// ---------------------------------------------------------
	// 3. Script src collection (for JS analysis)
	// ---------------------------------------------------------
	c.OnHTML("script[src]", func(e *colly.HTMLElement) {
		src := e.Request.AbsoluteURL(e.Attr("src"))
		if src == "" {
			return
		}
		mu.Lock()
		if !seenJS[src] && len(jsFiles) < 50 {
			seenJS[src] = true
			jsFiles = append(jsFiles, src)
		}
		mu.Unlock()
	})

	// ---------------------------------------------------------
	// 4. Inline JS — extract endpoints from script blocks
	// ---------------------------------------------------------
	c.OnHTML("script:not([src])", func(e *colly.HTMLElement) {
		js := e.Text
		if len(js) < 10 {
			return
		}
		extractJSEndpoints(js, e.Request.URL.String(), baseHost, addEndpoint)
	})

	// ---------------------------------------------------------
	// 5. Response body JS scan (catches inline + external JS content)
	// ---------------------------------------------------------
	c.OnResponse(func(r *colly.Response) {
		body := string(r.Body)
		ct := strings.ToLower(r.Headers.Get("Content-Type"))

		// If it's a JS file, scan it
		if strings.Contains(ct, "javascript") || strings.HasSuffix(r.Request.URL.Path, ".js") {
			extractJSEndpoints(body, r.Request.URL.String(), baseHost, addEndpoint)
		}

		// Also scan HTML responses for JS patterns
		if strings.Contains(ct, "html") {
			extractJSEndpoints(body, r.Request.URL.String(), baseHost, addEndpoint)
		}
	})

	// ---------------------------------------------------------
	// 6. Error handling
	// ---------------------------------------------------------
	c.OnError(func(r *colly.Response, err error) {
		// Silent — many 404s expected during crawl
	})

	// ---------------------------------------------------------
	// Start crawl
	// ---------------------------------------------------------
	err := c.Visit(req.URL)
	if err != nil {
		return nil, fmt.Errorf("crawl failed: %w", err)
	}

	c.Wait()

	// ---------------------------------------------------------
	// Post-process: fetch JS files for deeper endpoint discovery
	// ---------------------------------------------------------
	mu.Lock()
	jsSnapshot := make([]string, len(jsFiles))
	copy(jsSnapshot, jsFiles)
	mu.Unlock()

	if req.JSCrawl && len(jsSnapshot) > 0 {
		fetchJSFiles(jsSnapshot, baseHost, addEndpoint)
	}

	// ---------------------------------------------------------
	// Final: ensure base URL is included (with no params - for testing)
	// ---------------------------------------------------------
	addEndpoint(Endpoint{
		URL:    req.URL,
		Method: "GET",
		Params: map[string]string{},
		Source: "base",
	})

	mu.Lock()
	defer mu.Unlock()
	return endpoints, nil
}

// =========================================================
// JS Endpoint Extraction
// =========================================================
func extractJSEndpoints(js, baseURL, baseHost string, add func(Endpoint)) {
	// 1. fetch/axios/.open calls
	for _, m := range reJSFetch.FindAllStringSubmatch(js, -1) {
		if len(m) < 2 {
			continue
		}
		path := m[1]
		abs := resolveURL(baseURL, path)
		if abs == "" || !isSameHost(abs, baseHost) {
			continue
		}
		params := parseQueryParams(abs)
		add(Endpoint{
			URL:    stripQuery(abs),
			Method: "GET",
			Params: params,
			Source: "js",
		})
	}

	// 2. var url = "..." patterns
	for _, m := range reJSVar.FindAllStringSubmatch(js, -1) {
		if len(m) < 2 {
			continue
		}
		path := m[1]
		abs := resolveURL(baseURL, path)
		if abs == "" || !isSameHost(abs, baseHost) {
			continue
		}
		params := parseQueryParams(abs)
		add(Endpoint{
			URL:    stripQuery(abs),
			Method: "GET",
			Params: params,
			Source: "js",
		})
	}

	// 3. Absolute URLs in JS
	for _, m := range reJSURL.FindAllStringSubmatch(js, -1) {
		if len(m) < 2 {
			continue
		}
		path := m[1]
		abs := resolveURL(baseURL, path)
		if abs == "" || !isSameHost(abs, baseHost) {
			continue
		}
		if !strings.Contains(abs, "?") && !strings.Contains(abs, "/api/") {
			continue
		}
		params := parseQueryParams(abs)
		add(Endpoint{
			URL:    stripQuery(abs),
			Method: "GET",
			Params: params,
			Source: "js",
		})
	}
}

// =========================================================
// Fetch external JS files for deeper scan
// =========================================================
func fetchJSFiles(jsFiles []string, baseHost string, add func(Endpoint)) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // 10 concurrent

	for _, jsURL := range jsFiles {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			body, err := fetchURL(u)
			if err != nil {
				return
			}
			extractJSEndpoints(body, u, baseHost, add)
		}(jsURL)
	}
	wg.Wait()
}

// =========================================================
// HTTP fetch using fasthttp (shared client)
// =========================================================
func fetchURL(url string) (string, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(url)
	req.Header.SetMethod("GET")
	req.Header.SetUserAgent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")

	if err := httpClient.DoTimeout(req, resp, 10*time.Second); err != nil {
		return "", err
	}
	return string(resp.Body()), nil
}

// =========================================================
// Helpers
// =========================================================

func extractHost(rawURL string) string {
	// strip scheme
	u := rawURL
	if i := strings.Index(u, "://"); i != -1 {
		u = u[i+3:]
	}
	// strip path
	if i := strings.IndexAny(u, "/?#"); i != -1 {
		u = u[:i]
	}
	// strip port
	if i := strings.Index(u, ":"); i != -1 {
		u = u[:i]
	}
	return strings.ToLower(u)
}

func isSameHost(rawURL, baseHost string) bool {
	return extractHost(rawURL) == baseHost
}

func stripQuery(rawURL string) string {
	if i := strings.Index(rawURL, "?"); i != -1 {
		return rawURL[:i]
	}
	if i := strings.Index(rawURL, "#"); i != -1 {
		return rawURL[:i]
	}
	return rawURL
}

func parseQueryParams(rawURL string) map[string]string {
	params := make(map[string]string)

	idx := strings.Index(rawURL, "?")
	if idx == -1 {
		return params
	}
	query := rawURL[idx+1:]
	if i := strings.Index(query, "#"); i != -1 {
		query = query[:i]
	}

	for _, pair := range strings.Split(query, "&") {
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, "=", 2)
		key := kv[0]
		val := ""
		if len(kv) == 2 {
			val = kv[1]
		}
		if key != "" {
			params[key] = val
		}
	}
	return params
}

func resolveURL(baseURL, path string) string {
	if path == "" {
		return ""
	}
	// Already absolute
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	// Protocol-relative
	if strings.HasPrefix(path, "//") {
		scheme := "https"
		if strings.HasPrefix(baseURL, "http://") {
			scheme = "http"
		}
		return scheme + ":" + path
	}

	// Parse base
	base := baseURL
	if i := strings.Index(base, "://"); i != -1 {
		scheme := base[:i]
		rest := base[i+3:]
		host := rest
		if j := strings.IndexAny(rest, "/?#"); j != -1 {
			host = rest[:j]
		}
		// Relative path
		if strings.HasPrefix(path, "/") {
			return scheme + "://" + host + path
		}
		// Relative to current dir
		dir := rest
		if j := strings.LastIndex(rest, "/"); j != -1 {
			dir = rest[:j+1]
		} else {
			dir = ""
		}
		return scheme + "://" + host + "/" + dir + path
	}
	return ""
}