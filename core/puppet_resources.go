package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// CachedResource represents a downloaded web resource (CSS, image, font, etc.)
// cached in memory for serving to puppet control clients.
type CachedResource struct {
	URL      string
	MimeType string
	Data     []byte
}

// ResourceCache manages cached web resources for a puppet instance.
// When the puppet browser loads a page, resource URLs in the extracted HTML are
// rewritten to point through our proxy. When the client browser requests these
// resources, they are downloaded on demand, cached, and served.
type ResourceCache struct {
	resources map[string]*CachedResource
	mu        sync.RWMutex
	puppetId  int
	client    *http.Client
}

// NewResourceCache creates a new resource cache for the given puppet instance.
func NewResourceCache(puppetId int) *ResourceCache {
	return &ResourceCache{
		resources: make(map[string]*CachedResource),
		puppetId:  puppetId,
		client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

// ResourceHash returns a hex-encoded SHA256 hash (32 chars) for cache keys.
func ResourceHash(rawURL string) string {
	h := sha256.Sum256([]byte(rawURL))
	return hex.EncodeToString(h[:16])
}

// Get retrieves a cached resource by its hash key.
func (rc *ResourceCache) Get(hash string) (*CachedResource, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	res, ok := rc.resources[hash]
	return res, ok
}

// FetchAndCache downloads a resource from the original URL and caches it.
// If the resource is already cached, returns the cached version immediately.
// CSS resources have their url() references rewritten to also go through the proxy.
func (rc *ResourceCache) FetchAndCache(rawURL string) (*CachedResource, error) {
	hash := ResourceHash(rawURL)

	rc.mu.RLock()
	if cached, ok := rc.resources[hash]; ok {
		rc.mu.RUnlock()
		return cached, nil
	}
	rc.mu.RUnlock()

	resp, err := rc.client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("fetch failed for %s: %v", truncateString(rawURL, 80), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, truncateString(rawURL, 80))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read failed for %s: %v", truncateString(rawURL, 80), err)
	}

	mimeType := resp.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	// For CSS files, rewrite url() references to go through our resource proxy
	if strings.Contains(mimeType, "text/css") || strings.HasSuffix(strings.ToLower(rawURL), ".css") {
		cssContent := string(data)
		cssContent = rc.rewriteCSSURLs(cssContent, rawURL)
		data = []byte(cssContent)
	}

	res := &CachedResource{
		URL:      rawURL,
		MimeType: mimeType,
		Data:     data,
	}

	rc.mu.Lock()
	rc.resources[hash] = res
	rc.mu.Unlock()

	return res, nil
}

var cssURLRegex = regexp.MustCompile(`url\(\s*(['"]?)([^'")\s]+)\1\s*\)`)

// rewriteCSSURLs rewrites url() references in CSS content to go through the resource proxy.
func (rc *ResourceCache) rewriteCSSURLs(css string, baseURL string) string {
	return cssURLRegex.ReplaceAllStringFunc(css, func(match string) string {
		submatches := cssURLRegex.FindStringSubmatch(match)
		if len(submatches) < 3 {
			return match
		}
		quote := submatches[1]
		rawURL := submatches[2]

		if strings.HasPrefix(rawURL, "data:") || strings.HasPrefix(rawURL, "blob:") || strings.HasPrefix(rawURL, "#") {
			return match
		}

		absoluteURL := resolveURL(baseURL, rawURL)
		proxyURL := fmt.Sprintf("/puppet/res/%d/?url=%s", rc.puppetId, url.QueryEscape(absoluteURL))
		return fmt.Sprintf("url(%s%s%s)", quote, proxyURL, quote)
	})
}

// resolveURL resolves a relative URL against a base URL.
func resolveURL(baseURL string, relativeURL string) string {
	if strings.HasPrefix(relativeURL, "http://") || strings.HasPrefix(relativeURL, "https://") {
		return relativeURL
	}
	if strings.HasPrefix(relativeURL, "//") {
		return "https:" + relativeURL
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return relativeURL
	}

	ref, err := url.Parse(relativeURL)
	if err != nil {
		return relativeURL
	}

	return base.ResolveReference(ref).String()
}
