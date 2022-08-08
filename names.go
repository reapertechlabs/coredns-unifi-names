package unifinames

import (
	"context"

	"log"
	"net"
	"regexp"

	"strings"

	"time"

	"sync"

	dns_val "github.com/THREATINT/go-net"
	"github.com/coredns/coredns/plugin"
	"github.com/juju/errors"
	"github.com/miekg/dns"
	"github.com/unpoller/unifi"
	"go.uber.org/atomic"
)

type unifinames struct {
	Next        plugin.Handler
	Config      *config
	aClients    []dns.A
	aaaaClients []dns.AAAA
	lastUpdate  time.Time
	IsReady     bool
	mu          sync.Mutex
	haveRoutine atomic.Bool
}

// ServeDNS implements the middleware.Handler interface.
func (p *unifinames) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if !p.haveRoutine.Load() {
		p.haveRoutine.Store(true)
		go func() {
			update := func() {
				p.mu.Lock()
				if p.Config.Debug {
					log.Println("[unifi-names] updating clients")
				}
				if err := p.getClients(context.Background()); err != nil {
					p.mu.Unlock()
					log.Printf("[unifi-names] unable to get clients: %v\n", err)
					return
				}
				p.mu.Unlock()
				log.Printf("[unifi-names] got %d hosts", len(p.aClients)+len(p.aaaaClients))
				p.lastUpdate = time.Now()
			}
			update()
			t := time.NewTicker(time.Duration(p.Config.TTL) * time.Second)
			for range t.C {
				update()
			}
		}()
	}

	UnifinamesCount.Inc()
	if p.resolve(w, r) {
		return dns.RcodeSuccess, nil
	}

	return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
}

// Name implements the Handler interface.
func (*unifinames) Name() string { return "unifi-names" }

func (p *unifinames) resolve(w dns.ResponseWriter, r *dns.Msg) bool {
	if len(r.Question) <= 0 {
		return false
	}

	var rrs []dns.RR

	for i := 0; i < len(r.Question); i++ {
		question := r.Question[i]
		if question.Qclass != dns.ClassINET {
			continue
		}

		switch question.Qtype {
		case dns.TypeA:
			if p.shouldHandle(strings.ToLower(question.Name)) {
				p.mu.Lock()
				for _, client := range p.aClients {
					if strings.EqualFold(client.Hdr.Name, question.Name) {
						client.Hdr.Ttl = p.Config.TTL - uint32(time.Now().Sub(p.lastUpdate).Seconds())
						rrs = append(rrs, &client)
						break
					}
				}
				p.mu.Unlock()
			}
		case dns.TypeAAAA:
			if p.shouldHandle(strings.ToLower(question.Name)) {
				p.mu.Lock()
				for _, client := range p.aaaaClients {
					if strings.EqualFold(client.Hdr.Name, question.Name) {
						client.Hdr.Ttl = p.Config.TTL - uint32(time.Now().Sub(p.lastUpdate).Seconds())
						rrs = append(rrs, &client)
						break
					}
				}
				p.mu.Unlock()
			}
		}
	}

	if len(rrs) > 0 {
		if p.Config.Debug {
			log.Printf("[unifi-names] Answering with %d rr's\n", len(rrs))
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = rrs
		w.WriteMsg(m)
		return true
	}
	return false
}

func (p *unifinames) shouldHandle(name string) bool {
	for _, domain := range p.Config.Networks {
		if strings.HasSuffix(name, domain) {
			return true
		}
	}
	return false
}

var reSetCookieToken = regexp.MustCompile(`unifises=([0-9a-zA-Z]+)`)

func (p *unifinames) getClients(ctx context.Context) error {
	var c unifi.Config

	c = unifi.Config{
		User:      p.Config.UnifiUsername,
		Pass:      p.Config.UnifiPassword,
		URL:       p.Config.UnifiControllerURL,
		VerifySSL: p.Config.UnifiVerifySSL,
	}

	uni, err := unifi.NewUnifi(&c)
	if err != nil {
		return errors.Annotate(err, "coredns-unifi-names: unable to create unifi client")
	}

	sites, err := uni.GetSites()
	if err != nil {
		return errors.Annotate(err, "coredns-unifi-names: unable to get sites")
	}

	clients, err := uni.GetClients(sites)
	if err != nil {
		return errors.Annotate(err, "coredns-unifi-names: unable to get clients")
	}

	p.aClients = nil
	p.aaaaClients = nil

	for _, entry := range clients {
		dns_name := ""

		if p.Config.UseNameAsHostname {
			dns_name = strings.ToLower(sanitizeName(entry.Name))
			if entry.Name == "" {
				continue
			}
		} else {
			dns_name = strings.ToLower(sanitizeName(entry.Hostname))
			if entry.Hostname == "" {
				continue
			}
		}

		if dns_name == "" {
			continue
		}

		if dns_val.IsFQDN(dns_name) {
			continue
		}

		ip := net.ParseIP(entry.IP)
		if ip == nil {
			continue
		}

		domain, ok := p.Config.Networks[strings.ToLower(entry.Network)]
		if !ok {
			continue
		}

		if p.Config.Debug {
			log.Printf("[unifi-names] adding %s %s\n", entry.Name+"."+domain, entry.IP)
		}

		hdr := dns.RR_Header{
			Name:     dns_name + "." + domain,
			Rrtype:   0,
			Class:    dns.ClassINET,
			Ttl:      0,
			Rdlength: 0,
		}

		if ip.To4() != nil {
			hdr.Rrtype = dns.TypeA
			p.aClients = append(p.aClients, dns.A{
				Hdr: hdr,
				A:   ip,
			})
		} else {
			hdr.Rrtype = dns.TypeAAAA
			p.aaaaClients = append(p.aaaaClients, dns.AAAA{
				Hdr:  hdr,
				AAAA: ip,
			})
		}
	}

	UnifinamesHostsCount.Set(float64(len(p.aClients) + len(p.aaaaClients)))
	return nil

}

func isAllowedRune(allowedRunes []rune, r rune) bool {
	for _, a := range allowedRunes {
		if a == r {
			return true
		}
	}
	return false
}

func sanitizeName(s string) string {
	var allowedRunes = []rune("abcdefghijklmnopqrstuvwxyz12345679-")
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)

	var sb strings.Builder
	r := []rune(s)
	size := len(r)
	for i := 0; i < size; i++ {
		if isAllowedRune(allowedRunes, r[i]) {
			sb.WriteRune(r[i])
		} else {
			sb.WriteRune('-')
		}
	}

	// remove --
	return strings.Join(strings.FieldsFunc(sb.String(), func(r rune) bool {
		return r == '-'
	}), "-")
}

func (p *unifinames) Ready() bool {
	if p.IsReady == false {
		p.mu.Lock()
		if p.Config.Debug {
			log.Println("[unifi-names] updating clients")
		}
		if err := p.getClients(context.Background()); err != nil {
			log.Printf("[unifi-names] unable to get clients: %v\n", err)
			p.IsReady = true
		}
		p.mu.Unlock()
		log.Printf("[unifi-names] got %d hosts", len(p.aClients)+len(p.aaaaClients))
		p.lastUpdate = time.Now()
		p.IsReady = true
	}

	return p.IsReady
}
