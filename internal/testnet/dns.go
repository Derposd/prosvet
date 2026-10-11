package testnet

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Record is the configured answer for a name.
type Record struct {
	A        []string
	NX       bool
	ServFail bool
	TXT      []string // for CH/IN TXT queries
}

// DNSServer is a fake recursive resolver over UDP.
type DNSServer struct {
	mu      sync.RWMutex
	records map[string]Record
	srv     *dns.Server
	Addr    string
}

// NewDNSServer starts a resolver on 127.0.0.1 with the given records
// (names without trailing dot).
func NewDNSServer(records map[string]Record) (*DNSServer, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &DNSServer{records: map[string]Record{}, Addr: pc.LocalAddr().String()}
	for k, v := range records {
		s.records[strings.ToLower(k)] = v
	}
	s.srv = &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(s.serve)}
	go func() { _ = s.srv.ActivateAndServe() }()
	return s, nil
}

// Set replaces the record for name.
func (s *DNSServer) Set(name string, r Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[strings.ToLower(name)] = r
}

// Close stops the server.
func (s *DNSServer) Close() error { return s.srv.Shutdown() }

func (s *DNSServer) serve(w dns.ResponseWriter, req *dns.Msg) {
	_ = w.WriteMsg(s.Answer(req))
}

// Answer builds the response for req.
func (s *DNSServer) Answer(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	if len(req.Question) == 0 {
		resp.Rcode = dns.RcodeFormatError
		return resp
	}
	q := req.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	s.mu.RLock()
	rec, ok := s.records[name]
	s.mu.RUnlock()
	switch {
	case !ok || rec.NX:
		resp.Rcode = dns.RcodeNameError
	case rec.ServFail:
		resp.Rcode = dns.RcodeServerFailure
	case q.Qtype == dns.TypeA:
		for _, a := range rec.A {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(a).To4(),
			})
		}
	case q.Qtype == dns.TypeTXT:
		for _, t := range rec.TXT {
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: q.Qclass, Ttl: 0},
				Txt: []string{t},
			})
		}
	}
	return resp
}

// DoHHandler serves RFC 8484 POST queries from the same records.
func (s *DNSServer) DoHHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		req := new(dns.Msg)
		if err := req.Unpack(body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		out, err := s.Answer(req).Pack()
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	})
}
