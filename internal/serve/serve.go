// Package serve implements the local web dashboard (`prosvet serve`).
//
// Security model: the server binds to loopback only, rejects requests whose
// Host header is not the loopback address (DNS-rebinding protection),
// requires a per-process random token for every state-changing request
// (CSRF protection) and sends a strict Content-Security-Policy.
package serve

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ordinarysim/prosvet/internal/brand"
	"github.com/ordinarysim/prosvet/internal/catalog"
	"github.com/ordinarysim/prosvet/internal/engine"
	"github.com/ordinarysim/prosvet/internal/i18n"
	"github.com/ordinarysim/prosvet/internal/model"
	"github.com/ordinarysim/prosvet/internal/report"
)

//go:embed dashboard.html.tmpl
var dashboardTmpl string

//go:embed app.js
var appJS string

// Deps are the services the dashboard needs.
type Deps struct {
	Bundle        *i18n.Bundle
	Catalog       *catalog.Catalog
	NewEngine     func() *engine.Engine
	DetectNetwork func(ctx context.Context) model.NetworkInfo
	SaveReport    func(*model.Report)
	LoadReport    func() (*model.Report, error)
	AllowOptIn    bool // opt-in categories were confirmed on the command line
}

// Server is the dashboard HTTP server.
type Server struct {
	d     Deps
	token string
	tmpl  *template.Template
	addr  string

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	last    *model.Report
	subs    map[chan []byte]struct{}
	snap    []byte
}

// New creates a server.
func New(d Deps) (*Server, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	t, err := report.Templates().Parse(dashboardTmpl)
	if err != nil {
		return nil, err
	}
	s := &Server{d: d, token: hex.EncodeToString(b[:]), tmpl: t, subs: map[chan []byte]struct{}{}}
	if d.LoadReport != nil {
		if rep, err := d.LoadReport(); err == nil {
			s.last = rep
		}
	}
	return s, nil
}

// Token returns the CSRF token (tests).
func (s *Server) Token() string { return s.token }

// Listen binds to addr, which must be a loopback address.
func Listen(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("refusing to listen on %s: the dashboard is local-only (use 127.0.0.1)", addr)
	}
	return (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
}

// Serve runs the server on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.addr = ln.Addr().String()
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { //nolint:gosec // shutdown must outlive the cancelled serve context
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Handler returns the HTTP handler with all security middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /prosvet.css", static("text/css; charset=utf-8", brand.CSS))
	mux.HandleFunc("GET /app.js", static("text/javascript; charset=utf-8", appJS))
	mux.HandleFunc("GET /report.html", s.download("html"))
	mux.HandleFunc("GET /report.md", s.download("md"))
	mux.HandleFunc("GET /report.json", s.download("json"))
	mux.HandleFunc("GET /api/report", s.download("json"))
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("POST /api/scan", s.protect(s.startScan))
	mux.HandleFunc("POST /api/whitelist", s.protect(s.startWhitelist))
	mux.HandleFunc("POST /api/cancel", s.protect(s.cancelRun))
	return s.guard(mux)
}

func static(ctype, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ctype)
		_, _ = w.Write([]byte(body))
	}
}

// guard enforces the Host check and security headers on every request.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.allowedHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowedHost(host string) bool {
	h, port, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	if s.addr != "" {
		if _, want, err := net.SplitHostPort(s.addr); err == nil && port != want {
			return false
		}
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip != nil && ip.IsLoopback()
}

// protect requires the CSRF token and a same-origin request.
func (s *Server) protect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Prosvet-Token")
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) != 1 {
			http.Error(w, "missing or invalid token", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !s.allowedHost(strings.TrimPrefix(strings.TrimPrefix(o, "http://"), "https://")) {
			http.Error(w, "cross-origin request", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

type dashData struct {
	report.PageData
	Dash map[string]string
}

func (s *Server) index(w http.ResponseWriter, _ *http.Request) {
	b := s.d.Bundle
	s.mu.Lock()
	rep, running := s.last, s.running
	s.mu.Unlock()
	if rep == nil {
		rep = &model.Report{Schema: model.ReportSchema}
	}
	data := dashData{PageData: report.NewPageData(report.Build(rep, b, s.titles())), Dash: map[string]string{}}
	data.Token, data.Running = s.token, running
	for _, k := range []string{"title", "run", "whitelist", "cancel", "categories", "running", "empty", "download", "local_only"} {
		data.Dash[k] = b.T("dash." + k)
	}
	if s.d.Catalog != nil {
		for _, c := range s.d.Catalog.Categories {
			data.Cats = append(data.Cats, report.CatOption{ID: c.ID, Title: c.Title.Get(b.Lang), Checked: c.Default, OptIn: len(c.Consent) > 0})
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "dashboard", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) titles() report.CategoryTitles {
	t := report.CategoryTitles{}
	if s.d.Catalog != nil {
		for _, c := range s.d.Catalog.Categories {
			t[c.ID] = c.Title.Get(s.d.Bundle.Lang)
		}
	}
	return t
}

func (s *Server) download(format string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		rep := s.last
		s.mu.Unlock()
		if rep == nil {
			http.Error(w, "no report yet", http.StatusNotFound)
			return
		}
		v := report.Build(rep, s.d.Bundle, s.titles())
		var err error
		switch format {
		case "html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			err = report.WriteHTML(w, v)
		case "md":
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			err = report.WriteMarkdown(w, v)
		default:
			w.Header().Set("Content-Type", "application/json")
			err = report.WriteJSON(w, rep)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

type scanRequest struct {
	Categories []string `json:"categories"`
}

func (s *Server) begin() (context.Context, chan engine.Event, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return nil, nil, false
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.running, s.cancel, s.snap = true, cancel, nil
	ch := make(chan engine.Event, 64)
	go s.pump(ch)
	return ctx, ch, true
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	sel := catalog.Selection{Categories: req.Categories}
	if s.d.Catalog != nil {
		_, cats, err := s.d.Catalog.Select(sel)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for _, c := range cats {
			if len(c.Consent) > 0 && !s.d.AllowOptIn {
				http.Error(w, "opt-in category requires `prosvet serve --all`", http.StatusForbidden)
				return
			}
		}
	}
	ctx, ch, ok := s.begin()
	if !ok {
		http.Error(w, "a check is already running", http.StatusConflict)
		return
	}
	go func() {
		net := model.NetworkInfo{Conn: "unknown"}
		if s.d.DetectNetwork != nil {
			net = s.d.DetectNetwork(ctx)
		}
		rep, _ := s.d.NewEngine().Scan(ctx, sel, net, ch)
		close(ch)
		s.finish(rep)
	}()
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) startWhitelist(w http.ResponseWriter, _ *http.Request) {
	ctx, ch, ok := s.begin()
	if !ok {
		http.Error(w, "a check is already running", http.StatusConflict)
		return
	}
	go func() {
		net := model.NetworkInfo{Conn: "unknown"}
		if s.d.DetectNetwork != nil {
			net = s.d.DetectNetwork(ctx)
		}
		eng := s.d.NewEngine()
		res, _ := eng.Whitelist(ctx, ch)
		close(ch)
		var rep *model.Report
		if res != nil {
			rep = eng.NewReport(net)
			rep.Whitelist = res
			rep.FinishedAt = time.Now().UTC()
		}
		s.finish(rep)
	}()
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) cancelRun(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) finish(rep *model.Report) {
	if rep != nil && s.d.SaveReport != nil {
		s.d.SaveReport(rep)
	}
	s.mu.Lock()
	if rep != nil {
		s.last = rep
	}
	s.running, s.cancel = false, nil
	s.mu.Unlock()
	s.broadcast(eventJSON{Kind: "finished"})
}

type eventJSON struct {
	Kind      string      `json:"kind"`
	Done      int         `json:"done"`
	Total     int         `json:"total"`
	PhaseText string      `json:"phase_text,omitempty"`
	Target    *targetJSON `json:"target,omitempty"`
}

type targetJSON struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	StatusText string `json:"status_text"`
	KindTitle  string `json:"kind_title,omitempty"`
}

func (s *Server) pump(ch <-chan engine.Event) {
	b := s.d.Bundle
	for ev := range ch {
		out := eventJSON{Done: ev.Done, Total: ev.Total}
		switch ev.Kind {
		case engine.EventPhase:
			out.Kind, out.PhaseText = "phase", b.T("cli.phase."+ev.Phase)
		case engine.EventTarget:
			out.Kind = "target"
			if t := ev.Target; t != nil && t.Role != "baseline" {
				tj := &targetJSON{Name: t.Name, Status: string(t.Status), StatusText: b.Status(t.Status)}
				if t.Status != model.StatusOK {
					tj.KindTitle = b.KindTitle(t.Verdict.Kind)
				}
				out.Target = tj
			}
		case engine.EventStarted:
			out.Kind = "started"
		default:
			continue // "finished" is sent after the report is stored
		}
		s.broadcast(out)
	}
}

func (s *Server) broadcast(ev eventJSON) {
	data, _ := json.Marshal(ev)
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.Target == nil {
		s.snap = data
	}
	for c := range s.subs {
		select {
		case c <- data:
		default: // slow client: drop the event, the next one carries totals
		}
	}
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	ch := make(chan []byte, 32)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	snap, running := s.snap, s.running
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.subs, ch)
		s.mu.Unlock()
	}()
	if snap != nil {
		fmt.Fprintf(w, "data: %s\n\n", snap)
	}
	if !running {
		fmt.Fprintf(w, "data: {\"kind\":\"finished\"}\n\n")
		fl.Flush()
		return
	}
	fl.Flush()
	keep := time.NewTicker(15 * time.Second)
	defer keep.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case data := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", data)
			fl.Flush()
			if strings.Contains(string(data), `"kind":"finished"`) {
				return
			}
		case <-keep.C:
			fmt.Fprint(w, ": keep-alive\n\n")
			fl.Flush()
		}
	}
}
