package serve

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ordinarysim/prosvet/internal/demo"
	"github.com/ordinarysim/prosvet/internal/engine"
	"github.com/ordinarysim/prosvet/internal/i18n"
	"github.com/ordinarysim/prosvet/internal/model"
)

func newTestServer(t *testing.T) (*Server, *httptest.Server, *demo.Env) {
	t.Helper()
	env, err := demo.Start("test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.Close)
	s, err := New(Deps{
		Bundle:        i18n.New("en"),
		Catalog:       env.Catalog,
		NewEngine:     func() *engine.Engine { return env.Engine },
		DetectNetwork: func(context.Context) model.NetworkInfo { return demo.Network },
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	s.addr = strings.TrimPrefix(ts.URL, "http://")
	return s, ts, env
}

func do(t *testing.T, method, url string, hdr map[string]string, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, url, strings.NewReader(body))
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestSecurity(t *testing.T) {
	s, ts, _ := newTestServer(t)

	resp := do(t, "GET", ts.URL+"/", map[string]string{"Host": "evil.example:80"}, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign Host header must be rejected: %d", resp.StatusCode)
	}
	resp = do(t, "GET", ts.URL+"/", nil, "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("index: %d %v", resp.StatusCode, resp.Header)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), s.Token()) {
		t.Fatal("token must be embedded in the page")
	}
	resp = do(t, "POST", ts.URL+"/api/scan", nil, `{}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST without token must be rejected: %d", resp.StatusCode)
	}
	resp = do(t, "POST", ts.URL+"/api/scan", map[string]string{"X-Prosvet-Token": s.Token(), "Origin": "http://evil.example"}, `{}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin POST must be rejected: %d", resp.StatusCode)
	}
	if _, err := Listen("0.0.0.0:0"); err == nil {
		t.Fatal("non-loopback listen must be refused")
	}
}

func TestScanFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	s, ts, _ := newTestServer(t)
	resp := do(t, "POST", ts.URL+"/api/scan", map[string]string{"X-Prosvet-Token": s.Token(), "Content-Type": "application/json"}, `{"categories":["messengers"]}`)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("start: %d", resp.StatusCode)
	}
	resp = do(t, "POST", ts.URL+"/api/scan", map[string]string{"X-Prosvet-Token": s.Token()}, `{}`)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("second scan must conflict: %d", resp.StatusCode)
	}
	ev := do(t, "GET", ts.URL+"/api/events", nil, "")
	data, _ := io.ReadAll(ev.Body)
	if !strings.Contains(string(data), `"kind":"finished"`) || !strings.Contains(string(data), "Messenger A") {
		t.Fatalf("event stream incomplete: %s", data)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		r := do(t, "GET", ts.URL+"/report.html", nil, "")
		if r.StatusCode == http.StatusOK {
			b, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(b), "Messenger A") {
				t.Fatal("report.html missing results")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("report never became available")
		}
		time.Sleep(50 * time.Millisecond)
	}
	page := do(t, "GET", ts.URL+"/", nil, "")
	b, _ := io.ReadAll(page.Body)
	if !strings.Contains(string(b), "Messenger A") {
		t.Fatal("dashboard must show the last report")
	}
}

func TestOptInRequiresFlag(t *testing.T) {
	s, ts, env := newTestServer(t)
	env.Catalog.Categories[0].Consent = map[string]string{"en": "really?"}
	resp := do(t, "POST", ts.URL+"/api/scan", map[string]string{"X-Prosvet-Token": s.Token()}, `{"categories":["messengers"]}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("opt-in category without --all: %d", resp.StatusCode)
	}
}
