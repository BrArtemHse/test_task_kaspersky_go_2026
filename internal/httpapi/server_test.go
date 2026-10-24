package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"threat-exchange/internal/store"
)

const testToken = "0123456789abcdef0123456789abcdef"
const hash = "d41d8cd98f00b204e9800998ecf8427e"

func newTestServer(t *testing.T, rps float64, burst int) (*httptest.Server, *store.Store) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	h, err := New(db, Options{Token: testToken, RPS: rps, Burst: burst, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s, db
}

func request(t *testing.T, s *httptest.Server, method, path, body, token, media string) (int, http.Header, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, s.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if media != "" {
		req.Header.Set("Content-Type", media)
	}
	res, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if !strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("non-JSON response: %v", res.Header)
	}
	var result map[string]any
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, res.Header, result
}

func TestHTTPCRUD(t *testing.T) {
	s, _ := newTestServer(t, 10000, 10000)
	body := `{"md5":"D41D8CD98F00B204E9800998ECF8427E","name":"  Trojan  ","severity":"high","category":"trojan","description":"initial","first_seen":"2020-01-01T00:00:00Z"}`
	status, headers, created := request(t, s, "POST", "/info", body, testToken, "application/json; charset=utf-8")
	if status != 201 || headers.Get("Location") != "/info/"+hash || created["md5"] != hash || created["name"] != "Trojan" {
		t.Fatalf("create: %d %v %v", status, headers, created)
	}
	status, _, got := request(t, s, "GET", "/info/"+strings.ToUpper(hash), "", testToken, "")
	if status != 200 || got["severity"] != "high" || got["first_seen"] != "2020-01-01T00:00:00Z" {
		t.Fatalf("get: %d %v", status, got)
	}
	status, _, _ = request(t, s, "POST", "/info", body, testToken, "application/json")
	if status != 409 {
		t.Fatalf("duplicate: %d", status)
	}
	status, _, updated := request(t, s, "PUT", "/info/"+hash, `{"name":"New"}`, testToken, "application/json")
	if status != 200 || updated["name"] != "New" || updated["description"] != "" || updated["severity"] != "unknown" || updated["category"] != "unknown" || updated["first_seen"] != nil || updated["created_at"] != created["created_at"] {
		t.Fatalf("update: %d %v", status, updated)
	}
	status, _, _ = request(t, s, "GET", "/info/"+strings.Repeat("a", 32), "", testToken, "")
	if status != 404 {
		t.Fatalf("missing get: %d", status)
	}
	status, _, _ = request(t, s, "PUT", "/info/"+strings.Repeat("a", 32), `{"name":"x"}`, testToken, "application/json")
	if status != 404 {
		t.Fatalf("missing update: %d", status)
	}
}

func TestRejectInvalidRequestsWithoutWrites(t *testing.T) {
	for _, tc := range []struct {
		name, body, media string
		status            int
	}{
		{"empty", "", "application/json", 400},
		{"null", "null", "application/json", 400},
		{"array", "[]", "application/json", 400},
		{"syntax", `{`, "application/json", 400},
		{"trailing", `{"md5":"` + hash + `","name":"x"} {}`, "application/json", 400},
		{"duplicate", `{"md5":"` + hash + `","name":"x","name":"y"}`, "application/json", 400},
		{"escaped duplicate", `{"md5":"` + hash + `","name":"x","na\u006de":"y"}`, "application/json", 400},
		{"unknown", `{"md5":"` + hash + `","name":"x","extra":1}`, "application/json", 400},
		{"wrong case", `{"md5":"` + hash + `","Name":"x"}`, "application/json", 400},
		{"missing hash", `{"name":"x"}`, "application/json", 400},
		{"bad hash", `{"md5":"bad","name":"x"}`, "application/json", 400},
		{"blank name", `{"md5":"` + hash + `","name":" "}`, "application/json", 400},
		{"nul name", `{"md5":"` + hash + `","name":"\u0000"}`, "application/json", 400},
		{"UTC year underflow", `{"md5":"` + hash + `","name":"x","first_seen":"0000-01-01T00:00:00+01:00"}`, "application/json", 400},
		{"null field", `{"md5":"` + hash + `","name":"x","severity":null}`, "application/json", 400},
		{"empty enum", `{"md5":"` + hash + `","name":"x","severity":""}`, "application/json", 400},
		{"bad enum", `{"md5":"` + hash + `","name":"x","category":"evil"}`, "application/json", 400},
		{"bad date", `{"md5":"` + hash + `","name":"x","first_seen":"yesterday"}`, "application/json", 400},
		{"future date", `{"md5":"` + hash + `","name":"x","first_seen":"9999-01-01T00:00:00Z"}`, "application/json", 400},
		{"readonly", `{"md5":"` + hash + `","name":"x","created_at":"2020-01-01T00:00:00Z"}`, "application/json", 400},
		{"oversized", strings.Repeat(" ", 16385), "application/json", 413},
		{"media", `{}`, "text/plain", 415},
		{"missing media", `{}`, "", 415},
		{"charset", `{}`, "application/json; charset=latin1", 415},
		{"invalid utf8", "{\"name\":\"" + string([]byte{0xff}) + "\"}", "application/json", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestServer(t, 10000, 10000)
			status, _, result := request(t, s, "POST", "/info", tc.body, testToken, tc.media)
			if status != tc.status || result["message"] == "" {
				t.Fatalf("status=%d, want=%d body=%v", status, tc.status, result)
			}
			status, _, _ = request(t, s, "GET", "/info/"+hash, "", testToken, "")
			if status != 404 {
				t.Fatalf("invalid request wrote data: %d", status)
			}
		})
	}
}

func TestSecurityAndErrors(t *testing.T) {
	s, db := newTestServer(t, 10000, 10000)
	for _, token := range []string{"", "wrong"} {
		status, headers, _ := request(t, s, "GET", "/info/"+hash, "", token, "")
		if status != 401 || headers.Get("WWW-Authenticate") == "" {
			t.Fatalf("auth: %d %v", status, headers)
		}
	}
	status, _, _ := request(t, s, "GET", "/healthz", "", "", "")
	if status != 200 {
		t.Fatalf("health: %d", status)
	}
	status, _, _ = request(t, s, "GET", "/info/bad", "", testToken, "")
	if status != 400 {
		t.Fatalf("hash: %d", status)
	}
	status, headers, _ := request(t, s, "DELETE", "/info/"+hash, "", testToken, "")
	if status != 405 || headers.Get("Allow") != "GET, PUT" {
		t.Fatalf("method: %d %v", status, headers)
	}
	status, _, _ = request(t, s, "GET", "/unknown", "", testToken, "")
	if status != 404 {
		t.Fatalf("route: %d", status)
	}
	_ = db.Close()
	status, _, result := request(t, s, "GET", "/info/"+hash, "", testToken, "")
	if status != 500 || strings.Contains(result["message"].(string), "sql") {
		t.Fatalf("error leak: %d %v", status, result)
	}
	status, _, _ = request(t, s, "GET", "/healthz", "", "", "")
	if status != 503 {
		t.Fatalf("failed health: %d", status)
	}
}

func TestRateLimit(t *testing.T) {
	s, _ := newTestServer(t, 0.001, 1)
	status, _, _ := request(t, s, "GET", "/info/"+hash, "", testToken, "")
	if status != 404 {
		t.Fatalf("first: %d", status)
	}
	status, headers, _ := request(t, s, "GET", "/info/"+hash, "", testToken, "")
	if status != 429 || headers.Get("Retry-After") == "" {
		t.Fatalf("rate: %d %v", status, headers)
	}
	status, _, _ = request(t, s, "GET", "/healthz", "", "", "")
	if status != 200 {
		t.Fatalf("health limited: %d", status)
	}
}

func TestConcurrentHTTPCreate(t *testing.T) {
	s, _ := newTestServer(t, 10000, 10000)
	results := make(chan int, 12)
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest("POST", s.URL+"/info", bytes.NewBufferString(`{"md5":"`+hash+`","name":"x"}`))
			if err != nil {
				results <- 0
				return
			}
			req.Header.Set("Authorization", "Bearer "+testToken)
			req.Header.Set("Content-Type", "application/json")
			res, err := s.Client().Do(req)
			if err != nil {
				results <- 0
				return
			}
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			results <- res.StatusCode
		}()
	}
	wg.Wait()
	close(results)
	created := 0
	for code := range results {
		if code == 201 {
			created++
		} else if code != 409 {
			t.Fatalf("unexpected status: %d", code)
		}
	}
	if created != 1 {
		t.Fatalf("created: %d", created)
	}
}

func TestInvalidReplacementKeepsOriginal(t *testing.T) {
	s, _ := newTestServer(t, 10000, 10000)
	status, _, original := request(t, s, "POST", "/info", `{"md5":"`+hash+`","name":"Original","severity":"high"}`, testToken, "application/json")
	if status != 201 {
		t.Fatalf("create: %d", status)
	}
	for _, body := range []string{`{"name":""}`, `{"name":"Changed"} {}`, `{"name":"Changed","md5":"` + hash + `"}`} {
		status, _, _ := request(t, s, "PUT", "/info/"+hash, body, testToken, "application/json")
		if status != 400 {
			t.Fatalf("invalid replacement: %d", status)
		}
		status, _, got := request(t, s, "GET", "/info/"+hash, "", testToken, "")
		if status != 200 || got["name"] != "Original" || got["severity"] != "high" || got["updated_at"] != original["updated_at"] {
			t.Fatalf("invalid PUT changed record: %d %v", status, got)
		}
	}
}

func TestBodyLimitAndEncoding(t *testing.T) {
	s, _ := newTestServer(t, 10000, 10000)
	body := `{"md5":"` + hash + `","name":"At limit"}`
	body += strings.Repeat(" ", 16384-len(body))
	status, _, _ := request(t, s, "POST", "/info", body, testToken, "application/json")
	if status != 201 {
		t.Fatalf("valid body at limit: %d", status)
	}
	req, err := http.NewRequest("PUT", s.URL+"/info/"+hash, strings.NewReader(`{"name":"Should not change"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	res, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if res.StatusCode != 415 {
		t.Fatalf("unsupported encoding: %d", res.StatusCode)
	}
	status, _, got := request(t, s, "GET", "/info/"+hash, "", testToken, "")
	if status != 200 || got["name"] != "At limit" {
		t.Fatalf("unsupported encoding changed record: %d %v", status, got)
	}
}
