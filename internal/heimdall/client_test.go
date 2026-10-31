package heimdall

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const cofBody = `{"rrname":"www.x.example","rrtype":"CNAME","rdata":"cdn.y.example","time_first":1772366400,"time_last":1772370000,"count":3}
{"rrname":"www.x.example","rrtype":"AAAA","rdata":"2001:db8:0:0:1:0:0:1","time_first":1772366400,"time_last":1772366400,"count":18446744073709551615}
`

func TestPDNSQueryParsesCOF(t *testing.T) {
	var gotAuth, gotPath, gotLimit string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath, gotLimit = r.Header.Get("Authorization"), r.URL.Path, r.URL.Query().Get("limit")
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Write([]byte(cofBody))
	}))
	defer srv.Close()

	recs, err := New(srv.URL+"/", "TOK").PDNSQuery(context.Background(), "www.x.example", 5)
	if err != nil {
		t.Fatalf("PDNSQuery: %v", err)
	}
	if gotAuth != "Bearer TOK" {
		t.Errorf("Authorization = %q, want the Bearer scheme", gotAuth)
	}
	if gotPath != "/api/pdns/query/www.x.example" || gotLimit != "5" {
		t.Errorf("path %q limit %q", gotPath, gotLimit)
	}
	want := []COFRecord{
		{RRName: "www.x.example", RRType: "CNAME", RData: "cdn.y.example", TimeFirst: 1772366400, TimeLast: 1772370000, Count: 3},
		{RRName: "www.x.example", RRType: "AAAA", RData: "2001:db8:0:0:1:0:0:1", TimeFirst: 1772366400, TimeLast: 1772366400, Count: 18446744073709551615},
	}
	if len(recs) != len(want) {
		t.Fatalf("%d records, want %d", len(recs), len(want))
	}
	for i := range want {
		if recs[i] != want[i] {
			t.Errorf("record %d = %+v, want %+v", i, recs[i], want[i])
		}
	}
}

func TestDecodeCOF(t *testing.T) {
	recs, err := DecodeCOF(strings.NewReader(""))
	if err != nil || recs == nil || len(recs) != 0 {
		t.Errorf("empty stream: %v, %v; want an empty, non-nil slice", recs, err)
	}
	if _, err := DecodeCOF(strings.NewReader(`{"rrname":"a"}` + "\n{broken\n")); err == nil {
		t.Error("a malformed line was accepted")
	}
}

func TestPostSendsBearerAndJSON(t *testing.T) {
	var gotAuth, gotType string
	var got NewDomain
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotType = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"fqdn":"a.example","campaign":"spynote","interval_seconds":43200,"enabled":true,"source":"api:alice","added_at":"2026-03-01T12:00:00Z"}`))
	}))
	defer srv.Close()

	d, err := New(srv.URL, "TOK").CreateDomain(context.Background(), NewDomain{FQDN: "a.example", Campaign: "spynote", IntervalSeconds: 43200})
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if gotAuth != "Bearer TOK" || gotType != "application/json" {
		t.Errorf("Authorization %q, Content-Type %q", gotAuth, gotType)
	}
	if got.FQDN != "a.example" || got.Campaign != "spynote" || got.IntervalSeconds != 43200 {
		t.Errorf("body = %+v", got)
	}
	if d.AddedAt != "2026-03-01T12:00:00Z" || !d.Enabled {
		t.Errorf("domain = %+v", d)
	}
}

func TestForbiddenIsReturnedWithStatusAndBody(t *testing.T) {
	long := `{"error":"forbidden"}` + strings.Repeat("x", 600)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(long))
	}))
	defer srv.Close()

	_, err := New(srv.URL, "TOK").PatchDomain(context.Background(), "a.example", DomainPatch{})
	var ae *APIError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v, want an APIError", err)
	}
	if ae.StatusCode != http.StatusForbidden || ae.Method != http.MethodPatch || ae.Path != "/api/domains/a.example" {
		t.Errorf("APIError = %d %s %s", ae.StatusCode, ae.Method, ae.Path)
	}
	if ae.Body != long[:maxErrBody] {
		t.Errorf("body is %d bytes, want the first %d", len(ae.Body), maxErrBody)
	}
	if !strings.Contains(err.Error(), "HTTP 403") || !IsStatus(err, http.StatusForbidden) {
		t.Errorf("Error() = %q", err)
	}
}

func TestEventDetailKeepsDigits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"ts":"2026-03-01T12:00:00Z","domain":"x.example","campaign":"","kind":"soa_serial_change","qtype":"SOA","resolver":"9.9.9.9:53","detail":{"prev_serial":4294967295,"new_serial":2026030101}}]`))
	}))
	defer srv.Close()

	evs, err := New(srv.URL, "TOK").Events(context.Background(), EventQuery{})
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	b, _ := json.Marshal(evs[0].Detail)
	if got, want := string(b), `{"new_serial":2026030101,"prev_serial":4294967295}`; got != want {
		t.Errorf("detail = %s, want %s", got, want)
	}
}

func TestNoTokenIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the server was called without a token")
	}))
	defer srv.Close()
	if _, err := New(srv.URL, "").Campaigns(context.Background()); err == nil {
		t.Error("no error without a token")
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("HEIMDALL_TOKEN", "TOK")
	t.Setenv("HEIMDALL_TIMEOUT", "")
	t.Setenv("HEIMDALL_URL", "")
	if _, err := FromEnv(); err == nil {
		t.Error("no error without HEIMDALL_URL")
	}
	t.Setenv("HEIMDALL_URL", "heimdall.example")
	if _, err := FromEnv(); err == nil {
		t.Error("a URL without scheme was accepted")
	}
	t.Setenv("HEIMDALL_URL", "https://heimdall.example")
	t.Setenv("HEIMDALL_TIMEOUT", "soon")
	if _, err := FromEnv(); err == nil {
		t.Error("an invalid HEIMDALL_TIMEOUT was accepted")
	}
	t.Setenv("HEIMDALL_TIMEOUT", "5s")
	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if c.http.Timeout.String() != "5s" || c.baseURL != "https://heimdall.example" {
		t.Errorf("timeout %v, base %q", c.http.Timeout, c.baseURL)
	}
	t.Setenv("HEIMDALL_TIMEOUT", "")
	if c, _ := FromEnv(); c.http.Timeout != DefaultTimeout {
		t.Errorf("default timeout %v, want %v", c.http.Timeout, DefaultTimeout)
	}
}
