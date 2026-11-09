package heimdall

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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

func TestCreateCampaign(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":4,"name":"spynote-2026","family":"SpyNote","description":"March wave","domains":0,"created_at":"2026-03-01T12:00:00Z"}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL, "TOK").CreateCampaign(context.Background(), "spynote-2026", "SpyNote", "March wave")
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/campaigns" || gotAuth != "Bearer TOK" {
		t.Errorf("%s %s, Authorization %q", gotMethod, gotPath, gotAuth)
	}
	want := map[string]any{"name": "spynote-2026", "family": "SpyNote", "description": "March wave"}
	if len(got) != len(want) {
		t.Errorf("body = %v, want exactly the keys of %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("body[%q] = %v, want %q", k, got[k], v)
		}
	}
	if c != (Campaign{ID: 4, Name: "spynote-2026", Family: "SpyNote", Description: "March wave", CreatedAt: "2026-03-01T12:00:00Z"}) {
		t.Errorf("campaign = %+v", c)
	}
}

func TestCreateCampaignForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := New(srv.URL, "TOK").CreateCampaign(context.Background(), "spynote-2026", "", "")
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != http.StatusForbidden || ae.Method != http.MethodPost || ae.Path != "/api/campaigns" {
		t.Fatalf("err = %v, want the 403 of POST /api/campaigns", err)
	}
	if ae.Body != `{"error":"forbidden"}` {
		t.Errorf("body = %q", ae.Body)
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

const pivotJSON = `{"domain":"b.example","rrtype":"A","rdata":"192.0.2.1","target":{"first":"2026-03-01T12:00:00Z","last":"2026-03-02T12:00:00Z"},"other":{"first":"2026-03-02T00:00:00Z","last":"2026-03-03T00:00:00Z"},"overlap":{"first":"2026-03-02T00:00:00Z","last":"2026-03-02T12:00:00Z"}}`

func TestPivotsBothFormats(t *testing.T) {
	for name, tt := range map[string]struct {
		body     string
		excluded []ExcludedCDN
	}{
		"array":       {body: "[" + pivotJSON + "]", excluded: []ExcludedCDN{}},
		"array space": {body: "\n  [" + pivotJSON + "]", excluded: []ExcludedCDN{}},
		"object": {
			body:     `{"pivots":[` + pivotJSON + `],"excluded_cdn":[{"value":"104.16.0.1","provider":"Cloudflare"},{"value":"2606:4700::1","provider":"Cloudflare"}]}`,
			excluded: []ExcludedCDN{{Value: "104.16.0.1", Provider: "Cloudflare"}, {Value: "2606:4700::1", Provider: "Cloudflare"}},
		},
		"object without exclusions": {body: `{"pivots":[` + pivotJSON + `],"excluded_cdn":[]}`, excluded: []ExcludedCDN{}},
	} {
		var gotPath string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			w.Write([]byte(tt.body))
		}))
		res, err := New(srv.URL, "TOK").Pivots(context.Background(), "www.x.example", 0)
		srv.Close()
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if gotPath != "/api/pivots/www.x.example" {
			t.Errorf("%s: path %q", name, gotPath)
		}
		if len(res.Pivots) != 1 {
			t.Errorf("%s: %d pivots, want 1", name, len(res.Pivots))
			continue
		}
		if p := res.Pivots[0]; p.Domain != "b.example" || p.RData != "192.0.2.1" || p.Overlap == nil || p.Overlap.Last != "2026-03-02T12:00:00Z" {
			t.Errorf("%s: pivot = %+v", name, p)
		}
		if res.ExcludedCDN == nil || len(res.ExcludedCDN) != len(tt.excluded) {
			t.Errorf("%s: excluded = %#v, want %v", name, res.ExcludedCDN, tt.excluded)
			continue
		}
		for i := range tt.excluded {
			if res.ExcludedCDN[i] != tt.excluded[i] {
				t.Errorf("%s: excluded[%d] = %+v, want %+v", name, i, res.ExcludedCDN[i], tt.excluded[i])
			}
		}
	}
}

func TestDecodePivotsEmpty(t *testing.T) {
	for _, body := range []string{`[]`, `{"pivots":[],"excluded_cdn":[]}`, `{}`} {
		res, err := DecodePivots([]byte(body))
		if err != nil || res.Pivots == nil || len(res.Pivots) != 0 || res.ExcludedCDN == nil || len(res.ExcludedCDN) != 0 {
			t.Errorf("%s: %#v, %v; want empty, non-nil lists", body, res, err)
		}
	}
	if _, err := DecodePivots([]byte(`[{"domain":1}]`)); err == nil {
		t.Error("a malformed array was accepted")
	}
}

func TestDecodePivotsNSPairs(t *testing.T) {
	res, err := DecodePivots([]byte(`{"pivots":[],"excluded_cdn":[],"ns_pairs":{"zone":"a.example","ns":["ana.ns.cloudflare.com","bob.ns.cloudflare.com"],"matches":[` +
		`{"domain":"same.example","other":{"first":"2026-03-01T13:00:00Z","last":"2026-03-01T15:00:00Z"},"target":{"first":"2026-03-01T12:00:00Z","last":"2026-03-01T14:00:00Z"},"overlap":{"first":"2026-03-01T13:00:00Z","last":"2026-03-01T14:00:00Z"}},` +
		`{"domain":"later.example","other":{"first":"2026-03-01T17:00:00Z","last":"2026-03-01T18:00:00Z"},"target":{"first":"2026-03-01T12:00:00Z","last":"2026-03-01T14:00:00Z"},"overlap":null}]}}`))
	if err != nil {
		t.Fatalf("DecodePivots: %v", err)
	}
	p := res.NSPairs
	if p == nil || p.Zone != "a.example" || strings.Join(p.NS, " ") != "ana.ns.cloudflare.com bob.ns.cloudflare.com" || len(p.Matches) != 2 {
		t.Fatalf("ns_pairs = %+v", p)
	}
	if m := p.Matches[0]; m.Domain != "same.example" || m.Other.First != "2026-03-01T13:00:00Z" || m.Target.Last != "2026-03-01T14:00:00Z" ||
		m.Overlap == nil || m.Overlap.First != "2026-03-01T13:00:00Z" || m.Overlap.Last != "2026-03-01T14:00:00Z" {
		t.Errorf("match 0 = %+v", m)
	}
	if m := p.Matches[1]; m.Domain != "later.example" || m.Overlap != nil {
		t.Errorf("match 1 = %+v, want no overlap", m)
	}

	res, err = DecodePivots([]byte(`{"pivots":[],"excluded_cdn":[],"ns_pairs":{"zone":"a.example","ns":["ana.ns.cloudflare.com","bob.ns.cloudflare.com"],"matches":[]}}`))
	if err != nil || res.NSPairs == nil || res.NSPairs.Matches == nil || len(res.NSPairs.Matches) != 0 {
		t.Errorf("no match: %+v, %v; want an empty, non-nil list", res.NSPairs, err)
	}

	for _, body := range []string{`{"pivots":[],"excluded_cdn":[],"ns_pairs":null}`, `{"pivots":[],"excluded_cdn":[]}`, "[" + pivotJSON + "]"} {
		res, err := DecodePivots([]byte(body))
		if err != nil || res.NSPairs != nil {
			t.Errorf("%s: ns_pairs = %+v, %v; want nil", body, res.NSPairs, err)
		}
		b, _ := json.Marshal(res)
		if !strings.Contains(string(b), `"ns_pairs":null`) {
			t.Errorf("%s: re-encoded as %s, want ns_pairs null", body, b)
		}
	}
}

func TestDomainDetailScopeAndCDN(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"domain":null,` +
			`"current":[{"qtype":"A","resolver":"9.9.9.9:53","ts":"2026-03-01T12:00:00Z","rcode":"NOERROR","ttl":60,"rdata":["104.16.0.1","192.0.2.9"],"cdn":{"104.16.0.1":"Cloudflare"}},` +
			`{"qtype":"AAAA","resolver":"9.9.9.9:53","ts":"2026-03-01T12:00:00Z","rcode":"NOERROR","ttl":0,"rdata":[]}],` +
			`"changes":[{"ts":"2026-03-01T12:01:00Z","scope":"zone","qtype":"NS","resolver":"9.9.9.9:53","prev_rcode":"NOERROR","new_rcode":"NOERROR","added":["ns1.sinkhole.example"],"removed":["ns1.x.example"],"prev_ttl":3600,"new_ttl":3600},` +
			`{"ts":"2026-03-01T12:00:00Z","scope":"name","qtype":"A","resolver":"9.9.9.9:53","prev_rcode":"NXDOMAIN","new_rcode":"NOERROR","added":["192.0.2.1"],"removed":[],"prev_ttl":0,"new_ttl":300}],` +
			`"pdns":[]}`))
	}))
	defer srv.Close()

	d, err := New(srv.URL, "TOK").DomainDetail(context.Background(), "www.x.example", 0)
	if err != nil {
		t.Fatalf("DomainDetail: %v", err)
	}
	if len(d.Changes) != 2 || d.Changes[0].Scope != "zone" || d.Changes[1].Scope != "name" {
		t.Errorf("changes = %+v, want scopes zone then name", d.Changes)
	}
	if len(d.Current) != 2 || d.Current[0].CDN["104.16.0.1"] != "Cloudflare" || len(d.Current[0].CDN) != 1 || d.Current[1].CDN != nil {
		t.Errorf("current = %+v", d.Current)
	}
	b, _ := json.Marshal(d.Current[1])
	if strings.Contains(string(b), "cdn") {
		t.Errorf("empty cdn re-encoded: %s", b)
	}
}

func TestVTEnrichRequests(t *testing.T) {
	for _, tc := range []struct {
		target VTTarget
		start  bool
		want   string
	}{
		{target: VTTarget{FQDN: "a.example", Depth: 2}, start: true, want: "POST /api/vt/enrich/domain/a.example?depth=2"},
		{target: VTTarget{FQDN: "a.example"}, start: true, want: "POST /api/vt/enrich/domain/a.example?"},
		{target: VTTarget{FQDN: "a.example", Depth: 2}, want: "GET /api/vt/enrich/domain/a.example?"},
		{target: VTTarget{Campaign: 2, Depth: 2}, start: true, want: "POST /api/vt/enrich/campaign/2?"},
		{target: VTTarget{Campaign: 2}, want: "GET /api/vt/enrich/campaign/2?"},
		{target: VTTarget{IP: "192.0.2.1"}, start: true, want: "POST /api/vt/enrich/ip/192.0.2.1?"},
		{target: VTTarget{IP: "2001:db8::1"}, want: "GET /api/vt/enrich/ip/2001:db8::1?"},
	} {
		var got string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.Method + " " + r.URL.Path + "?" + r.URL.RawQuery
			w.Write([]byte(`{"job":"domain:a.example","state":"running","started_at":"2026-03-01T12:00:00Z"}`))
		}))
		c := New(srv.URL, "TOK")
		var job VTJob
		var err error
		if tc.start {
			job, err = c.StartVTEnrich(context.Background(), tc.target)
		} else {
			job, err = c.VTEnrichState(context.Background(), tc.target)
		}
		srv.Close()
		if err != nil || got != tc.want || job.State != "running" || job.VTSummary != nil {
			t.Errorf("%s: sent %q, got %+v, %v", tc.want, got, job, err)
		}
	}
}

func TestVTJobSummary(t *testing.T) {
	for _, tc := range []struct {
		body    string
		summary *VTSummary
	}{
		{body: `{"state":"none"}`},
		{body: `{"job":"domain:a.example","state":"running","started_at":"2026-03-01T12:00:00Z"}`},
		{
			body:    `{"job":"domain:a.example","state":"done","started_at":"2026-03-01T12:00:00Z","finished_at":"2026-03-01T12:00:05Z","looked_up":3,"cached":1,"skipped_cdn":1,"skipped_reserved":0,"skipped_budget":2,"stopped_reason":"daily budget reached"}`,
			summary: &VTSummary{LookedUp: 3, Cached: 1, SkippedCDN: 1, SkippedBudget: 2, StoppedReason: "daily budget reached"},
		},
	} {
		var j VTJob
		if err := json.Unmarshal([]byte(tc.body), &j); err != nil {
			t.Errorf("%s: %v", tc.body, err)
			continue
		}
		if (j.VTSummary == nil) != (tc.summary == nil) || j.VTSummary != nil && *j.VTSummary != *tc.summary {
			t.Errorf("%s: summary %+v, want %+v", tc.body, j.VTSummary, tc.summary)
		}
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

const (
	certSHA256 = "8f7a1c52e0b3d94a6c1f2e7b0d5a3c9e4b8f6a2d1c7e5b3a9f0d4c2e6b8a1f3d"
	enrichJSON = `{"fqdn":"a.example","fetched_at":"2026-03-01T12:00:00Z","status":"partial",` +
		`"dns":{"resolver":"9.9.9.9:53","records":[{"qtype":"A","rcode":"NOERROR","ttl":300,"rdata":["192.0.2.1"]},{"qtype":"AAAA","rcode":"NOERROR","ttl":0,"rdata":[]}]},` +
		`"zone":{"name":"a.example","soa":["ns1.a.example. hostmaster.a.example. 2026030101 7200 3600 1209600 300"],"ns":["ana.ns.cloudflare.com","bob.ns.cloudflare.com"]},` +
		`"rdap":{"domain":"a.example","registrar":{"name":"NameCheap, Inc.","iana_id":"1068"},"registration":"2026-02-01T00:00:00Z","expiration":"2027-02-01T00:00:00Z",` +
		`"status":["client transfer prohibited"],"nameservers":["ana.ns.cloudflare.com","bob.ns.cloudflare.com"],"entities":[{"roles":["registrar"],"name":"NameCheap, Inc."}]},` +
		`"ct":{"zone":"a.example","total":1,"certificates":[{"id":"7392018311","cert_sha256":"` + certSHA256 + `","issuer":"R11","not_before":"2026-02-01T00:00:00Z","not_after":"2026-05-02T00:00:00Z","revoked":false,"names":["a.example","*.a.example"]}],"names":["*.a.example","a.example"],"truncated":false},` +
		`"subdomains":null,"errors":{"subdomains":"passive DNS: timeout"},` +
		`"graph":{"nodes":[{"id":"d:a.example","kind":"domain","label":"a.example","watched":true,"campaign":"spynote","href":"/domains/a.example","source":"heimdall"},` +
		`{"id":"ip:192.0.2.1","kind":"ip","label":"192.0.2.1","watched":false,"campaign":"","href":"/rdata/192.0.2.1","source":"heimdall"}],` +
		`"edges":[{"from":"d:a.example","to":"ip:192.0.2.1","kind":"A"}],"truncated":false,"excluded_cdn":1}}`
)

func TestDomainEnrichRequests(t *testing.T) {
	for _, tc := range []struct {
		desc string
		run  func(*Client) (EnrichJob, error)
		want string
	}{
		{"start", func(c *Client) (EnrichJob, error) { return c.StartDomainEnrich(context.Background(), "a.example") }, "POST /api/enrich/domain/a.example"},
		{"state", func(c *Client) (EnrichJob, error) { return c.DomainEnrichState(context.Background(), "a.example") }, "GET /api/enrich/domain/a.example"},
	} {
		var got string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.Method + " " + r.URL.Path
			w.WriteHeader(http.StatusAccepted)
			w.Write([]byte(`{"job":"domain:a.example","state":"running","started_at":"2026-03-01T12:00:00Z"}`))
		}))
		job, err := tc.run(New(srv.URL, "TOK"))
		srv.Close()
		if err != nil || got != tc.want || job.State != "running" || job.EnrichSummary != nil {
			t.Errorf("%s: sent %q, got %+v, %v", tc.desc, got, job, err)
		}
	}
}

func TestEnrichJobSummary(t *testing.T) {
	for _, tc := range []struct {
		body    string
		summary *EnrichSummary
		errMsg  string
	}{
		{body: `{"state":"none"}`},
		{body: `{"job":"domain:a.example","state":"running","started_at":"2026-03-01T12:00:00Z"}`},
		{
			body:    `{"job":"domain:a.example","state":"done","started_at":"2026-03-01T12:00:00Z","finished_at":"2026-03-01T12:00:05Z","status":"ok","counts":{"dns":4,"rdap":1,"ct":12,"subdomains":3},"summary":"ok: dns 4, rdap 1, ct 12, subdomains 3"}`,
			summary: &EnrichSummary{Status: "ok", Counts: EnrichCounts{DNS: 4, RDAP: 1, CT: 12, Subdomains: 3}, Summary: "ok: dns 4, rdap 1, ct 12, subdomains 3"},
		},
		{
			body:    `{"job":"domain:a.example","state":"failed","started_at":"2026-03-01T12:00:00Z","finished_at":"2026-03-01T12:00:05Z","status":"partial","counts":{"dns":4,"rdap":0,"ct":0,"subdomains":0},"errors":{"ct":"rate limited","rdap":"no RDAP server"},"summary":"partial: dns 4, rdap failed, ct failed, subdomains 0","error":"internal error"}`,
			summary: &EnrichSummary{Status: "partial", Counts: EnrichCounts{DNS: 4}, Errors: map[string]string{"ct": "rate limited", "rdap": "no RDAP server"}, Summary: "partial: dns 4, rdap failed, ct failed, subdomains 0"},
			errMsg:  "internal error",
		},
	} {
		var j EnrichJob
		if err := json.Unmarshal([]byte(tc.body), &j); err != nil {
			t.Errorf("%s: %v", tc.body, err)
			continue
		}
		if (j.EnrichSummary == nil) != (tc.summary == nil) || j.Error != tc.errMsg {
			t.Errorf("%s: summary %+v error %q, want %+v %q", tc.body, j.EnrichSummary, j.Error, tc.summary, tc.errMsg)
			continue
		}
		if s := j.EnrichSummary; s != nil {
			if s.Status != tc.summary.Status || s.Counts != tc.summary.Counts || s.Summary != tc.summary.Summary || len(s.Errors) != len(tc.summary.Errors) {
				t.Errorf("%s: summary %+v, want %+v", tc.body, s, tc.summary)
			}
			for k, v := range tc.summary.Errors {
				if s.Errors[k] != v {
					t.Errorf("%s: errors[%q] = %q, want %q", tc.body, k, s.Errors[k], v)
				}
			}
		}
	}
}

func TestDomainEnrichment(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Method + " " + r.URL.Path
		w.Write([]byte(enrichJSON))
	}))
	defer srv.Close()

	e, err := New(srv.URL, "TOK").DomainEnrichment(context.Background(), "a.example")
	if err != nil {
		t.Fatalf("DomainEnrichment: %v", err)
	}
	if got != "GET /api/domains/a.example/enrich" {
		t.Errorf("sent %q", got)
	}
	if e.FQDN != "a.example" || e.Status != "partial" || e.Subdomains != nil || e.Errors["subdomains"] != "passive DNS: timeout" {
		t.Errorf("enrichment = %+v", e)
	}
	if e.DNS == nil || e.DNS.Resolver != "9.9.9.9:53" || len(e.DNS.Records) != 2 || e.DNS.Records[0].TTL != 300 || e.DNS.Records[1].Rdata == nil {
		t.Errorf("dns = %+v", e.DNS)
	}
	if e.Zone == nil || e.Zone.Name != "a.example" || len(e.Zone.NS) != 2 || len(e.Zone.SOA) != 1 {
		t.Errorf("zone = %+v", e.Zone)
	}
	if r := e.RDAP; r == nil || r.Registrar == nil || r.Registrar.IANAID != "1068" || r.Registration != "2026-02-01T00:00:00Z" ||
		r.Expiration != "2027-02-01T00:00:00Z" || r.LastChanged != "" || len(r.Status) != 1 || len(r.Entities) != 1 || r.Entities[0].Roles[0] != "registrar" {
		t.Errorf("rdap = %+v", e.RDAP)
	}
	if e.CT == nil || e.CT.Total != 1 || len(e.CT.Certificates) != 1 || len(e.CT.Names) != 2 {
		t.Fatalf("ct = %+v", e.CT)
	}
	if c := e.CT.Certificates[0]; c.CertSHA256 != certSHA256 || c.ID != "7392018311" || c.Issuer != "R11" || c.NotAfter != "2026-05-02T00:00:00Z" || len(c.Names) != 2 {
		t.Errorf("certificate = %+v", c)
	}
	if g := e.Graph; g == nil || len(g.Nodes) != 2 || len(g.Edges) != 1 || g.ExcludedCDN != 1 || !g.Nodes[0].Watched || g.Nodes[0].Campaign != "spynote" || g.Edges[0].FirstSeen != nil {
		t.Errorf("graph = %+v", e.Graph)
	}
	b, _ := json.Marshal(e)
	if !strings.Contains(string(b), `"cert_sha256":"`+certSHA256+`"`) {
		t.Errorf("re-encoded without the whole SHA-256: %s", b)
	}
	if strings.Contains(string(b), "last_changed") {
		t.Errorf("an absent RDAP date was re-encoded: %s", b)
	}
}

func TestDomainEnrichmentNotEnriched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := New(srv.URL, "TOK").DomainEnrichment(context.Background(), "a.example")
	if !errors.Is(err, ErrNotEnriched) || !IsStatus(err, http.StatusNotFound) {
		t.Errorf("err = %v, want ErrNotEnriched wrapping the 404", err)
	}
}

func TestDomainEnrichmentNoErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"fqdn":"a.example","fetched_at":"2026-03-01T12:00:00Z","status":"ok","dns":null,"zone":null,"rdap":null,"ct":null,"subdomains":null,"errors":null,"graph":{"nodes":[],"edges":[],"truncated":false,"excluded_cdn":0}}`))
	}))
	defer srv.Close()

	e, err := New(srv.URL, "TOK").DomainEnrichment(context.Background(), "a.example")
	if err != nil || e.Errors == nil {
		t.Errorf("errors = %#v, %v; want an empty, non-nil map", e.Errors, err)
	}
}

func TestLinkDomain(t *testing.T) {
	id := int64(2)
	for _, tc := range []struct {
		desc  string
		req   LinkRequest
		reply string
		body  string
	}{
		{
			desc:  "existing campaign",
			req:   LinkRequest{Campaign: &id},
			reply: `{"fqdn":"a.example","campaign":{"id":2,"name":"SpyNote"},"action":"moved","created_campaign":false}`,
			body:  `{"campaign":2}`,
		},
		{
			desc:  "new campaign",
			req:   LinkRequest{NewCampaign: &LinkNewCampaign{Name: "spynote-2026", Description: "March wave"}},
			reply: `{"fqdn":"a.example","campaign":{"id":4,"name":"spynote-2026"},"action":"added","created_campaign":true}`,
			body:  `{"new_campaign":{"name":"spynote-2026","description":"March wave"}}`,
		},
	} {
		var got, gotBody string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.Method + " " + r.URL.Path
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			w.Write([]byte(tc.reply))
		}))
		res, err := New(srv.URL, "TOK").LinkDomain(context.Background(), "a.example", tc.req)
		srv.Close()
		if err != nil {
			t.Errorf("%s: %v", tc.desc, err)
			continue
		}
		if got != "POST /api/domains/a.example/link" || gotBody != tc.body {
			t.Errorf("%s: sent %q %s, want body %s", tc.desc, got, gotBody, tc.body)
		}
		b, _ := json.Marshal(res)
		if string(b) != tc.reply {
			t.Errorf("%s: result %s, want %s", tc.desc, b, tc.reply)
		}
	}
}

func TestLinkDomainErrors(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusNotFound, http.StatusConflict} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error":"campaign exists"}`, status)
		}))
		_, err := New(srv.URL, "TOK").LinkDomain(context.Background(), "a.example", LinkRequest{NewCampaign: &LinkNewCampaign{Name: "x"}})
		srv.Close()
		if !IsStatus(err, status) || errors.Is(err, ErrNotEnriched) {
			t.Errorf("HTTP %d: err = %v", status, err)
		}
	}
}

const analyticsBody = `{"days":90,` +
	`"header":{"campaign":{"id":7,"name":"SpyNote","family":"SpyNote","description":"March wave"},"domains":2,"enabled":1,"last_measured_at":"2026-03-01T11:58:00Z","vt":{"budget":500,"used_today":12,"remaining":488}},` +
	`"kpis":{"resolving":{"value":1,"series":[0,1]},"nxdomain":{"value":0,"series":[1,0]},"failing":{"value":0,"series":[0,0]},"unmeasured":{"value":1,"series":[1,1]},` +
	`"active_ips":{"value":2,"series":[1,2]},"cdn_share":{"value":0.3333,"series":[0,0.3333]},"ns_sets":{"value":1,"series":[1,1]},"events_7d":{"value":3,"series":[1,3]}},` +
	`"timeline":{"kinds":["new_rdata","nxdomain"],"days":[{"day":"2026-02-28","counts":{"nxdomain":1}},{"day":"2026-03-01","counts":{"new_rdata":2}}]},` +
	`"liveness":{"days":["2026-02-28","2026-03-01"],"rows":[{"fqdn":"a.example","enabled":true,"first_seen":"2026-01-10T08:00:00Z","cells":["nx","ok"]},{"fqdn":"b.example","enabled":false,"first_seen":null,"cells":["none","none"]}]},` +
	`"clusters":{"ips":[{"ip":"192.0.2.1","domains":["a.example","c.example"],"first_seen":"2026-02-28","last_seen":"2026-03-01"}],` +
	`"ns_sets":[{"ns":["ana.ns.cloudflare.com","bob.ns.cloudflare.com"],"zones":["a.example","c.example"],"domains":["a.example","c.example"]}],` +
	`"new_ips_per_day":[{"day":"2026-02-28","ips":[]},{"day":"2026-03-01","ips":["192.0.2.1"]}],"excluded_cdn":1},` +
	`"events":[{"ts":"2026-03-01T11:00:00Z","domain":"a.example","campaign":"SpyNote","kind":"soa_serial_change","qtype":"SOA","resolver":"9.9.9.9:53","detail":{"new":2026030112,"prev":2026030111}}],` +
	`"vt_leads":[{"host_name":"new.example","ips":["192.0.2.1"],"last_seen":"2026-02-20T00:00:00Z"}]}`

func TestCampaignAnalytics(t *testing.T) {
	for _, tc := range []struct {
		days  int
		query string
	}{
		{days: 0},
		{days: 30},
		{days: 45},
		{days: 90, query: "days=90"},
	} {
		var got, gotQuery string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, gotQuery = r.Method+" "+r.URL.Path, r.URL.RawQuery
			w.Write([]byte(analyticsBody))
		}))
		a, err := New(srv.URL, "TOK").CampaignAnalytics(context.Background(), 7, tc.days)
		srv.Close()
		if err != nil {
			t.Errorf("days %d: %v", tc.days, err)
			continue
		}
		if got != "GET /api/campaigns/7/analytics" || gotQuery != tc.query {
			t.Errorf("days %d: sent %q ?%s, want ?%s", tc.days, got, gotQuery, tc.query)
		}
		b, _ := json.Marshal(a)
		if string(b) != analyticsBody {
			t.Errorf("days %d: decoded and encoded back as\n%s\nwant\n%s", tc.days, b, analyticsBody)
		}
		if a.Header.VT == nil || a.Header.VT.Remaining != 488 || a.Liveness.Rows[1].FirstSeen != nil || a.KPIs.CDNShare.Value != 0.3333 || a.Timeline.Days[0].Counts["nxdomain"] != 1 {
			t.Errorf("days %d: analytics %+v", tc.days, a)
		}
	}
}

func TestNSGraph(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte(`{"nodes":[{"id":"ns:ana.ns.cloudflare.com,bob.ns.cloudflare.com","kind":"nsset","label":"ana.ns.cloudflare.com, bob.ns.cloudflare.com","watched":false,"campaign":"","href":"","source":"heimdall"},` +
			`{"id":"d:a.example","kind":"domain","label":"a.example","watched":true,"campaign":"spynote","href":"/domains/a.example","source":"heimdall"}],` +
			`"edges":[{"from":"d:a.example","to":"ns:ana.ns.cloudflare.com,bob.ns.cloudflare.com","kind":"NS_SET"}],"truncated":false,"excluded_cdn":0}`))
	}))
	defer srv.Close()

	g, err := New(srv.URL, "TOK").NSGraph(context.Background(), []string{"ana.ns.cloudflare.com", "bob.ns.cloudflare.com"})
	if err != nil {
		t.Fatalf("NSGraph: %v", err)
	}
	if gotPath != "/api/graph/ns/ana.ns.cloudflare.com,bob.ns.cloudflare.com" {
		t.Errorf("path %q", gotPath)
	}
	if len(g.Nodes) != 2 || g.Nodes[1].Kind != "domain" || len(g.Edges) != 1 || g.Edges[0].Kind != "NS_SET" {
		t.Errorf("graph = %+v", g)
	}
}
