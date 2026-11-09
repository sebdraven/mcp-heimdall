package mcptools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-heimdall/internal/heimdall"
	"github.com/sebdraven/mcp-heimdall/internal/service"
)

const (
	campaignsJSON = `[{"id":2,"name":"SpyNote","family":"SpyNote","description":"","domains":0,"created_at":"2026-03-01T12:00:00Z"}]`
	certSHA256    = "8f7a1c52e0b3d94a6c1f2e7b0d5a3c9e4b8f6a2d1c7e5b3a9f0d4c2e6b8a1f3d"
	enrichRunning = `{"job":"domain:a.example","state":"running","started_at":"2026-03-01T12:00:00Z"}`
	enrichDone    = `{"job":"domain:a.example","state":"done","started_at":"2026-03-01T12:00:00Z","finished_at":"2026-03-01T12:00:04Z","status":"ok","counts":{"dns":1,"rdap":0,"ct":1,"subdomains":0},"summary":"ok: dns 1, rdap 0, ct 1, subdomains 0"}`
	enrichBody    = `{"fqdn":"a.example","fetched_at":"2026-03-01T12:00:04Z","status":"partial",` +
		`"dns":{"resolver":"9.9.9.9:53","records":[{"qtype":"A","rcode":"NOERROR","ttl":300,"rdata":["192.0.2.1"]}]},` +
		`"zone":null,"rdap":null,` +
		`"ct":{"zone":"a.example","total":1,"certificates":[{"id":"7392018311","cert_sha256":"` + certSHA256 + `","issuer":"R11","not_before":"2026-02-01T00:00:00Z","not_after":"2026-05-02T00:00:00Z","revoked":false,"names":["a.example"]}],"names":["a.example"],"truncated":false},` +
		`"subdomains":{"zone":"a.example","names":[{"name":"www.a.example","first_seen":"2026-02-01T00:00:00Z","last_seen":"2026-03-01T00:00:00Z"}],"truncated":false},` +
		`"errors":{"rdap":"no RDAP server"},` +
		`"graph":{"nodes":[{"id":"d:a.example","kind":"domain","label":"a.example","watched":false,"campaign":"","href":"/domains/a.example","source":"heimdall"},` +
		`{"id":"ip:192.0.2.1","kind":"ip","label":"192.0.2.1","watched":false,"campaign":"","href":"/rdata/192.0.2.1","source":"heimdall"}],` +
		`"edges":[{"from":"d:a.example","to":"ip:192.0.2.1","kind":"A"}],"truncated":false,"excluded_cdn":0}}`
	nsGraph = `{"nodes":[{"id":"ns:ana.ns.cloudflare.com,bob.ns.cloudflare.com","kind":"nsset","label":"ana.ns.cloudflare.com, bob.ns.cloudflare.com","watched":false,"campaign":"","href":"","source":"heimdall"},` +
		`{"id":"d:a.example","kind":"domain","label":"a.example","watched":true,"campaign":"SpyNote","href":"/domains/a.example","source":"heimdall"}],` +
		`"edges":[{"from":"d:a.example","to":"ns:ana.ns.cloudflare.com,bob.ns.cloudflare.com","kind":"NS_SET"}],"truncated":false,"excluded_cdn":0}`
	linkReply = `{"fqdn":"a.example","campaign":{"id":2,"name":"SpyNote"},"action":"added","created_campaign":false}`
	vtRunning = `{"job":"ip:192.0.2.1","state":"running","started_at":"2026-03-01T12:00:00Z"}`
)

const analyticsJSON = `{"days":30,` +
	`"header":{"campaign":{"id":2,"name":"SpyNote","family":"SpyNote","description":""},"domains":1,"enabled":1,"last_measured_at":"2026-03-01T11:58:00Z","vt":null},` +
	`"kpis":{"resolving":{"value":1,"series":[0,1]},"nxdomain":{"value":0,"series":[1,0]},"failing":{"value":0,"series":[0,0]},"unmeasured":{"value":0,"series":[0,0]},` +
	`"active_ips":{"value":1,"series":[0,1]},"cdn_share":{"value":0.25,"series":[0,0.25]},"ns_sets":{"value":1,"series":[1,1]},"events_7d":{"value":2,"series":[1,2]}},` +
	`"timeline":{"kinds":["new_rdata","nxdomain"],"days":[{"day":"2026-02-28","counts":{"nxdomain":1}},{"day":"2026-03-01","counts":{"new_rdata":1}}]},` +
	`"liveness":{"days":["2026-02-28","2026-03-01"],"rows":[{"fqdn":"a.example","enabled":true,"first_seen":null,"cells":["nx","ok"]}]},` +
	`"clusters":{"ips":[],"ns_sets":[],"new_ips_per_day":[{"day":"2026-02-28","ips":[]},{"day":"2026-03-01","ips":["192.0.2.1"]}],"excluded_cdn":0},` +
	`"events":[{"ts":"2026-03-01T11:00:00Z","domain":"a.example","campaign":"SpyNote","kind":"new_rdata","qtype":"A","resolver":"9.9.9.9:53","detail":{"values":["192.0.2.1"]}}],` +
	`"vt_leads":null}`

// connect serves replies, keyed by method and path, behind the tools over an
// in-memory session; anything else is a 404. requests records what Heimdall
// was asked.
func connect(t *testing.T, replies map[string]string) (*mcp.ClientSession, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		mu.Lock()
		requests = append(requests, key)
		mu.Unlock()
		if key == "GET /api/campaigns" {
			w.Write([]byte(campaignsJSON))
			return
		}
		body, ok := replies[key]
		if !ok {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	server := mcp.NewServer(&mcp.Implementation{Name: "heimdall", Version: "test"}, nil)
	Register(server, service.New(heimdall.New(srv.URL, "TOK")))
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), requests...)
	}
}

func text(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func TestNewToolsListed(t *testing.T) {
	cs, _ := connect(t, nil)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	inputs := map[string]string{}
	for _, tool := range res.Tools {
		b, _ := json.Marshal(tool.InputSchema)
		inputs[tool.Name] = string(b)
	}
	for name, params := range map[string][]string{
		"hd_campaign_analytics": {"campaign", "days", "charts_only"},
		"hd_domain_enrich":      {"fqdn", "wait", "include_graph"},
		"hd_domain_enrichment":  {"fqdn", "include_graph"},
		"hd_link_domain":        {"fqdn", "campaign", "new_campaign_name", "new_campaign_description"},
		"hd_ns_set":             {"ns"},
		"hd_vt_enrich":          {"domain", "campaign", "ip", "depth", "wait"},
	} {
		schema, ok := inputs[name]
		if !ok {
			t.Errorf("%s is not listed", name)
			continue
		}
		for _, p := range params {
			if !strings.Contains(schema, `"`+p+`"`) {
				t.Errorf("%s: input schema %s lacks %s", name, schema, p)
			}
		}
	}
}

// The SDK re-encodes structured output from a map, so object keys come back
// sorted.
func TestNewTools(t *testing.T) {
	for _, tc := range []struct {
		desc     string
		tool     string
		args     map[string]any
		replies  map[string]string
		wantReqs string
		wantErr  string
		want     []string
		notWant  []string
	}{
		{
			desc:     "enrich without wait",
			tool:     "hd_domain_enrich",
			args:     map[string]any{"fqdn": "a.example", "wait": false},
			replies:  map[string]string{"POST /api/enrich/domain/a.example": enrichRunning},
			wantReqs: "POST /api/enrich/domain/a.example",
			want:     []string{`"state":"running"`, `"summary":null`, `"enrichment":null`},
		},
		{
			desc: "enrich and wait",
			tool: "hd_domain_enrich",
			args: map[string]any{"fqdn": "A.example."},
			replies: map[string]string{
				"POST /api/enrich/domain/a.example": enrichDone,
				"GET /api/domains/a.example/enrich": enrichBody,
			},
			wantReqs: "POST /api/enrich/domain/a.example, GET /api/domains/a.example/enrich",
			want:     []string{`"state":"done"`, `"summary":"ok: dns 1, rdap 0, ct 1, subdomains 0"`, `"cert_sha256":"` + certSHA256 + `"`, `"errors":{"rdap":"no RDAP server"}`, `"www.a.example"`},
			notWant:  []string{`"graph"`},
		},
		{
			desc: "enrich with the graph",
			tool: "hd_domain_enrich",
			args: map[string]any{"fqdn": "a.example", "include_graph": true},
			replies: map[string]string{
				"POST /api/enrich/domain/a.example": enrichDone,
				"GET /api/domains/a.example/enrich": enrichBody,
			},
			wantReqs: "POST /api/enrich/domain/a.example, GET /api/domains/a.example/enrich",
			want:     []string{`"graph":{`, `"to":"ip:192.0.2.1"`},
		},
		{desc: "enrich an invalid name", tool: "hd_domain_enrich", args: map[string]any{"fqdn": "a..example"}, wantErr: "invalid fqdn"},
		{
			desc:     "enrichment",
			tool:     "hd_domain_enrichment",
			args:     map[string]any{"fqdn": "a.example"},
			replies:  map[string]string{"GET /api/domains/a.example/enrich": enrichBody},
			wantReqs: "GET /api/domains/a.example/enrich",
			want:     []string{`"status":"partial"`, `"cert_sha256":"` + certSHA256 + `"`},
			notWant:  []string{`"graph"`},
		},
		{
			desc:     "enrichment with the graph",
			tool:     "hd_domain_enrichment",
			args:     map[string]any{"fqdn": "a.example", "include_graph": true},
			replies:  map[string]string{"GET /api/domains/a.example/enrich": enrichBody},
			wantReqs: "GET /api/domains/a.example/enrich",
			want:     []string{`"graph":{`, `"kind":"domain"`},
		},
		{
			desc:     "never enriched",
			tool:     "hd_domain_enrichment",
			args:     map[string]any{"fqdn": "a.example"},
			wantReqs: "GET /api/domains/a.example/enrich",
			wantErr:  "not enriched yet, run hd_domain_enrich",
		},
		{
			desc:     "link to a campaign",
			tool:     "hd_link_domain",
			args:     map[string]any{"fqdn": "a.example", "campaign": "SpyNote"},
			replies:  map[string]string{"POST /api/domains/a.example/link": linkReply},
			wantReqs: "GET /api/campaigns, POST /api/domains/a.example/link",
			want:     []string{`"action":"added"`, `"campaign":{"id":2,"name":"SpyNote"}`},
		},
		{
			desc:    "link to both",
			tool:    "hd_link_domain",
			args:    map[string]any{"fqdn": "a.example", "campaign": "SpyNote", "new_campaign_name": "x"},
			wantErr: "either",
		},
		{
			desc:     "ns set",
			tool:     "hd_ns_set",
			args:     map[string]any{"ns": []string{"BOB.ns.cloudflare.com.", "ana.ns.cloudflare.com"}},
			replies:  map[string]string{"GET /api/graph/ns/ana.ns.cloudflare.com,bob.ns.cloudflare.com": nsGraph},
			wantReqs: "GET /api/graph/ns/ana.ns.cloudflare.com,bob.ns.cloudflare.com",
			want:     []string{`"returned":1`, `"domains":[{"campaign":"SpyNote","fqdn":"a.example","watched":true}]`},
		},
		{desc: "ns set of one", tool: "hd_ns_set", args: map[string]any{"ns": []string{"ana.ns.cloudflare.com"}}, wantErr: "got 1"},
		{
			desc:     "vt enrich an ip",
			tool:     "hd_vt_enrich",
			args:     map[string]any{"ip": "192.0.2.1", "wait": false},
			replies:  map[string]string{"POST /api/vt/enrich/ip/192.0.2.1": vtRunning},
			wantReqs: "POST /api/vt/enrich/ip/192.0.2.1",
			want:     []string{`"ip":"192.0.2.1"`, `"state":"running"`},
		},
		{desc: "vt enrich an ip and a domain", tool: "hd_vt_enrich", args: map[string]any{"ip": "192.0.2.1", "domain": "a.example"}, wantErr: "either"},
		{
			desc:     "campaign analytics",
			tool:     "hd_campaign_analytics",
			args:     map[string]any{"campaign": "SpyNote"},
			replies:  map[string]string{"GET /api/campaigns/2/analytics": analyticsJSON},
			wantReqs: "GET /api/campaigns, GET /api/campaigns/2/analytics",
			want:     []string{`"cells":"NO"`, `"last_state":"ok"`, `"vt_leads":[]`, `"vt":null`, `"id":"cdn_share"`, `"name":"cdn_share","values":[0,25]`, `"style":"bar"`},
			notWant:  []string{`"rows"`, `"id":"top_ip_clusters"`},
		},
		{
			desc:     "campaign analytics, charts only",
			tool:     "hd_campaign_analytics",
			args:     map[string]any{"campaign": "2", "days": 30, "charts_only": true},
			replies:  map[string]string{"GET /api/campaigns/2/analytics": analyticsJSON},
			wantReqs: "GET /api/campaigns, GET /api/campaigns/2/analytics",
			want:     []string{`"days":30`, `"id":"kpi_states"`, `"header":{`},
			notWant:  []string{`"kpis"`, `"timeline"`, `"liveness_summary"`, `"clusters"`, `"vt_leads"`, `"events"`},
		},
		{desc: "campaign analytics over 7 days", tool: "hd_campaign_analytics", args: map[string]any{"campaign": "SpyNote", "days": 7}, wantErr: "days must be 30 or 90"},
	} {
		cs, requests := connect(t, tc.replies)
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tc.tool, Arguments: tc.args})
		if err != nil {
			t.Errorf("%s: %v", tc.desc, err)
			continue
		}
		out := text(res)
		if got := strings.Join(requests(), ", "); got != tc.wantReqs {
			t.Errorf("%s: requests = %q, want %q", tc.desc, got, tc.wantReqs)
		}
		if tc.wantErr != "" {
			if !res.IsError || !strings.Contains(out, tc.wantErr) {
				t.Errorf("%s: %s, want an error mentioning %q", tc.desc, out, tc.wantErr)
			}
			continue
		}
		if res.IsError {
			t.Errorf("%s: error %s", tc.desc, out)
			continue
		}
		for _, w := range tc.want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: result %s lacks %s", tc.desc, out, w)
			}
		}
		for _, w := range tc.notWant {
			if strings.Contains(out, w) {
				t.Errorf("%s: result %s holds %s", tc.desc, out, w)
			}
		}
	}
}
