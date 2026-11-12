package heimdall

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

const corrSHA256 = "8f7a1c52e0b3d94a6c1f2e7b0d5a3c9e4b8f6a2d1c7e5b3a9f0d4c2e6b8a1f3d"

const correlationsBody = `{"campaigns":[{"id":1,"name":"SpyNote"},{"id":3,"name":"FluBot"}],` +
	`"pairs":[{"a":1,"b":3,"score":0.95,"counts":{"mx":1,"ns_set":1},"first_seen":"2026-02-20T10:00:00Z","last_seen":"2026-03-01T11:00:00Z"}],` +
	`"new_links":[{"kind":"cert","value":"` + corrSHA256 + `","domain_a":"a.example","campaign_a":1,"domain_b":"b.example","campaign_b":3,"first_seen":"2026-02-28T09:00:00Z","last_seen":"2026-03-01T11:00:00Z"}],` +
	`"computed_at":"2026-03-01T11:00:00Z"}`

const correlationPairBody = `{"a":{"id":1,"name":"SpyNote"},"b":{"id":3,"name":"FluBot"},"score":1,"counts":{"cert":1,"ip":1},` +
	`"evidence":[{"kind":"cert","value":"` + corrSHA256 + `","domain_a":"a.example","campaign_a":1,"domain_b":"b.example","campaign_b":3,"weight":1,` +
	`"period":{"first":"2026-02-01T00:00:00Z","last":"2026-05-02T00:00:00Z"},"first_seen":"2026-02-28T09:00:00Z","last_seen":"2026-03-01T11:00:00Z"},` +
	`{"kind":"ip","value":"192.0.2.1","domain_a":"a.example","campaign_a":1,"domain_b":"c.example","campaign_b":3,"weight":0.4,"period":null,"first_seen":null,"last_seen":null}],` +
	`"past":[{"kind":"mx","value":"mx.c.example","domain_a":"a.example","campaign_a":1,"domain_b":"c.example","campaign_b":3,"first_seen":"2026-01-02T00:00:00Z","last_seen":"2026-01-09T00:00:00Z"}],` +
	`"computed_at":null}`

func TestCorrelations(t *testing.T) {
	zero, half := 0.0, 0.25
	for _, tc := range []struct {
		desc string
		q    CorrelationQuery
		want url.Values
	}{
		{desc: "no parameter", want: url.Values{}},
		{desc: "empty kinds", q: CorrelationQuery{Kinds: []string{}}, want: url.Values{}},
		{desc: "min score 0", q: CorrelationQuery{MinScore: &zero}, want: url.Values{"min_score": {"0"}}},
		{
			desc: "all",
			q:    CorrelationQuery{MinScore: &half, Kinds: []string{"ip", "cert"}, Since: "2026-02-22T12:00:00Z"},
			want: url.Values{"min_score": {"0.25"}, "kinds": {"ip,cert"}, "since": {"2026-02-22T12:00:00Z"}},
		},
	} {
		var got string
		var gotQuery url.Values
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, gotQuery = r.Method+" "+r.URL.Path, r.URL.Query()
			w.Write([]byte(correlationsBody))
		}))
		c, err := New(srv.URL, "TOK").Correlations(context.Background(), tc.q)
		srv.Close()
		if err != nil {
			t.Errorf("%s: %v", tc.desc, err)
			continue
		}
		if got != "GET /api/correlations" {
			t.Errorf("%s: sent %q", tc.desc, got)
		}
		if gotQuery.Encode() != tc.want.Encode() {
			t.Errorf("%s: query %q, want %q", tc.desc, gotQuery.Encode(), tc.want.Encode())
		}
		b, _ := json.Marshal(c)
		if string(b) != correlationsBody {
			t.Errorf("%s: decoded and encoded back as\n%s\nwant\n%s", tc.desc, b, correlationsBody)
		}
		if len(c.Pairs) != 1 || c.Pairs[0].Counts["ns_set"] != 1 || c.ComputedAt == nil || c.NewLinks[0].Value != corrSHA256 {
			t.Errorf("%s: correlations %+v", tc.desc, c)
		}
	}
}

func TestCorrelationsNotComputed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"campaigns":[],"pairs":[],"new_links":[],"computed_at":null}`))
	}))
	defer srv.Close()
	c, err := New(srv.URL, "TOK").Correlations(context.Background(), CorrelationQuery{})
	if err != nil || c.ComputedAt != nil || c.Pairs == nil || len(c.Pairs) != 0 {
		t.Errorf("correlations %+v, err %v; want computed_at nil and no pair", c, err)
	}
}

func TestCorrelationPair(t *testing.T) {
	for _, tc := range []struct {
		kinds []string
		query string
	}{
		{},
		{kinds: []string{"cert", "mx"}, query: "cert,mx"},
	} {
		var got, gotKinds, gotRaw string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, gotKinds, gotRaw = r.Method+" "+r.URL.Path, r.URL.Query().Get("kinds"), r.URL.RawQuery
			w.Write([]byte(correlationPairBody))
		}))
		d, err := New(srv.URL, "TOK").CorrelationPair(context.Background(), 1, 3, tc.kinds)
		srv.Close()
		if err != nil {
			t.Errorf("kinds %v: %v", tc.kinds, err)
			continue
		}
		if got != "GET /api/correlations/1/3" || gotKinds != tc.query || (tc.query == "" && gotRaw != "") {
			t.Errorf("kinds %v: sent %q ?%s", tc.kinds, got, gotRaw)
		}
		b, _ := json.Marshal(d)
		if string(b) != correlationPairBody {
			t.Errorf("kinds %v: decoded and encoded back as\n%s\nwant\n%s", tc.kinds, b, correlationPairBody)
		}
		if len(d.Evidence) != 2 || d.Evidence[0].Period == nil || d.Evidence[1].Period != nil || d.Evidence[1].Weight != 0.4 || d.ComputedAt != nil || len(d.Past) != 1 {
			t.Errorf("kinds %v: detail %+v", tc.kinds, d)
		}
	}
}
