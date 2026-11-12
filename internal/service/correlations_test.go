package service

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/sebdraven/mcp-heimdall/internal/heimdall"
)

const corrSHA256 = "8f7a1c52e0b3d94a6c1f2e7b0d5a3c9e4b8f6a2d1c7e5b3a9f0d4c2e6b8a1f3d"

func strp(s string) *string { return &s }

func floatp(f float64) *float64 { return &f }

// correlationsFixture has Idle (5) in no pair and campaign 9 in a pair but not
// in the list; soa is counted 0 and cname never.
func correlationsFixture() heimdall.Correlations {
	link := func(kind, value, first string) heimdall.CorrelationLink {
		return heimdall.CorrelationLink{Kind: kind, Value: value, DomainA: "a.example", CampaignA: 2, DomainB: "b.example", CampaignB: 4, FirstSeen: first, LastSeen: "2026-03-01T11:00:00Z"}
	}
	return heimdall.Correlations{
		Campaigns: []heimdall.CampaignRef{{ID: 1, Name: "spynote"}, {ID: 2, Name: "SpyNote"}, {ID: 3, Name: "1"}, {ID: 4, Name: "FluBot"}, {ID: 5, Name: "Idle"}},
		Pairs: []heimdall.CorrelationPair{
			{A: 1, B: 2, Score: 0.5, Counts: map[string]int{"mx": 1}},
			{A: 2, B: 4, Score: 1, Counts: map[string]int{"cert": 1, "ip": 2}, FirstSeen: strp("2026-02-20T10:00:00Z"), LastSeen: strp("2026-03-01T11:00:00Z")},
			{A: 1, B: 4, Score: 0.82, Counts: map[string]int{"ns_set": 1, "rdap": 1, "soa": 0}},
			{A: 3, B: 9, Score: 0.3, Counts: map[string]int{"vt": 1}},
		},
		NewLinks: []heimdall.CorrelationLink{
			link("cert", corrSHA256, "2026-02-23T05:00:00Z"),
			link("ip", "192.0.2.1", "2026-02-23T23:59:59Z"),
			link("ip", "192.0.2.2", "2026-03-01T10:00:00Z"),
			link("mx", "mx.b.example", "2026-02-27T00:00:00+02:00"),
		},
		ComputedAt: strp("2026-03-01T11:00:00Z"),
	}
}

func chartByID(charts []Chart, id string) *Chart {
	for i := range charts {
		if charts[i].ID == id {
			return &charts[i]
		}
	}
	return nil
}

// wantChart checks x, the series in order and their values.
func wantChart(t *testing.T, desc string, charts []Chart, id string, x []string, names []string, values [][]float64) {
	t.Helper()
	c := chartByID(charts, id)
	if c == nil {
		t.Errorf("%s: no chart %s", desc, id)
		return
	}
	if !slices.Equal(c.X, x) {
		t.Errorf("%s: %s x %q, want %q", desc, id, c.X, x)
	}
	var got []string
	for _, s := range c.Series {
		got = append(got, s.Name)
	}
	if !slices.Equal(got, names) {
		t.Errorf("%s: %s series %q, want %q", desc, id, got, names)
		return
	}
	for i, s := range c.Series {
		if !slices.Equal(s.Values, values[i]) {
			t.Errorf("%s: %s series %s = %v, want %v", desc, id, s.Name, s.Values, values[i])
		}
	}
}

func checkCharts(t *testing.T, desc string, charts []Chart, want []string) {
	t.Helper()
	var ids []string
	for _, c := range charts {
		ids = append(ids, c.ID)
		if len(c.X) == 0 || len(c.Series) == 0 || c.Style != "bar" || c.Title == "" || c.XLabel == "" || c.YLabel == "" {
			t.Errorf("%s: chart %+v", desc, c)
		}
		nonZero := false
		for _, s := range c.Series {
			if len(s.Values) != len(c.X) {
				t.Errorf("%s: %s series %s has %d values for %d x", desc, c.ID, s.Name, len(s.Values), len(c.X))
			}
			nonZero = nonZero || slices.ContainsFunc(s.Values, func(v float64) bool { return v != 0 })
		}
		if !nonZero {
			t.Errorf("%s: %s holds only zeros", desc, c.ID)
		}
	}
	if !slices.Equal(ids, want) {
		t.Errorf("%s: charts %v, want %v", desc, ids, want)
	}
}

func jsonKeys(v any) string {
	b, _ := json.Marshal(v)
	var keys map[string]json.RawMessage
	json.Unmarshal(b, &keys)
	return strings.Join(slices.Sorted(maps.Keys(keys)), ",")
}

func TestCorrelations(t *testing.T) {
	allCharts := []string{"pair_scores", "links_by_kind", "score_matrix", "new_links_by_day"}
	week := []string{"2026-02-22", "2026-02-23", "2026-02-24", "2026-02-25", "2026-02-26", "2026-02-27", "2026-02-28", "2026-03-01"}
	for _, tc := range []struct {
		desc       string
		minScore   *float64
		kinds      []string
		since      string
		chartsOnly bool
		mod        func(*heimdall.Correlations)
		wantReqs   string
		wantQuery  url.Values
		wantErr    string
		wantCharts []string
		check      func(*testing.T, string, CorrelationsResult)
	}{
		{
			desc:       "defaults",
			wantReqs:   "GET /api/correlations",
			wantQuery:  url.Values{},
			wantCharts: allCharts,
			check: func(t *testing.T, desc string, res CorrelationsResult) {
				var got []string
				for _, p := range res.Pairs {
					got = append(got, fmt.Sprintf("%d %s-%d %s %v", p.A, p.AName, p.B, p.BName, p.Score))
				}
				if want := []string{"2 SpyNote-4 FluBot 1", "1 spynote-4 FluBot 0.82", "1 spynote-2 SpyNote 0.5", "3 1-9  0.3"}; !slices.Equal(got, want) {
					t.Errorf("%s: pairs %q, want %q", desc, got, want)
				}
				if res.Since != "2026-02-22T12:00:00Z" || res.Note != "" || res.ComputedAt == nil || len(res.Campaigns) != 5 {
					t.Errorf("%s: since %q, note %q, computed_at %v, %d campaigns", desc, res.Since, res.Note, res.ComputedAt, len(res.Campaigns))
				}
				if l := res.NewLinks; len(l) != 4 || l[0].Value != corrSHA256 || l[0].CampaignAName != "SpyNote" || l[0].CampaignBName != "FluBot" {
					t.Errorf("%s: new links %+v", desc, l)
				}
				b, _ := json.Marshal(res)
				for _, w := range []string{`"a_name":"SpyNote"`, `"b_name":"FluBot"`, `"campaign_a_name":"SpyNote"`, `"value":"` + corrSHA256 + `"`, `"counts":{"cert":1,"ip":2}`} {
					if !strings.Contains(string(b), w) {
						t.Errorf("%s: encoded as %s, lacks %s", desc, b, w)
					}
				}
				if strings.Contains(string(b), `"note":`) {
					t.Errorf("%s: encoded as %s, holds a note", desc, b)
				}

				pairs := []string{"SpyNote ↔ FluBot", "spynote ↔ FluBot", "spynote ↔ SpyNote", "1 ↔ #9"}
				wantChart(t, desc, res.Charts, "pair_scores", pairs, []string{"score"}, [][]float64{{1, 0.82, 0.5, 0.3}})
				wantChart(t, desc, res.Charts, "links_by_kind", pairs,
					[]string{"cert", "ns_set", "ip", "mx", "rdap", "vt"},
					[][]float64{{1, 0, 0, 0}, {0, 1, 0, 0}, {2, 0, 0, 0}, {0, 0, 1, 0}, {0, 1, 0, 0}, {0, 0, 0, 1}})
				matrix := []string{"spynote", "SpyNote", "1", "FluBot", "#9"}
				wantChart(t, desc, res.Charts, "score_matrix", matrix, matrix, [][]float64{
					{0, 0.5, 0, 0.82, 0},
					{0.5, 0, 0, 1, 0},
					{0, 0, 0, 0, 0.3},
					{0.82, 1, 0, 0, 0},
					{0, 0, 0.3, 0, 0},
				})
				if m := chartByID(res.Charts, "score_matrix"); m != nil {
					for i := range m.Series {
						for j := range m.Series {
							if m.Series[i].Values[j] != m.Series[j].Values[i] || (i == j && m.Series[i].Values[i] != 0) {
								t.Errorf("%s: score_matrix [%d][%d] = %v, [%d][%d] = %v", desc, i, j, m.Series[i].Values[j], j, i, m.Series[j].Values[i])
							}
						}
					}
				}
				wantChart(t, desc, res.Charts, "new_links_by_day", week, []string{"cert", "ip", "mx"}, [][]float64{
					{0, 1, 0, 0, 0, 0, 0, 0},
					{0, 1, 0, 0, 0, 0, 0, 1},
					{0, 0, 0, 0, 1, 0, 0, 0},
				})
			},
		},
		{
			desc:       "parameters",
			minScore:   floatp(0.5),
			kinds:      []string{" ip", "cert", "ip", ""},
			since:      "2d",
			wantReqs:   "GET /api/correlations",
			wantQuery:  url.Values{"min_score": {"0.5"}, "kinds": {"ip,cert"}, "since": {"2026-02-27T12:00:00Z"}},
			wantCharts: allCharts,
			check: func(t *testing.T, desc string, res CorrelationsResult) {
				if res.Since != "2026-02-27T12:00:00Z" {
					t.Errorf("%s: since %q", desc, res.Since)
				}
				wantChart(t, desc, res.Charts, "new_links_by_day", []string{"2026-02-27", "2026-02-28", "2026-03-01"}, []string{"ip"}, [][]float64{{0, 0, 1}})
			},
		},
		{
			desc:       "since as RFC 3339",
			since:      "2026-02-28T23:00:00+02:00",
			wantReqs:   "GET /api/correlations",
			wantQuery:  url.Values{"since": {"2026-02-28T21:00:00Z"}},
			wantCharts: []string{"pair_scores", "links_by_kind", "score_matrix", "new_links_by_day"},
			check: func(t *testing.T, desc string, res CorrelationsResult) {
				wantChart(t, desc, res.Charts, "new_links_by_day", []string{"2026-02-28", "2026-03-01"}, []string{"ip"}, [][]float64{{0, 1}})
			},
		},
		{desc: "min score 0 is sent", minScore: floatp(0), wantReqs: "GET /api/correlations", wantQuery: url.Values{"min_score": {"0"}}, wantCharts: allCharts},
		{
			desc: "at most 15 pairs, highest score first",
			mod: func(c *heimdall.Correlations) {
				c.Pairs = nil
				for i := range 20 {
					c.Pairs = append(c.Pairs, heimdall.CorrelationPair{A: 1, B: int64(100 + i), Score: float64(i+1) / 20, Counts: map[string]int{"cname": 1}})
				}
				c.NewLinks = nil
			},
			wantReqs:   "GET /api/correlations",
			wantQuery:  url.Values{},
			wantCharts: []string{"pair_scores", "links_by_kind", "score_matrix"},
			check: func(t *testing.T, desc string, res CorrelationsResult) {
				if len(res.Pairs) != 20 || res.Pairs[0].B != 119 || res.Pairs[19].B != 100 {
					t.Errorf("%s: %d pairs, from %+v", desc, len(res.Pairs), res.Pairs[0])
				}
				c := chartByID(res.Charts, "pair_scores")
				if c == nil || len(c.X) != 15 || c.X[0] != "spynote ↔ #119" || c.X[14] != "spynote ↔ #105" {
					t.Fatalf("%s: pair_scores %+v", desc, c)
				}
				for k, v := range c.Series[0].Values {
					if want := float64(20-k) / 20; v != want {
						t.Errorf("%s: score %d = %v, want %v", desc, k, v, want)
					}
				}
				if l := chartByID(res.Charts, "links_by_kind"); l == nil || len(l.X) != 15 || len(l.Series) != 1 || l.Series[0].Name != "cname" {
					t.Errorf("%s: links_by_kind %+v", desc, l)
				}
				if m := chartByID(res.Charts, "score_matrix"); m == nil || len(m.X) != 21 || len(m.Series) != 21 {
					t.Errorf("%s: score_matrix %+v", desc, m)
				}
			},
		},
		{
			desc: "not computed",
			mod: func(c *heimdall.Correlations) {
				c.ComputedAt, c.Pairs, c.NewLinks = nil, nil, nil
			},
			wantReqs:   "GET /api/correlations",
			wantQuery:  url.Values{},
			wantCharts: nil,
			check: func(t *testing.T, desc string, res CorrelationsResult) {
				if res.Note != notComputed {
					t.Errorf("%s: note %q", desc, res.Note)
				}
				b, _ := json.Marshal(res)
				for _, w := range []string{`"computed_at":null`, `"pairs":[]`, `"new_links":[]`, `"charts":[]`, `"note":"correlation not computed yet (Heimdall computes every hour)"`} {
					if !strings.Contains(string(b), w) {
						t.Errorf("%s: encoded as %s, lacks %s", desc, b, w)
					}
				}
			},
		},
		{
			desc: "new links at Heimdall's cap",
			mod: func(c *heimdall.Correlations) {
				c.NewLinks = nil
				for range 500 {
					c.NewLinks = append(c.NewLinks, heimdall.CorrelationLink{Kind: "ip", Value: "192.0.2.1", FirstSeen: "2026-03-01T10:00:00Z"})
				}
			},
			wantReqs:   "GET /api/correlations",
			wantQuery:  url.Values{},
			wantCharts: allCharts,
			check: func(t *testing.T, desc string, res CorrelationsResult) {
				if !strings.Contains(res.Note, "500 new links") {
					t.Errorf("%s: note %q", desc, res.Note)
				}
			},
		},
		{
			desc:       "charts only",
			chartsOnly: true,
			wantReqs:   "GET /api/correlations",
			wantQuery:  url.Values{},
			wantCharts: allCharts,
			check: func(t *testing.T, desc string, res CorrelationsResult) {
				if got := jsonKeys(res); got != "campaigns,charts,computed_at" {
					t.Errorf("%s: keys %s", desc, got)
				}
			},
		},
		{
			desc:       "charts only, not computed",
			chartsOnly: true,
			mod:        func(c *heimdall.Correlations) { c.ComputedAt, c.Pairs = nil, nil },
			wantReqs:   "GET /api/correlations",
			wantQuery:  url.Values{},
			wantCharts: []string{"new_links_by_day"},
			check: func(t *testing.T, desc string, res CorrelationsResult) {
				if got := jsonKeys(res); got != "campaigns,charts,computed_at,note" {
					t.Errorf("%s: keys %s", desc, got)
				}
			},
		},
		{desc: "min score above 1", minScore: floatp(1.5), wantErr: "min_score must be between 0 and 1"},
		{desc: "negative min score", minScore: floatp(-0.1), wantErr: "min_score must be between 0 and 1"},
		{desc: "min score NaN", minScore: floatp(math.NaN()), wantErr: "min_score must be between 0 and 1"},
		{desc: "unknown kind", kinds: []string{"ip", "dns"}, wantErr: `unknown kind "dns"`},
		{desc: "bad since", since: "yesterday", wantErr: "since"},
	} {
		c := correlationsFixture()
		if tc.mod != nil {
			tc.mod(&c)
		}
		var gotQuery url.Values
		s, reqs := stub(t, func(w http.ResponseWriter, r *http.Request) {
			gotQuery = r.URL.Query()
			json.NewEncoder(w).Encode(c)
		})
		res, err := s.Correlations(context.Background(), tc.minScore, tc.kinds, tc.since, tc.chartsOnly)
		if got := strings.Join(*reqs, ", "); got != tc.wantReqs {
			t.Errorf("%s: requests = %q, want %q", tc.desc, got, tc.wantReqs)
		}
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: err %v, want one mentioning %q", tc.desc, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.desc, err)
			continue
		}
		if gotQuery.Encode() != tc.wantQuery.Encode() {
			t.Errorf("%s: query %q, want %q", tc.desc, gotQuery.Encode(), tc.wantQuery.Encode())
		}
		checkCharts(t, tc.desc, res.Charts, tc.wantCharts)
		if res.Charts == nil {
			t.Errorf("%s: charts nil, want a list", tc.desc)
		}
		if tc.check != nil {
			tc.check(t, tc.desc, res)
		}
	}
}

func correlationPairFixture() heimdall.CorrelationPairDetail {
	ev := func(kind, value, b string, w float64) heimdall.CorrelationEvidence {
		return heimdall.CorrelationEvidence{Kind: kind, Value: value, DomainA: "a.example", CampaignA: 1, DomainB: b, CampaignB: 3, Weight: w}
	}
	cert := ev("cert", corrSHA256, "b.example", 1)
	cert.Period = &heimdall.Period{First: "2026-02-01T00:00:00Z", Last: "2026-05-02T00:00:00Z"}
	return heimdall.CorrelationPairDetail{
		A: heimdall.CampaignRef{ID: 1, Name: "spynote"}, B: heimdall.CampaignRef{ID: 3, Name: "1"},
		Score: 1, Counts: map[string]int{"cert": 1, "ip": 2},
		Evidence: []heimdall.CorrelationEvidence{cert, ev("ip", "192.0.2.1", "c.example", 0.4), ev("ip", "192.0.2.2", "d.example", 0.2)},
		Past: []heimdall.CorrelationLink{{Kind: "mx", Value: "mx.c.example", DomainA: "a.example", CampaignA: 1, DomainB: "c.example", CampaignB: 3,
			FirstSeen: "2026-01-02T00:00:00Z", LastSeen: "2026-01-09T00:00:00Z"}},
		ComputedAt: strp("2026-03-01T11:00:00Z"),
	}
}

func TestCorrelationPair(t *testing.T) {
	for _, tc := range []struct {
		desc       string
		a, b       string
		kinds      []string
		mod        func(*heimdall.CorrelationPairDetail)
		wantReqs   string
		wantQuery  string
		wantErr    string
		wantCharts []string
		check      func(*testing.T, string, CorrelationPairResult)
	}{
		{
			desc:       "by name and id",
			a:          "spynote",
			b:          "3",
			wantReqs:   "GET /api/campaigns, GET /api/campaigns, GET /api/correlations/1/3",
			wantCharts: []string{"evidence_by_kind"},
			check: func(t *testing.T, desc string, res CorrelationPairResult) {
				if res.A != (heimdall.CampaignRef{ID: 1, Name: "spynote"}) || res.B != (heimdall.CampaignRef{ID: 3, Name: "1"}) || res.Score != 1 || res.Note != "" {
					t.Errorf("%s: result %+v", desc, res)
				}
				if e := res.Evidence; len(e) != 3 || e[0].Value != corrSHA256 || e[0].CampaignAName != "spynote" || e[0].CampaignBName != "1" || e[0].Period == nil {
					t.Errorf("%s: evidence %+v", desc, e)
				}
				if p := res.Past; len(p) != 1 || p[0].CampaignAName != "spynote" || p[0].CampaignBName != "1" {
					t.Errorf("%s: past %+v", desc, p)
				}
				wantChart(t, desc, res.Charts, "evidence_by_kind", []string{"cert", "ip"}, []string{"links", "max weight"}, [][]float64{{1, 2}, {1, 0.4}})
				b, _ := json.Marshal(res)
				for _, w := range []string{`"value":"` + corrSHA256 + `"`, `"campaign_a_name":"spynote"`, `"weight":0.4`, `"period":null`, `"period":{"first":"2026-02-01T00:00:00Z"`} {
					if !strings.Contains(string(b), w) {
						t.Errorf("%s: encoded as %s, lacks %s", desc, b, w)
					}
				}
			},
		},
		{
			desc:       "kinds",
			a:          "spynote",
			b:          "3",
			kinds:      []string{"cert", " mx ", "cert"},
			wantReqs:   "GET /api/campaigns, GET /api/campaigns, GET /api/correlations/1/3",
			wantQuery:  "cert,mx",
			wantCharts: []string{"evidence_by_kind"},
		},
		{
			desc: "not computed",
			a:    "3",
			b:    "spynote",
			mod: func(d *heimdall.CorrelationPairDetail) {
				d.ComputedAt, d.Score, d.Counts, d.Evidence, d.Past = nil, 0, nil, nil, nil
			},
			wantReqs: "GET /api/campaigns, GET /api/campaigns, GET /api/correlations/3/1",
			check: func(t *testing.T, desc string, res CorrelationPairResult) {
				if res.Note != notComputed {
					t.Errorf("%s: note %q", desc, res.Note)
				}
				b, _ := json.Marshal(res)
				for _, w := range []string{`"computed_at":null`, `"counts":{}`, `"evidence":[]`, `"past":[]`, `"charts":[]`} {
					if !strings.Contains(string(b), w) {
						t.Errorf("%s: encoded as %s, lacks %s", desc, b, w)
					}
				}
			},
		},
		{desc: "same campaign", a: "SpyNote", b: "2", wantReqs: "GET /api/campaigns, GET /api/campaigns", wantErr: "same campaign"},
		{desc: "unknown kind", a: "spynote", b: "3", kinds: []string{"whois"}, wantErr: `unknown kind "whois"`},
		{desc: "unknown campaign", a: "spynote", b: "missing", wantReqs: "GET /api/campaigns, GET /api/campaigns", wantErr: "b: no campaign"},
		{desc: "ambiguous campaign", a: "1", b: "3", wantReqs: "GET /api/campaigns", wantErr: "a: campaign \"1\" is ambiguous"},
		{desc: "no campaign", a: "", b: "3", wantReqs: "", wantErr: "a: campaign is required"},
	} {
		d := correlationPairFixture()
		if tc.mod != nil {
			tc.mod(&d)
		}
		var gotQuery string
		s, reqs := stub(t, func(w http.ResponseWriter, r *http.Request) {
			gotQuery = r.URL.Query().Get("kinds")
			json.NewEncoder(w).Encode(d)
		})
		res, err := s.CorrelationPair(context.Background(), tc.a, tc.b, tc.kinds)
		if got := strings.Join(*reqs, ", "); got != tc.wantReqs {
			t.Errorf("%s: requests = %q, want %q", tc.desc, got, tc.wantReqs)
		}
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: err %v, want one mentioning %q", tc.desc, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.desc, err)
			continue
		}
		if gotQuery != tc.wantQuery {
			t.Errorf("%s: kinds %q, want %q", tc.desc, gotQuery, tc.wantQuery)
		}
		checkCharts(t, tc.desc, res.Charts, tc.wantCharts)
		if tc.check != nil {
			tc.check(t, tc.desc, res)
		}
	}
}
