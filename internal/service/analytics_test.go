package service

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sebdraven/mcp-heimdall/internal/heimdall"
)

func names(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("d%d.example", i)
	}
	return out
}

// analyticsFixture covers three days. cdn_share is zero throughout, ttl_change
// has no count, and the IP clusters come in address order.
func analyticsFixture() heimdall.Analytics {
	kpi := func(s ...float64) heimdall.KPI { return heimdall.KPI{Value: s[len(s)-1], Series: s} }
	first := "2026-01-10T08:00:00Z"
	var ips []heimdall.IPCluster
	for _, c := range []struct {
		ip string
		n  int
	}{
		{"192.0.2.1", 2}, {"192.0.2.2", 3}, {"192.0.2.3", 2}, {"192.0.2.4", 4}, {"192.0.2.5", 2}, {"192.0.2.6", 2},
		{"192.0.2.7", 3}, {"192.0.2.8", 2}, {"192.0.2.9", 5}, {"192.0.2.10", 5}, {"192.0.2.11", 2}, {"192.0.2.12", 2},
		{"2001:db8::1", 3},
	} {
		ips = append(ips, heimdall.IPCluster{IP: c.ip, Domains: names(c.n), FirstSeen: "2026-02-27", LastSeen: "2026-03-01"})
	}
	var events []heimdall.Event
	for i := range 60 {
		ts := t0.Add(-time.Duration(60-i) * time.Minute).Format(time.RFC3339)
		events = append(events, heimdall.Event{TS: ts, Domain: "a.example", Campaign: "SpyNote", Kind: "new_rdata", QType: "A", Resolver: "9.9.9.9:53"})
	}
	return heimdall.Analytics{
		Days: 30,
		Header: heimdall.AnalyticsHeader{
			Campaign: heimdall.AnalyticsCampaign{ID: 2, Name: "SpyNote", Family: "SpyNote"},
			Domains:  3,
			Enabled:  2,
		},
		KPIs: heimdall.KPIs{
			Resolving: kpi(1, 1, 2), NXDomain: kpi(1, 0, 0), Failing: kpi(0, 1, 0), Unmeasured: kpi(1, 1, 1),
			ActiveIPs: kpi(1, 2, 2), CDNShare: kpi(0, 0, 0), NSSets: kpi(1, 1, 1), Events7d: kpi(1, 1, 4),
		},
		Timeline: heimdall.Timeline{
			Kinds: []string{"new_rdata", "nxdomain", "ttl_change"},
			Days: []heimdall.TimelineDay{
				{Day: "2026-02-27", Counts: map[string]uint64{"nxdomain": 1}},
				{Day: "2026-02-28", Counts: map[string]uint64{}},
				{Day: "2026-03-01", Counts: map[string]uint64{"new_rdata": 2}},
			},
		},
		Liveness: heimdall.Liveness{
			Days: []string{"2026-02-27", "2026-02-28", "2026-03-01"},
			Rows: []heimdall.LivenessRow{
				{FQDN: "a.example", Enabled: true, FirstSeen: &first, Cells: []string{"nx", "ok", "ok"}},
				{FQDN: "b.example", Enabled: true, FirstSeen: &first, Cells: []string{"ok", "fail", "ok"}},
				{FQDN: "c.example", Cells: []string{"none", "none", "none"}},
			},
		},
		Clusters: heimdall.Clusters{
			IPs:          ips,
			NSSets:       []heimdall.NSCluster{{NS: []string{"ana.ns.cloudflare.com", "bob.ns.cloudflare.com"}, Zones: []string{"a.example", "b.example"}, Domains: []string{"a.example", "b.example"}}},
			NewIPsPerDay: []heimdall.NewIPs{{Day: "2026-01-01", IPs: []string{"192.0.2.99"}}, {Day: "2026-03-01", IPs: []string{"192.0.2.1", "192.0.2.9"}}},
			ExcludedCDN:  1,
		},
		Events: events,
	}
}

func findChart(res CampaignAnalyticsResult, id string) *Chart {
	for i := range res.Charts {
		if res.Charts[i].ID == id {
			return &res.Charts[i]
		}
	}
	return nil
}

// wantSeries checks the values of each named series of chart id.
func wantSeries(t *testing.T, res CampaignAnalyticsResult, id string, x []string, want map[string][]float64) {
	t.Helper()
	c := findChart(res, id)
	if c == nil {
		t.Errorf("%s: no chart", id)
		return
	}
	if x != nil && !slices.Equal(c.X, x) {
		t.Errorf("%s: x %v, want %v", id, c.X, x)
	}
	got := map[string][]float64{}
	for _, s := range c.Series {
		got[s.Name] = s.Values
	}
	if len(got) != len(want) {
		t.Errorf("%s: series %v, want %v", id, got, want)
	}
	for name, w := range want {
		if !slices.Equal(got[name], w) {
			t.Errorf("%s: series %s = %v, want %v", id, name, got[name], w)
		}
	}
}

func TestCampaignAnalytics(t *testing.T) {
	days := []string{"2026-02-27", "2026-02-28", "2026-03-01"}
	allCharts := []string{"kpi_states", "kpi_infra", "events_by_kind", "new_ips_per_day", "liveness_by_day", "top_ip_clusters"}
	for _, tc := range []struct {
		desc       string
		campaign   string
		days       int
		chartsOnly bool
		mod        func(*heimdall.Analytics)
		wantReqs   string
		wantQuery  string
		wantErr    string
		wantCharts []string
		check      func(*testing.T, CampaignAnalyticsResult)
	}{
		{
			desc:       "default window",
			wantReqs:   "GET /api/campaigns, GET /api/campaigns/2/analytics",
			wantCharts: allCharts,
			check: func(t *testing.T, res CampaignAnalyticsResult) {
				if res.Campaign.ID != 2 || res.Days != 30 || res.Header.Domains != 3 || res.KPIs == nil || res.Timeline == nil || res.Clusters == nil {
					t.Errorf("result %+v", res)
				}
				wantSeries(t, res, "kpi_states", days, map[string][]float64{"resolving": {1, 1, 2}, "nxdomain": {1, 0, 0}, "failing": {0, 1, 0}, "unmeasured": {1, 1, 1}})
				wantSeries(t, res, "kpi_infra", days, map[string][]float64{"active_ips": {1, 2, 2}, "ns_sets": {1, 1, 1}})
				wantSeries(t, res, "events_by_kind", days, map[string][]float64{"new_rdata": {0, 0, 2}, "nxdomain": {1, 0, 0}, "ttl_change": {0, 0, 0}})
				wantSeries(t, res, "new_ips_per_day", days, map[string][]float64{"new_ips": {0, 0, 2}})
				wantSeries(t, res, "liveness_by_day", days, map[string][]float64{"ok": {1, 1, 2}, "nx": {1, 0, 0}, "fail": {0, 1, 0}, "none": {1, 1, 1}})
				wantSeries(t, res, "top_ip_clusters",
					[]string{"192.0.2.9", "192.0.2.10", "192.0.2.4", "192.0.2.2", "192.0.2.7", "2001:db8::1", "192.0.2.1", "192.0.2.3", "192.0.2.5", "192.0.2.6"},
					map[string][]float64{"domains": {5, 5, 4, 3, 3, 3, 2, 2, 2, 2}})
				if c := findChart(res, "events_by_kind"); c == nil || c.Style != "bar" || slices.IndexFunc(c.Series, func(s ChartSeries) bool { return s.Name == "ttl_change" }) != 2 {
					t.Errorf("events_by_kind = %+v, want one bar series per kind in timeline order", c)
				}

				l := res.LivenessSummary
				if l == nil || !slices.Equal(l.Days, days) || len(l.Domains) != 3 {
					t.Fatalf("liveness summary %+v", l)
				}
				first := "2026-01-10T08:00:00Z"
				for i, want := range []DomainLiveness{
					{FQDN: "a.example", Enabled: true, FirstSeen: &first, OK: 2, NX: 1, LastState: "ok", Cells: "NOO"},
					{FQDN: "b.example", Enabled: true, FirstSeen: &first, OK: 2, Fail: 1, LastState: "ok", Cells: "OFO"},
					{FQDN: "c.example", None: 3, LastState: "none", Cells: "..."},
				} {
					got := l.Domains[i]
					if (got.FirstSeen == nil) != (want.FirstSeen == nil) || (got.FirstSeen != nil && *got.FirstSeen != *want.FirstSeen) {
						t.Errorf("domain %d: first_seen %v, want %v", i, got.FirstSeen, want.FirstSeen)
					}
					got.FirstSeen, want.FirstSeen = nil, nil
					if got != want {
						t.Errorf("domain %d: %+v, want %+v", i, got, want)
					}
				}

				if len(res.Events) != 50 || res.Events[0].TS != "2026-03-01T11:59:00Z" || res.Events[49].TS != "2026-03-01T11:10:00Z" {
					t.Errorf("%d events, from %s to %s; want the 50 most recent, newest first", len(res.Events), res.Events[0].TS, res.Events[len(res.Events)-1].TS)
				}
				b, _ := json.Marshal(res)
				for _, w := range []string{`"vt_leads":[]`, `"liveness_summary":{`, `"kpis":{`, `"timeline":{`, `"clusters":{`, `"events":[`, `"vt":null`} {
					if !strings.Contains(string(b), w) {
						t.Errorf("encoded as %s, lacks %s", b, w)
					}
				}
				for _, w := range []string{`"liveness":`, `"rows":`} {
					if strings.Contains(string(b), w) {
						t.Errorf("encoded as %s, holds the raw matrix %s", b, w)
					}
				}
			},
		},
		{
			desc:       "90 days",
			days:       90,
			mod:        func(a *heimdall.Analytics) { a.Days = 90 },
			wantReqs:   "GET /api/campaigns, GET /api/campaigns/2/analytics",
			wantQuery:  "days=90",
			wantCharts: allCharts,
			check: func(t *testing.T, res CampaignAnalyticsResult) {
				if res.Days != 90 {
					t.Errorf("days %d", res.Days)
				}
			},
		},
		{
			desc:       "30 days by id",
			campaign:   "3",
			days:       30,
			wantReqs:   "GET /api/campaigns, GET /api/campaigns/3/analytics",
			wantCharts: allCharts,
		},
		{
			desc: "cdn share in percent",
			mod: func(a *heimdall.Analytics) {
				a.KPIs.CDNShare = heimdall.KPI{Value: 0.5, Series: []float64{0, 0.3333, 0.5}}
			},
			wantReqs:   "GET /api/campaigns, GET /api/campaigns/2/analytics",
			wantCharts: []string{"kpi_states", "kpi_infra", "cdn_share", "events_by_kind", "new_ips_per_day", "liveness_by_day", "top_ip_clusters"},
			check: func(t *testing.T, res CampaignAnalyticsResult) {
				wantSeries(t, res, "cdn_share", days, map[string][]float64{"cdn_share": {0, 33.33, 50}})
				if c := findChart(res, "cdn_share"); c == nil || c.Style != "line" || !strings.Contains(c.YLabel, "%") || !strings.Contains(c.YLabel, "100") {
					t.Errorf("cdn_share = %+v, want a line in percent saying so", c)
				}
				if res.KPIs.CDNShare.Value != 0.5 {
					t.Errorf("kpis changed: %+v", res.KPIs.CDNShare)
				}
			},
		},
		{
			desc: "charts of zeros omitted",
			mod: func(a *heimdall.Analytics) {
				for i := range a.Timeline.Days {
					a.Timeline.Days[i].Counts = map[string]uint64{}
				}
				a.Clusters.NewIPsPerDay, a.Clusters.IPs = nil, nil
				a.KPIs.ActiveIPs.Series, a.KPIs.NSSets.Series = []float64{0, 0, 0}, []float64{0, 0, 0}
			},
			wantReqs:   "GET /api/campaigns, GET /api/campaigns/2/analytics",
			wantCharts: []string{"kpi_states", "liveness_by_day"},
		},
		{
			desc: "no days",
			mod: func(a *heimdall.Analytics) {
				a.Liveness.Days, a.Timeline.Days = nil, nil
			},
			wantReqs:   "GET /api/campaigns, GET /api/campaigns/2/analytics",
			wantCharts: []string{"top_ip_clusters"},
			check: func(t *testing.T, res CampaignAnalyticsResult) {
				if l := res.LivenessSummary; l == nil || l.Days == nil || l.Domains[0].Cells != "NOO" {
					t.Errorf("liveness summary %+v", l)
				}
			},
		},
		{
			desc: "series of another length left out",
			mod: func(a *heimdall.Analytics) {
				a.KPIs.NSSets.Series = []float64{1, 1}
				a.Liveness.Rows[0].Cells = []string{"ok", "bogus", "ok", "ok"}
			},
			wantReqs:   "GET /api/campaigns, GET /api/campaigns/2/analytics",
			wantCharts: allCharts,
			check: func(t *testing.T, res CampaignAnalyticsResult) {
				wantSeries(t, res, "kpi_infra", days, map[string][]float64{"active_ips": {1, 2, 2}})
				wantSeries(t, res, "liveness_by_day", days, map[string][]float64{"ok": {2, 0, 2}, "nx": {0, 0, 0}, "fail": {0, 1, 0}, "none": {1, 2, 1}})
				if d := res.LivenessSummary.Domains[0]; d.Cells != "O.OO" || d.OK != 3 || d.None != 1 || d.LastState != "ok" {
					t.Errorf("domain %+v", d)
				}
			},
		},
		{
			desc:       "charts only",
			chartsOnly: true,
			wantReqs:   "GET /api/campaigns, GET /api/campaigns/2/analytics",
			wantCharts: allCharts,
			check: func(t *testing.T, res CampaignAnalyticsResult) {
				if res.KPIs != nil || res.Timeline != nil || res.LivenessSummary != nil || res.Clusters != nil || res.VTLeads != nil || res.Events != nil {
					t.Errorf("result %+v, want campaign, days, header and charts only", res)
				}
				b, _ := json.Marshal(res)
				var keys map[string]json.RawMessage
				json.Unmarshal(b, &keys)
				if got := slices.Sorted(maps.Keys(keys)); strings.Join(got, ",") != "campaign,charts,days,header" {
					t.Errorf("keys %v", got)
				}
			},
		},
		{desc: "7 days", days: 7, wantErr: "days must be 30 or 90"},
		{desc: "60 days", days: 60, wantErr: "days must be 30 or 90"},
		{desc: "negative days", days: -30, wantErr: "days must be 30 or 90"},
		{desc: "unknown campaign", campaign: "missing", wantReqs: "GET /api/campaigns", wantErr: "no campaign"},
	} {
		a := analyticsFixture()
		if tc.mod != nil {
			tc.mod(&a)
		}
		var gotQuery string
		s, reqs := stub(t, func(w http.ResponseWriter, r *http.Request) {
			gotQuery = r.URL.RawQuery
			json.NewEncoder(w).Encode(a)
		})
		res, err := s.CampaignAnalytics(context.Background(), cmp.Or(tc.campaign, "SpyNote"), tc.days, tc.chartsOnly)
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
			t.Errorf("%s: query %q, want %q", tc.desc, gotQuery, tc.wantQuery)
		}
		var ids []string
		for _, c := range res.Charts {
			ids = append(ids, c.ID)
			if len(c.X) == 0 || len(c.Series) == 0 || (c.Style != "line" && c.Style != "bar") || c.Title == "" || c.XLabel == "" || c.YLabel == "" {
				t.Errorf("%s: chart %+v", tc.desc, c)
			}
			nonZero := false
			for _, s := range c.Series {
				if len(s.Values) != len(c.X) {
					t.Errorf("%s: %s series %s has %d values for %d x", tc.desc, c.ID, s.Name, len(s.Values), len(c.X))
				}
				nonZero = nonZero || slices.ContainsFunc(s.Values, func(v float64) bool { return v != 0 })
			}
			if !nonZero {
				t.Errorf("%s: %s holds only zeros", tc.desc, c.ID)
			}
		}
		if !slices.Equal(ids, tc.wantCharts) {
			t.Errorf("%s: charts %v, want %v", tc.desc, ids, tc.wantCharts)
		}
		if tc.check != nil {
			tc.check(t, res)
		}
	}
}
