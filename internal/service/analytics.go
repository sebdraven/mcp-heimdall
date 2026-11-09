package service

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/sebdraven/mcp-heimdall/internal/heimdall"
)

// The analytics windows, in days.
const (
	analyticsShort = 30
	analyticsLong  = 90
)

const (
	analyticsEvents = 50
	topIPs          = 10
	dayLabel        = "day (UTC)"
)

// livenessStates in chart order, with their letter in DomainLiveness.Cells.
var (
	livenessStates = []string{"ok", "nx", "fail", "none"}
	stateLetters   = map[string]byte{"ok": 'O', "nx": 'N', "fail": 'F', "none": '.'}
)

// Chart is a spec for the client to plot: every series has one value per x.
type Chart struct {
	ID     string        `json:"id"`
	Title  string        `json:"title"`
	Style  string        `json:"style"`
	XLabel string        `json:"x_label"`
	YLabel string        `json:"y_label"`
	X      []string      `json:"x"`
	Series []ChartSeries `json:"series"`
}

type ChartSeries struct {
	Name   string    `json:"name"`
	Values []float64 `json:"values"`
}

// DomainLiveness counts the days of a domain in each state; Cells has one
// letter per day: O ok, N nx, F fail, . none.
type DomainLiveness struct {
	FQDN      string  `json:"fqdn"`
	Enabled   bool    `json:"enabled"`
	FirstSeen *string `json:"first_seen"`
	OK        int     `json:"ok"`
	NX        int     `json:"nx"`
	Fail      int     `json:"fail"`
	None      int     `json:"none"`
	LastState string  `json:"last_state"`
	Cells     string  `json:"cells"`
}

type LivenessSummary struct {
	Days    []string         `json:"days"`
	Domains []DomainLiveness `json:"domains"`
}

// CampaignAnalyticsResult leaves out everything but Campaign, Days, Header and
// Charts when only the charts are asked for.
type CampaignAnalyticsResult struct {
	Campaign        heimdall.Campaign        `json:"campaign"`
	Days            int                      `json:"days"`
	Header          heimdall.AnalyticsHeader `json:"header"`
	KPIs            *heimdall.KPIs           `json:"kpis,omitzero"`
	Timeline        *heimdall.Timeline       `json:"timeline,omitzero"`
	LivenessSummary *LivenessSummary         `json:"liveness_summary,omitzero"`
	Clusters        *heimdall.Clusters       `json:"clusters,omitzero"`
	VTLeads         []heimdall.VTLead        `json:"vt_leads,omitzero"`
	Events          []heimdall.Event         `json:"events,omitzero"`
	Charts          []Chart                  `json:"charts"`
}

// CampaignAnalytics reads the analytics of a campaign (id or exact name) over
// days, 30 (the default, given as 0) or 90.
func (s *Service) CampaignAnalytics(ctx context.Context, campaign string, days int, chartsOnly bool) (CampaignAnalyticsResult, error) {
	switch days {
	case 0:
		days = analyticsShort
	case analyticsShort, analyticsLong:
	default:
		return CampaignAnalyticsResult{}, fmt.Errorf("days must be %d or %d, got %d", analyticsShort, analyticsLong, days)
	}
	c, err := s.ResolveCampaign(ctx, campaign)
	if err != nil {
		return CampaignAnalyticsResult{}, err
	}
	a, err := s.client.CampaignAnalytics(ctx, c.ID, days)
	if err != nil {
		return CampaignAnalyticsResult{}, err
	}
	res := CampaignAnalyticsResult{Campaign: c, Days: cmp.Or(a.Days, days), Header: a.Header, Charts: charts(a)}
	if chartsOnly {
		return res, nil
	}
	live := summarizeLiveness(a.Liveness)
	res.KPIs, res.Timeline, res.LivenessSummary, res.Clusters = &a.KPIs, &a.Timeline, &live, &a.Clusters
	res.VTLeads = a.VTLeads
	if res.VTLeads == nil {
		res.VTLeads = []heimdall.VTLead{}
	}
	res.Events = recentEvents(a.Events, analyticsEvents)
	return res, nil
}

// cellState reads an unknown cell as none, as Heimdall counts it.
func cellState(c string) string {
	if _, ok := stateLetters[c]; ok {
		return c
	}
	return "none"
}

func summarizeLiveness(l heimdall.Liveness) LivenessSummary {
	out := LivenessSummary{Days: l.Days, Domains: make([]DomainLiveness, 0, len(l.Rows))}
	if out.Days == nil {
		out.Days = []string{}
	}
	for _, r := range l.Rows {
		d := DomainLiveness{FQDN: r.FQDN, Enabled: r.Enabled, FirstSeen: r.FirstSeen, LastState: "none"}
		cells := make([]byte, len(r.Cells))
		for i, c := range r.Cells {
			c = cellState(c)
			switch c {
			case "ok":
				d.OK++
			case "nx":
				d.NX++
			case "fail":
				d.Fail++
			default:
				d.None++
			}
			cells[i], d.LastState = stateLetters[c], c
		}
		d.Cells = string(cells)
		out.Domains = append(out.Domains, d)
	}
	return out
}

func recentEvents(evs []heimdall.Event, n int) []heimdall.Event {
	ts := func(e heimdall.Event) time.Time {
		t, _ := time.Parse(time.RFC3339Nano, e.TS)
		return t
	}
	out := slices.Clone(evs)
	slices.SortStableFunc(out, func(a, b heimdall.Event) int { return ts(b).Compare(ts(a)) })
	if out == nil {
		out = []heimdall.Event{}
	}
	return out[:min(len(out), n)]
}

// charts dates the KPI series like Heimdall: value i is day i of
// Liveness.Days. A chart left with only zeros is not emitted.
func charts(a heimdall.Analytics) []Chart {
	days, k := a.Liveness.Days, a.KPIs
	cdn := make([]float64, len(k.CDNShare.Series))
	for i, v := range k.CDNShare.Series {
		cdn[i] = math.Round(v*1e4) / 1e2
	}
	all := []Chart{
		{
			ID: "kpi_states", Title: "Domains per state", Style: "line", XLabel: dayLabel, YLabel: "domains", X: days,
			Series: []ChartSeries{
				{Name: "resolving", Values: k.Resolving.Series},
				{Name: "nxdomain", Values: k.NXDomain.Series},
				{Name: "failing", Values: k.Failing.Series},
				{Name: "unmeasured", Values: k.Unmeasured.Series},
			},
		},
		{
			ID: "kpi_infra", Title: "Active IPs and NS sets", Style: "line", XLabel: dayLabel, YLabel: "count", X: days,
			Series: []ChartSeries{
				{Name: "active_ips", Values: k.ActiveIPs.Series},
				{Name: "ns_sets", Values: k.NSSets.Series},
			},
		},
		{
			ID:     "cdn_share",
			Title:  "CDN share of the addresses answered",
			Style:  "line",
			XLabel: dayLabel,
			YLabel: "CDN share (%, Heimdall's fraction × 100)",
			X:      days,
			Series: []ChartSeries{{Name: "cdn_share", Values: cdn}},
		},
		eventsByKind(a.Timeline),
		newIPsPerDay(days, a.Clusters.NewIPsPerDay),
		livenessByDay(a.Liveness),
		topIPClusters(a.Clusters.IPs, topIPs),
	}
	out := []Chart{}
	for _, c := range all {
		if plottable(&c) {
			out = append(out, c)
		}
	}
	return out
}

// plottable drops the series not as long as x and reports whether a value
// other than zero is left.
func plottable(c *Chart) bool {
	c.Series = slices.DeleteFunc(c.Series, func(s ChartSeries) bool { return len(s.Values) != len(c.X) })
	for _, s := range c.Series {
		if slices.ContainsFunc(s.Values, func(v float64) bool { return v != 0 }) {
			return true
		}
	}
	return false
}

func eventsByKind(t heimdall.Timeline) Chart {
	c := Chart{ID: "events_by_kind", Title: "Events per day by kind", Style: "bar", XLabel: dayLabel, YLabel: "events", X: make([]string, len(t.Days))}
	for i, d := range t.Days {
		c.X[i] = d.Day
	}
	for _, kind := range t.Kinds {
		s := ChartSeries{Name: kind, Values: make([]float64, len(t.Days))}
		for i, d := range t.Days {
			s.Values[i] = float64(d.Counts[kind])
		}
		c.Series = append(c.Series, s)
	}
	return c
}

func newIPsPerDay(days []string, rows []heimdall.NewIPs) Chart {
	n := map[string]int{}
	for _, r := range rows {
		n[r.Day] += len(r.IPs)
	}
	s := ChartSeries{Name: "new_ips", Values: make([]float64, len(days))}
	for i, d := range days {
		s.Values[i] = float64(n[d])
	}
	return Chart{ID: "new_ips_per_day", Title: "New IP addresses per day", Style: "bar", XLabel: dayLabel, YLabel: "addresses first seen", X: days, Series: []ChartSeries{s}}
}

func livenessByDay(l heimdall.Liveness) Chart {
	c := Chart{ID: "liveness_by_day", Title: "Domains per state and day", Style: "bar", XLabel: dayLabel, YLabel: "domains", X: l.Days}
	for _, st := range livenessStates {
		c.Series = append(c.Series, ChartSeries{Name: st, Values: make([]float64, len(l.Days))})
	}
	for _, r := range l.Rows {
		for i, cell := range r.Cells[:min(len(r.Cells), len(l.Days))] {
			c.Series[slices.Index(livenessStates, cellState(cell))].Values[i]++
		}
	}
	return c
}

// topIPClusters keeps the n addresses shared by the most domains, then in
// address order.
func topIPClusters(ips []heimdall.IPCluster, n int) Chart {
	top := slices.Clone(ips)
	slices.SortStableFunc(top, func(a, b heimdall.IPCluster) int {
		return cmp.Or(cmp.Compare(len(b.Domains), len(a.Domains)), compareIP(a.IP, b.IP))
	})
	top = top[:min(len(top), n)]
	c := Chart{
		ID:     "top_ip_clusters",
		Title:  "IP addresses shared by the most domains",
		Style:  "bar",
		XLabel: "IP address",
		YLabel: "domains",
		X:      make([]string, len(top)),
		Series: []ChartSeries{{Name: "domains", Values: make([]float64, len(top))}},
	}
	for i, ip := range top {
		c.X[i], c.Series[0].Values[i] = ip.IP, float64(len(ip.Domains))
	}
	return c
}

// compareIP orders addresses numerically, anything else after them as text.
func compareIP(a, b string) int {
	x, errX := netip.ParseAddr(a)
	y, errY := netip.ParseAddr(b)
	switch {
	case errX == nil && errY == nil:
		return x.Compare(y)
	case errX == nil:
		return -1
	case errY == nil:
		return 1
	}
	return cmp.Compare(a, b)
}
