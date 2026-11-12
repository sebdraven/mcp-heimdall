package service

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sebdraven/mcp-heimdall/internal/heimdall"
)

// CorrelationKinds are Heimdall's kinds of link, strongest first.
var CorrelationKinds = []string{"cert", "ns_set", "ip", "cname", "mx", "soa", "rdap", "vt"}

const (
	topPairs       = 15
	newLinksWindow = 7 * 24 * time.Hour
	newLinksCap    = 500
	notComputed    = "correlation not computed yet (Heimdall computes every hour)"
)

// CorrelationPair is a pair of Heimdall's with the names of its campaigns.
type CorrelationPair struct {
	A         int64          `json:"a"`
	AName     string         `json:"a_name"`
	B         int64          `json:"b"`
	BName     string         `json:"b_name"`
	Score     float64        `json:"score"`
	Counts    map[string]int `json:"counts"`
	FirstSeen *string        `json:"first_seen"`
	LastSeen  *string        `json:"last_seen"`
}

type CorrelationLink struct {
	heimdall.CorrelationLink
	CampaignAName string `json:"campaign_a_name"`
	CampaignBName string `json:"campaign_b_name"`
}

type CorrelationEvidence struct {
	heimdall.CorrelationEvidence
	CampaignAName string `json:"campaign_a_name"`
	CampaignBName string `json:"campaign_b_name"`
}

// CorrelationsResult leaves out Since, Pairs and NewLinks when only the charts
// are asked for.
type CorrelationsResult struct {
	ComputedAt *string                `json:"computed_at"`
	Campaigns  []heimdall.CampaignRef `json:"campaigns"`
	Since      string                 `json:"since,omitempty"`
	Pairs      []CorrelationPair      `json:"pairs,omitzero"`
	NewLinks   []CorrelationLink      `json:"new_links,omitzero"`
	Charts     []Chart                `json:"charts"`
	Note       string                 `json:"note,omitempty"`
}

type CorrelationPairResult struct {
	A          heimdall.CampaignRef  `json:"a"`
	B          heimdall.CampaignRef  `json:"b"`
	Score      float64               `json:"score"`
	Counts     map[string]int        `json:"counts"`
	Evidence   []CorrelationEvidence `json:"evidence"`
	Past       []CorrelationLink     `json:"past"`
	ComputedAt *string               `json:"computed_at"`
	Charts     []Chart               `json:"charts"`
	Note       string                `json:"note,omitempty"`
}

// correlationKinds trims and deduplicates kinds, dropping empty ones, and
// rejects a kind Heimdall does not know.
func correlationKinds(kinds []string) ([]string, error) {
	var out []string
	for _, k := range kinds {
		k = strings.TrimSpace(k)
		switch {
		case k == "" || slices.Contains(out, k):
		case !slices.Contains(CorrelationKinds, k):
			return nil, fmt.Errorf("unknown kind %q (known: %s)", k, strings.Join(CorrelationKinds, ", "))
		default:
			out = append(out, k)
		}
	}
	return out, nil
}

func campaignLabel(name string, id int64) string {
	return cmp.Or(name, "#"+strconv.FormatInt(id, 10))
}

func pairLabel(p CorrelationPair) string {
	return campaignLabel(p.AName, p.A) + " ↔ " + campaignLabel(p.BName, p.B)
}

func nonNilCounts(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	return m
}

func namedLinks(links []heimdall.CorrelationLink, names map[int64]string) []CorrelationLink {
	out := make([]CorrelationLink, 0, len(links))
	for _, l := range links {
		out = append(out, CorrelationLink{CorrelationLink: l, CampaignAName: names[l.CampaignA], CampaignBName: names[l.CampaignB]})
	}
	return out
}

// Correlations reads the pairs of campaigns Heimdall linked, scored at least
// minScore (0 to 1, nil for all) on kinds (all when empty), and the links
// first seen since (RFC 3339 or a duration back from now, 7 days when empty).
func (s *Service) Correlations(ctx context.Context, minScore *float64, kinds []string, since string, chartsOnly bool) (CorrelationsResult, error) {
	if minScore != nil && !(*minScore >= 0 && *minScore <= 1) {
		return CorrelationsResult{}, fmt.Errorf("min_score must be between 0 and 1, got %v", *minScore)
	}
	kinds, err := correlationKinds(kinds)
	if err != nil {
		return CorrelationsResult{}, err
	}
	from, err := ParseSince(since, s.now())
	if err != nil {
		return CorrelationsResult{}, err
	}
	start := s.now().Add(-newLinksWindow)
	if from != "" {
		start, _ = time.Parse(time.RFC3339, from)
	}
	c, err := s.client.Correlations(ctx, heimdall.CorrelationQuery{MinScore: minScore, Kinds: kinds, Since: from})
	if err != nil {
		return CorrelationsResult{}, err
	}

	names := map[int64]string{}
	for _, cp := range c.Campaigns {
		names[cp.ID] = cp.Name
	}
	pairs := make([]CorrelationPair, 0, len(c.Pairs))
	for _, p := range c.Pairs {
		pairs = append(pairs, CorrelationPair{
			A: p.A, AName: names[p.A], B: p.B, BName: names[p.B], Score: p.Score,
			Counts: nonNilCounts(p.Counts), FirstSeen: p.FirstSeen, LastSeen: p.LastSeen,
		})
	}
	slices.SortStableFunc(pairs, func(x, y CorrelationPair) int { return cmp.Compare(y.Score, x.Score) })

	res := CorrelationsResult{ComputedAt: c.ComputedAt, Campaigns: c.Campaigns, Charts: []Chart{}}
	if res.Campaigns == nil {
		res.Campaigns = []heimdall.CampaignRef{}
	}
	top := pairs[:min(len(pairs), topPairs)]
	for _, ch := range []Chart{pairScores(top), linksByKind(top), scoreMatrix(pairs, c.Campaigns), newLinksByDay(c.NewLinks, start, s.now())} {
		if plottable(&ch) {
			res.Charts = append(res.Charts, ch)
		}
	}
	var notes []string
	if c.ComputedAt == nil {
		notes = append(notes, notComputed)
	}
	if len(c.NewLinks) >= newLinksCap {
		notes = append(notes, fmt.Sprintf("%d new links, Heimdall's cap: more may exist; narrow since or kinds.", len(c.NewLinks)))
	}
	res.Note = strings.Join(notes, " ")
	if !chartsOnly {
		res.Since = start.UTC().Format(time.RFC3339)
		res.Pairs, res.NewLinks = pairs, namedLinks(c.NewLinks, names)
	}
	return res, nil
}

// CorrelationPair reads the links between campaigns a and b, each an id or
// exact name, on kinds (all when empty).
func (s *Service) CorrelationPair(ctx context.Context, a, b string, kinds []string) (CorrelationPairResult, error) {
	kinds, err := correlationKinds(kinds)
	if err != nil {
		return CorrelationPairResult{}, err
	}
	ca, err := s.ResolveCampaign(ctx, a)
	if err != nil {
		return CorrelationPairResult{}, fmt.Errorf("a: %w", err)
	}
	cb, err := s.ResolveCampaign(ctx, b)
	if err != nil {
		return CorrelationPairResult{}, fmt.Errorf("b: %w", err)
	}
	if ca.ID == cb.ID {
		return CorrelationPairResult{}, fmt.Errorf("a and b are the same campaign (id %d %q)", ca.ID, ca.Name)
	}
	d, err := s.client.CorrelationPair(ctx, ca.ID, cb.ID, kinds)
	if err != nil {
		return CorrelationPairResult{}, err
	}
	names := map[int64]string{ca.ID: ca.Name, cb.ID: cb.Name}
	res := CorrelationPairResult{
		A: heimdall.CampaignRef{ID: ca.ID, Name: ca.Name}, B: heimdall.CampaignRef{ID: cb.ID, Name: cb.Name},
		Score: d.Score, Counts: nonNilCounts(d.Counts), Evidence: make([]CorrelationEvidence, 0, len(d.Evidence)),
		Past: namedLinks(d.Past, names), ComputedAt: d.ComputedAt, Charts: []Chart{},
	}
	for _, e := range d.Evidence {
		res.Evidence = append(res.Evidence, CorrelationEvidence{CorrelationEvidence: e, CampaignAName: names[e.CampaignA], CampaignBName: names[e.CampaignB]})
	}
	if ch := evidenceByKind(d.Evidence); plottable(&ch) {
		res.Charts = append(res.Charts, ch)
	}
	if d.ComputedAt == nil {
		res.Note = notComputed
	}
	return res, nil
}

// kindsOrder puts the kinds of seen in CorrelationKinds order, any other
// after them by name.
func kindsOrder(seen map[string]bool) []string {
	var out, other []string
	for _, k := range CorrelationKinds {
		if seen[k] {
			out = append(out, k)
		}
	}
	for k := range seen {
		if seen[k] && !slices.Contains(CorrelationKinds, k) {
			other = append(other, k)
		}
	}
	slices.Sort(other)
	return append(out, other...)
}

func pairScores(top []CorrelationPair) Chart {
	c := Chart{
		ID:     "pair_scores",
		Title:  "Score of the most linked pairs of campaigns",
		Style:  "bar",
		XLabel: "pair of campaigns",
		YLabel: "score (0 to 1)",
		X:      make([]string, len(top)),
		Series: []ChartSeries{{Name: "score", Values: make([]float64, len(top))}},
	}
	for i, p := range top {
		c.X[i], c.Series[0].Values[i] = pairLabel(p), p.Score
	}
	return c
}

// linksByKind leaves out the kinds at 0 for every pair.
func linksByKind(top []CorrelationPair) Chart {
	c := Chart{ID: "links_by_kind", Title: "Links of the most linked pairs by kind", Style: "bar", XLabel: "pair of campaigns", YLabel: "distinct values linked", X: make([]string, len(top))}
	seen := map[string]bool{}
	for i, p := range top {
		c.X[i] = pairLabel(p)
		for k, n := range p.Counts {
			seen[k] = seen[k] || n != 0
		}
	}
	for _, k := range kindsOrder(seen) {
		s := ChartSeries{Name: k, Values: make([]float64, len(top))}
		for i, p := range top {
			s.Values[i] = float64(p.Counts[k])
		}
		c.Series = append(c.Series, s)
	}
	return c
}

// scoreMatrix covers the campaigns of at least one pair, in Heimdall's
// order: series i holds the score of campaign i with each x, 0 on the
// diagonal and without a link.
func scoreMatrix(pairs []CorrelationPair, campaigns []heimdall.CampaignRef) Chart {
	names := map[int64]string{}
	for _, p := range pairs {
		names[p.A], names[p.B] = p.AName, p.BName
	}
	var ids []int64
	for _, c := range campaigns {
		if _, ok := names[c.ID]; ok && !slices.Contains(ids, c.ID) {
			ids = append(ids, c.ID)
		}
	}
	var other []int64
	for id := range names {
		if !slices.Contains(ids, id) {
			other = append(other, id)
		}
	}
	slices.Sort(other)
	ids = append(ids, other...)

	c := Chart{ID: "score_matrix", Title: "Score of each pair of campaigns", Style: "bar", XLabel: "campaign", YLabel: "score (0 to 1)", X: make([]string, len(ids))}
	pos := map[int64]int{}
	for i, id := range ids {
		pos[id], c.X[i] = i, campaignLabel(names[id], id)
		c.Series = append(c.Series, ChartSeries{Name: c.X[i], Values: make([]float64, len(ids))})
	}
	for _, p := range pairs {
		if i, j := pos[p.A], pos[p.B]; i != j {
			c.Series[i].Values[j], c.Series[j].Values[i] = p.Score, p.Score
		}
	}
	return c
}

// newLinksByDay counts the links by the UTC day of their first_seen, from the
// day of since to today, one series per kind among links.
func newLinksByDay(links []heimdall.CorrelationLink, since, now time.Time) Chart {
	c := Chart{ID: "new_links_by_day", Title: "New links per day by kind", Style: "bar", XLabel: dayLabel, YLabel: "links first seen"}
	since = since.UTC()
	for d := time.Date(since.Year(), since.Month(), since.Day(), 0, 0, 0, 0, time.UTC); !d.After(now); d = d.AddDate(0, 0, 1) {
		c.X = append(c.X, d.Format(time.DateOnly))
	}
	day := map[string]int{}
	for i, x := range c.X {
		day[x] = i
	}
	counts, seen := map[string][]float64{}, map[string]bool{}
	for _, l := range links {
		t, err := time.Parse(time.RFC3339Nano, l.FirstSeen)
		if err != nil {
			continue
		}
		i, ok := day[t.UTC().Format(time.DateOnly)]
		if !ok {
			continue
		}
		if counts[l.Kind] == nil {
			counts[l.Kind], seen[l.Kind] = make([]float64, len(c.X)), true
		}
		counts[l.Kind][i]++
	}
	for _, k := range kindsOrder(seen) {
		c.Series = append(c.Series, ChartSeries{Name: k, Values: counts[k]})
	}
	return c
}

func evidenceByKind(ev []heimdall.CorrelationEvidence) Chart {
	links, weight, seen := map[string]float64{}, map[string]float64{}, map[string]bool{}
	for _, e := range ev {
		links[e.Kind]++
		weight[e.Kind] = max(weight[e.Kind], e.Weight)
		seen[e.Kind] = true
	}
	kinds := kindsOrder(seen)
	c := Chart{
		ID:     "evidence_by_kind",
		Title:  "Links of the pair by kind",
		Style:  "bar",
		XLabel: "kind of link",
		YLabel: "links, or weight (0 to 1)",
		X:      kinds,
		Series: []ChartSeries{{Name: "links", Values: make([]float64, len(kinds))}, {Name: "max weight", Values: make([]float64, len(kinds))}},
	}
	for i, k := range kinds {
		c.Series[0].Values[i], c.Series[1].Values[i] = links[k], weight[k]
	}
	return c
}
