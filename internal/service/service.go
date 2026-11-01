// Package service turns the Heimdall API into the operations an analyst runs:
// look a name up, pivot on a value, read the event stream, manage the
// watchlist.
package service

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sebdraven/mcp-heimdall/internal/heimdall"
)

// DefaultInterval is the measurement interval of domains added without one.
const DefaultInterval = 43200

// Server-side defaults, used to tell a full page from a complete answer.
const (
	pdnsLimit   = 10000
	eventsLimit = 1000
	pivotsLimit = 1000
)

type Service struct {
	client *heimdall.Client
	now    func() time.Time
}

func New(c *heimdall.Client) *Service {
	return &Service{client: c, now: time.Now}
}

type PDNSResult struct {
	Query     string               `json:"query"`
	FetchedAt string               `json:"fetched_at"`
	Returned  int                  `json:"returned"`
	Records   []heimdall.COFRecord `json:"records"`
	Note      string               `json:"note,omitempty"`
}

type DomainResult struct {
	FQDN      string               `json:"fqdn"`
	FetchedAt string               `json:"fetched_at"`
	Domain    *heimdall.Domain     `json:"domain"`
	Current   []heimdall.Current   `json:"current"`
	Changes   []heimdall.Change    `json:"changes"`
	PDNS      []heimdall.PDNSEntry `json:"pdns"`
}

type PivotsResult struct {
	FQDN        string                 `json:"fqdn"`
	FetchedAt   string                 `json:"fetched_at"`
	Returned    int                    `json:"returned"`
	Pivots      []heimdall.Pivot       `json:"pivots"`
	ExcludedCDN []heimdall.ExcludedCDN `json:"excluded_cdn"`
	NSPairs     *heimdall.NSPairs      `json:"ns_pairs"`
	Note        string                 `json:"note,omitempty"`
}

type EventsResult struct {
	Since     string           `json:"since,omitempty"`
	Kind      string           `json:"kind,omitempty"`
	Campaign  string           `json:"campaign,omitempty"`
	FetchedAt string           `json:"fetched_at"`
	Returned  int              `json:"returned"`
	Events    []heimdall.Event `json:"events"`
	Note      string           `json:"note,omitempty"`
}

type CampaignsResult struct {
	FetchedAt string              `json:"fetched_at"`
	Campaigns []heimdall.Campaign `json:"campaigns"`
}

type DomainsResult struct {
	Campaign  *heimdall.Campaign `json:"campaign,omitempty"`
	FetchedAt string             `json:"fetched_at"`
	Returned  int                `json:"returned"`
	Domains   []heimdall.Domain  `json:"domains"`
}

type DomainError struct {
	FQDN  string `json:"fqdn"`
	Error string `json:"error"`
}

type AddDomainsResult struct {
	Campaign        string            `json:"campaign"`
	IntervalSeconds int               `json:"interval_seconds"`
	Requested       int               `json:"requested"`
	Added           []heimdall.Domain `json:"added"`
	AlreadyPresent  []string          `json:"already_present"`
	Failed          []DomainError     `json:"failed"`
}

func (s *Service) stamp() string { return s.now().UTC().Format(time.RFC3339) }

func fullPage(returned, limit, serverDefault int) string {
	if limit <= 0 {
		limit = serverDefault
	}
	if returned < limit {
		return ""
	}
	return fmt.Sprintf("%d results, the limit: more may exist. Raise limit or narrow the query.", returned)
}

func (s *Service) PDNSQuery(ctx context.Context, rrname string, limit int) (PDNSResult, error) {
	return s.pdns(ctx, rrname, limit, s.client.PDNSQuery)
}

func (s *Service) PDNSRdata(ctx context.Context, value string, limit int) (PDNSResult, error) {
	return s.pdns(ctx, value, limit, s.client.PDNSRdata)
}

func (s *Service) pdns(ctx context.Context, q string, limit int,
	query func(context.Context, string, int) ([]heimdall.COFRecord, error)) (PDNSResult, error) {
	if q = strings.TrimSpace(q); q == "" {
		return PDNSResult{}, fmt.Errorf("a name or value is required")
	}
	recs, err := query(ctx, q, limit)
	if err != nil {
		return PDNSResult{}, err
	}
	return PDNSResult{
		Query:     q,
		FetchedAt: s.stamp(),
		Returned:  len(recs),
		Records:   recs,
		Note:      fullPage(len(recs), limit, pdnsLimit),
	}, nil
}

func (s *Service) Domain(ctx context.Context, fqdn string, changes int) (DomainResult, error) {
	if fqdn = strings.TrimSpace(fqdn); fqdn == "" {
		return DomainResult{}, fmt.Errorf("fqdn is required")
	}
	d, err := s.client.DomainDetail(ctx, fqdn, changes)
	if err != nil {
		return DomainResult{}, err
	}
	return DomainResult{FQDN: fqdn, FetchedAt: s.stamp(), Domain: d.Domain, Current: d.Current, Changes: d.Changes, PDNS: d.PDNS}, nil
}

func (s *Service) Pivots(ctx context.Context, fqdn string, limit int) (PivotsResult, error) {
	if fqdn = strings.TrimSpace(fqdn); fqdn == "" {
		return PivotsResult{}, fmt.Errorf("fqdn is required")
	}
	ps, err := s.client.Pivots(ctx, fqdn, limit)
	if err != nil {
		return PivotsResult{}, err
	}
	return PivotsResult{
		FQDN:        fqdn,
		FetchedAt:   s.stamp(),
		Returned:    len(ps.Pivots),
		Pivots:      ps.Pivots,
		ExcludedCDN: ps.ExcludedCDN,
		NSPairs:     ps.NSPairs,
		Note:        fullPage(len(ps.Pivots), limit, pivotsLimit),
	}, nil
}

// Events reads the event stream. An empty since leaves the server default,
// the last 24 hours.
func (s *Service) Events(ctx context.Context, since, kind, campaign string, limit int) (EventsResult, error) {
	from, err := ParseSince(since, s.now())
	if err != nil {
		return EventsResult{}, err
	}
	q := heimdall.EventQuery{Since: from, Kind: strings.TrimSpace(kind), Campaign: strings.TrimSpace(campaign), Limit: limit}
	evs, err := s.client.Events(ctx, q)
	if err != nil {
		return EventsResult{}, err
	}
	return EventsResult{
		Since:     from,
		Kind:      q.Kind,
		Campaign:  q.Campaign,
		FetchedAt: s.stamp(),
		Returned:  len(evs),
		Events:    evs,
		Note:      fullPage(len(evs), limit, eventsLimit),
	}, nil
}

// ParseSince accepts RFC 3339 or a duration back from now (90m, 24h, 7d) and
// returns the instant in RFC 3339 UTC.
func ParseSince(v string, now time.Time) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	var d time.Duration
	var err error
	if n, ok := strings.CutSuffix(v, "d"); ok {
		var days int
		days, err = strconv.Atoi(n)
		d = time.Duration(days) * 24 * time.Hour
	} else {
		d, err = time.ParseDuration(v)
	}
	if err != nil || d <= 0 {
		return "", fmt.Errorf("since %q: want RFC 3339 or a duration such as 24h or 7d", v)
	}
	return now.Add(-d).UTC().Format(time.RFC3339), nil
}

func (s *Service) Campaigns(ctx context.Context) (CampaignsResult, error) {
	cs, err := s.client.Campaigns(ctx)
	if err != nil {
		return CampaignsResult{}, err
	}
	return CampaignsResult{FetchedAt: s.stamp(), Campaigns: cs}, nil
}

// ResolveCampaign matches ref against campaign ids and exact, case-sensitive
// names. A ref matching both an id and another campaign's name is ambiguous.
func (s *Service) ResolveCampaign(ctx context.Context, ref string) (heimdall.Campaign, error) {
	if ref = strings.TrimSpace(ref); ref == "" {
		return heimdall.Campaign{}, fmt.Errorf("campaign is required")
	}
	cs, err := s.client.Campaigns(ctx)
	if err != nil {
		return heimdall.Campaign{}, err
	}
	var matches []heimdall.Campaign
	for _, c := range cs {
		if c.Name == ref || strconv.FormatInt(c.ID, 10) == ref {
			matches = append(matches, c)
		}
	}
	switch len(matches) {
	case 0:
		return heimdall.Campaign{}, fmt.Errorf("no campaign with id or name %q (names are case-sensitive)", ref)
	case 1:
		return matches[0], nil
	}
	names := make([]string, 0, len(matches))
	for _, c := range matches {
		names = append(names, fmt.Sprintf("id %d %q", c.ID, c.Name))
	}
	return heimdall.Campaign{}, fmt.Errorf("campaign %q is ambiguous: %s", ref, strings.Join(names, ", "))
}

func (s *Service) CampaignDomains(ctx context.Context, ref string) (DomainsResult, error) {
	c, err := s.ResolveCampaign(ctx, ref)
	if err != nil {
		return DomainsResult{}, err
	}
	ds, err := s.client.CampaignDomains(ctx, c.ID)
	if err != nil {
		return DomainsResult{}, err
	}
	return DomainsResult{Campaign: &c, FetchedAt: s.stamp(), Returned: len(ds), Domains: ds}, nil
}

// Domains lists the watchlist, optionally only enabled or disabled entries.
func (s *Service) Domains(ctx context.Context, enabled *bool) (DomainsResult, error) {
	ds, err := s.client.Domains(ctx)
	if err != nil {
		return DomainsResult{}, err
	}
	out := ds[:0]
	for _, d := range ds {
		if enabled == nil || d.Enabled == *enabled {
			out = append(out, d)
		}
	}
	return DomainsResult{FetchedAt: s.stamp(), Returned: len(out), Domains: out}, nil
}

// AddDomains posts one domain at a time. A 409 counts as already present; a
// 401 or 403 stops the run, since every other request would meet it too.
func (s *Service) AddDomains(ctx context.Context, fqdns []string, campaign string, interval int) (AddDomainsResult, error) {
	if interval == 0 {
		interval = DefaultInterval
	}
	if interval < 10 {
		return AddDomainsResult{}, fmt.Errorf("interval_seconds must be at least 10")
	}
	seen := map[string]bool{}
	var clean []string
	for _, f := range fqdns {
		if f = strings.TrimSpace(f); f != "" && !seen[f] {
			seen[f] = true
			clean = append(clean, f)
		}
	}
	if len(clean) == 0 {
		return AddDomainsResult{}, fmt.Errorf("no fqdn given")
	}
	c, err := s.ResolveCampaign(ctx, campaign)
	if err != nil {
		return AddDomainsResult{}, err
	}

	res := AddDomainsResult{
		Campaign:        c.Name,
		IntervalSeconds: interval,
		Requested:       len(clean),
		Added:           []heimdall.Domain{},
		AlreadyPresent:  []string{},
		Failed:          []DomainError{},
	}
	for _, f := range clean {
		d, err := s.client.CreateDomain(ctx, heimdall.NewDomain{FQDN: f, Campaign: c.Name, IntervalSeconds: interval})
		switch {
		case err == nil:
			res.Added = append(res.Added, d)
		case heimdall.IsStatus(err, http.StatusConflict):
			res.AlreadyPresent = append(res.AlreadyPresent, f)
		case heimdall.IsStatus(err, http.StatusUnauthorized), heimdall.IsStatus(err, http.StatusForbidden), ctx.Err() != nil:
			return res, err
		default:
			res.Failed = append(res.Failed, DomainError{FQDN: f, Error: err.Error()})
		}
	}
	return res, nil
}

// SetDomain patches one domain. A non-empty campaign is resolved like
// CampaignDomains; an empty one detaches the domain.
func (s *Service) SetDomain(ctx context.Context, fqdn string, enabled *bool, interval *int, campaign *string) (heimdall.Domain, error) {
	if fqdn = strings.TrimSpace(fqdn); fqdn == "" {
		return heimdall.Domain{}, fmt.Errorf("fqdn is required")
	}
	if enabled == nil && interval == nil && campaign == nil {
		return heimdall.Domain{}, fmt.Errorf("nothing to change: pass enabled, interval_seconds or campaign")
	}
	if interval != nil && *interval < 10 {
		return heimdall.Domain{}, fmt.Errorf("interval_seconds must be at least 10")
	}
	p := heimdall.DomainPatch{Enabled: enabled, IntervalSeconds: interval}
	if campaign != nil {
		name := ""
		if strings.TrimSpace(*campaign) != "" {
			c, err := s.ResolveCampaign(ctx, *campaign)
			if err != nil {
				return heimdall.Domain{}, err
			}
			name = c.Name
		}
		p.Campaign = &name
	}
	return s.client.PatchDomain(ctx, fqdn, p)
}
