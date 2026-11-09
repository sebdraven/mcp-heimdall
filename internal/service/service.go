// Package service turns the Heimdall API into the operations an analyst runs:
// look a name up, pivot on a value, read the event stream, manage the
// watchlist.
package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
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
	vtRows      = 500
)

// A waited job is polled every pollInterval for at most waitLimit.
const (
	pollInterval = 2 * time.Second
	waitLimit    = 5 * time.Minute
)

// An NS set has minNSSet to maxNSSet nameservers.
const (
	minNSSet = 2
	maxNSSet = 16
)

type Service struct {
	client  *heimdall.Client
	now     func() time.Time
	poll    time.Duration
	maxWait time.Duration
}

func New(c *heimdall.Client) *Service {
	return &Service{client: c, now: time.Now, poll: pollInterval, maxWait: waitLimit}
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
	VT        *heimdall.VTInfo     `json:"vt"`
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

type VTIPResult struct {
	IP         string            `json:"ip"`
	FetchedAt  string            `json:"fetched_at"`
	LookedUpAt *string           `json:"looked_up_at"`
	Status     *string           `json:"status"`
	Returned   int               `json:"returned"`
	Names      []heimdall.VTName `json:"names"`
	Note       string            `json:"note,omitempty"`
}

type VTBudgetResult struct {
	FetchedAt string `json:"fetched_at"`
	Budget    int    `json:"budget"`
	UsedToday int    `json:"used_today"`
	Remaining int    `json:"remaining"`
}

// VTEnrichResult is the job of an enrichment; Summary is nil until it has
// finished.
type VTEnrichResult struct {
	Domain     string              `json:"domain,omitempty"`
	Depth      int                 `json:"depth,omitempty"`
	IP         string              `json:"ip,omitempty"`
	Campaign   *heimdall.Campaign  `json:"campaign,omitempty"`
	FetchedAt  string              `json:"fetched_at"`
	State      string              `json:"state"`
	StartedAt  *string             `json:"started_at"`
	FinishedAt *string             `json:"finished_at"`
	Summary    *heimdall.VTSummary `json:"summary"`
	Error      string              `json:"error,omitempty"`
	Note       string              `json:"note,omitempty"`
}

// VTRequest names what an enrichment covers: exactly one of Domain, Campaign
// and IP. Depth applies to Domain only.
type VTRequest struct {
	Domain   string
	Campaign string
	IP       string
	Depth    int
}

// DomainEnrichResult is the job of a domain enrichment and, once done, the
// stored enrichment.
type DomainEnrichResult struct {
	FQDN       string                     `json:"fqdn"`
	FetchedAt  string                     `json:"fetched_at"`
	State      string                     `json:"state"`
	StartedAt  *string                    `json:"started_at"`
	FinishedAt *string                    `json:"finished_at"`
	Summary    *heimdall.EnrichSummary    `json:"summary"`
	Error      string                     `json:"error,omitempty"`
	Enrichment *heimdall.DomainEnrichment `json:"enrichment"`
	Note       string                     `json:"note,omitempty"`
}

type DomainEnrichmentResult struct {
	FQDN       string                     `json:"fqdn"`
	FetchedAt  string                     `json:"fetched_at"`
	Enrichment *heimdall.DomainEnrichment `json:"enrichment"`
}

type NSSetDomain struct {
	FQDN     string `json:"fqdn"`
	Watched  bool   `json:"watched"`
	Campaign string `json:"campaign"`
}

// NSSetResult lists the names whose current NS set is exactly NS.
type NSSetResult struct {
	NS        []string      `json:"ns"`
	FetchedAt string        `json:"fetched_at"`
	Returned  int           `json:"returned"`
	Domains   []NSSetDomain `json:"domains"`
	Truncated bool          `json:"truncated"`
	Note      string        `json:"note,omitempty"`
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
	return DomainResult{FQDN: fqdn, FetchedAt: s.stamp(), Domain: d.Domain, Current: d.Current, Changes: d.Changes, PDNS: d.PDNS, VT: d.VT}, nil
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

// CreateCampaign reads the campaigns back on a 409 to name the id already
// holding the name.
func (s *Service) CreateCampaign(ctx context.Context, name, family, description string) (heimdall.Campaign, error) {
	if name = strings.TrimSpace(name); name == "" {
		return heimdall.Campaign{}, fmt.Errorf("name is required")
	}
	c, err := s.client.CreateCampaign(ctx, name, family, description)
	if !heimdall.IsStatus(err, http.StatusConflict) {
		return c, err
	}
	cs, err := s.client.Campaigns(ctx)
	if err != nil {
		return heimdall.Campaign{}, fmt.Errorf("campaign %q already exists; reading its id: %w", name, err)
	}
	for _, c := range cs {
		if c.Name == name {
			return heimdall.Campaign{}, fmt.Errorf("campaign %q already exists (id %d)", name, c.ID)
		}
	}
	return heimdall.Campaign{}, fmt.Errorf("campaign %q already exists", name)
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

// vtErr names the cause of the 404 Heimdall answers without VirusTotal.
func vtErr(err error) error {
	if heimdall.IsStatus(err, http.StatusNotFound) {
		return fmt.Errorf("VirusTotal is not configured on this Heimdall: %w", err)
	}
	return err
}

// VTIP reads the names VirusTotal saw on ip from Heimdall's cache.
func (s *Service) VTIP(ctx context.Context, ip string) (VTIPResult, error) {
	if ip = strings.TrimSpace(ip); ip == "" {
		return VTIPResult{}, fmt.Errorf("ip is required")
	}
	v, err := s.client.VTIP(ctx, ip)
	if err != nil {
		return VTIPResult{}, vtErr(err)
	}
	if v.Names == nil {
		v.Names = []heimdall.VTName{}
	}
	res := VTIPResult{IP: v.IP, FetchedAt: s.stamp(), LookedUpAt: v.LookedUpAt, Status: v.Status, Returned: len(v.Names), Names: v.Names}
	if len(v.Names) >= vtRows {
		res.Note = fmt.Sprintf("%d names, Heimdall's cap: more may exist.", len(v.Names))
	}
	return res, nil
}

func (s *Service) VTBudget(ctx context.Context) (VTBudgetResult, error) {
	b, err := s.client.VTBudget(ctx)
	if err != nil {
		return VTBudgetResult{}, vtErr(err)
	}
	return VTBudgetResult{FetchedAt: s.stamp(), Budget: b.Budget, UsedToday: b.UsedToday, Remaining: b.Remaining}, nil
}

// VTEnrich enriches a domain to depth (1 or 2, default 1) or a campaign (id
// or exact name). With wait it polls the job until it ends or maxWait has
// passed; a job still running then is no error.
func (s *Service) VTEnrich(ctx context.Context, domain, campaign string, depth int, wait bool) (VTEnrichResult, error) {
	return s.VTEnrichRequest(ctx, VTRequest{Domain: domain, Campaign: campaign, Depth: depth}, wait)
}

// VTEnrichRequest is VTEnrich for a domain, a campaign or an IP.
func (s *Service) VTEnrichRequest(ctx context.Context, r VTRequest, wait bool) (VTEnrichResult, error) {
	domain, campaign, ip := strings.TrimSpace(r.Domain), strings.TrimSpace(r.Campaign), strings.TrimSpace(r.IP)
	depth := r.Depth
	var res VTEnrichResult
	var t heimdall.VTTarget
	given := 0
	for _, v := range []string{domain, campaign, ip} {
		if v != "" {
			given++
		}
	}
	switch {
	case given != 1:
		return res, fmt.Errorf("give either a domain, a campaign or an ip")
	case domain != "":
		if depth == 0 {
			depth = 1
		}
		if depth != 1 && depth != 2 {
			return res, fmt.Errorf("depth must be 1 or 2")
		}
		t = heimdall.VTTarget{FQDN: domain, Depth: depth}
		res.Domain, res.Depth = domain, depth
	case depth != 0:
		return res, fmt.Errorf("depth applies to a domain only")
	case ip != "":
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return res, fmt.Errorf("ip %q: not an IP address", ip)
		}
		t = heimdall.VTTarget{IP: a.String()}
		res.IP = t.IP
	default:
		c, err := s.ResolveCampaign(ctx, campaign)
		if err != nil {
			return res, err
		}
		t = heimdall.VTTarget{Campaign: c.ID}
		res.Campaign = &c
	}

	job, err := s.client.StartVTEnrich(ctx, t)
	if err != nil {
		return res, vtErr(err)
	}
	if wait {
		var timedOut bool
		job, timedOut, err = await(ctx, s, job, func(j heimdall.VTJob) string { return j.State },
			func(ctx context.Context) (heimdall.VTJob, error) { return s.client.VTEnrichState(ctx, t) })
		if err != nil {
			return res, vtErr(err)
		}
		if timedOut {
			res.Note = fmt.Sprintf("still running after %s; enriching the same target while it runs returns this job without starting another", s.maxWait)
		}
	}
	res.FetchedAt, res.State, res.Error = s.stamp(), job.State, job.Error
	res.StartedAt, res.FinishedAt, res.Summary = job.StartedAt, job.FinishedAt, job.VTSummary
	return res, nil
}

// await polls next while state reports a running job, every s.poll for at
// most s.maxWait; the bool reports a job still running then.
func await[J any](ctx context.Context, s *Service, job J, state func(J) string, next func(context.Context) (J, error)) (J, bool, error) {
	limit := time.NewTimer(s.maxWait)
	defer limit.Stop()
	tick := time.NewTicker(s.poll)
	defer tick.Stop()
	for state(job) == "running" {
		select {
		case <-ctx.Done():
			return job, false, ctx.Err()
		case <-limit.C:
			return job, true, nil
		case <-tick.C:
		}
		n, err := next(ctx)
		if err != nil {
			return job, false, err
		}
		job = n
	}
	return job, false, nil
}

// normalizeFQDN lowercases v and drops its trailing dot; it wants at least two
// labels of letters, digits, '-' and '_'.
func normalizeFQDN(v string) (string, error) {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")
	if n == "" {
		return "", fmt.Errorf("fqdn is required")
	}
	labels := strings.Split(n, ".")
	ok := len(n) <= 253 && len(labels) >= 2
	for _, l := range labels {
		ok = ok && l != "" && len(l) <= 63
		for _, c := range l {
			ok = ok && (c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_')
		}
	}
	if !ok {
		return "", fmt.Errorf("invalid fqdn %q", v)
	}
	return n, nil
}

// enrichment drops the graph of e unless asked for.
func enrichment(e heimdall.DomainEnrichment, includeGraph bool) *heimdall.DomainEnrichment {
	if !includeGraph {
		e.Graph = nil
	}
	return &e
}

func notEnrichedErr(err error) error {
	if errors.Is(err, heimdall.ErrNotEnriched) {
		return fmt.Errorf("not enriched yet, run hd_domain_enrich: %w", err)
	}
	return err
}

// DomainEnrich enriches fqdn. With wait it polls the job like VTEnrich and,
// once done, reads the stored enrichment back; a job still running then
// comes back with a note and no enrichment.
func (s *Service) DomainEnrich(ctx context.Context, fqdn string, wait, includeGraph bool) (DomainEnrichResult, error) {
	fqdn, err := normalizeFQDN(fqdn)
	if err != nil {
		return DomainEnrichResult{}, err
	}
	res := DomainEnrichResult{FQDN: fqdn}
	job, err := s.client.StartDomainEnrich(ctx, fqdn)
	if err != nil {
		return res, err
	}
	if wait {
		var timedOut bool
		job, timedOut, err = await(ctx, s, job, func(j heimdall.EnrichJob) string { return j.State },
			func(ctx context.Context) (heimdall.EnrichJob, error) { return s.client.DomainEnrichState(ctx, fqdn) })
		if err != nil {
			return res, err
		}
		if timedOut {
			res.Note = fmt.Sprintf("still running after %s; enriching the same name while it runs returns this job without starting another, and hd_domain_enrichment reads the result once done", s.maxWait)
		}
	}
	if job.State == "done" {
		e, err := s.client.DomainEnrichment(ctx, fqdn)
		if err != nil {
			return res, notEnrichedErr(err)
		}
		res.Enrichment = enrichment(e, includeGraph)
	}
	res.FetchedAt, res.State, res.Error = s.stamp(), job.State, job.Error
	res.StartedAt, res.FinishedAt, res.Summary = job.StartedAt, job.FinishedAt, job.EnrichSummary
	return res, nil
}

// DomainEnrichment reads the last enrichment of fqdn.
func (s *Service) DomainEnrichment(ctx context.Context, fqdn string, includeGraph bool) (DomainEnrichmentResult, error) {
	fqdn, err := normalizeFQDN(fqdn)
	if err != nil {
		return DomainEnrichmentResult{}, err
	}
	e, err := s.client.DomainEnrichment(ctx, fqdn)
	if err != nil {
		return DomainEnrichmentResult{}, notEnrichedErr(err)
	}
	return DomainEnrichmentResult{FQDN: fqdn, FetchedAt: s.stamp(), Enrichment: enrichment(e, includeGraph)}, nil
}

// LinkDomain puts fqdn in a campaign, given exactly one of campaign (id or
// exact name) and newName, the name of a campaign to create.
func (s *Service) LinkDomain(ctx context.Context, fqdn, campaign, newName, newDescription string) (heimdall.LinkResult, error) {
	fqdn, err := normalizeFQDN(fqdn)
	if err != nil {
		return heimdall.LinkResult{}, err
	}
	campaign, newName, newDescription = strings.TrimSpace(campaign), strings.TrimSpace(newName), strings.TrimSpace(newDescription)
	var req heimdall.LinkRequest
	switch {
	case (campaign == "") == (newName == ""):
		return heimdall.LinkResult{}, fmt.Errorf("give either a campaign or a new campaign name")
	case newName != "":
		req.NewCampaign = &heimdall.LinkNewCampaign{Name: newName, Description: newDescription}
	case newDescription != "":
		return heimdall.LinkResult{}, fmt.Errorf("a description applies to a new campaign only")
	default:
		c, err := s.ResolveCampaign(ctx, campaign)
		if err != nil {
			return heimdall.LinkResult{}, err
		}
		req.Campaign = &c.ID
	}
	res, err := s.client.LinkDomain(ctx, fqdn, req)
	if heimdall.IsStatus(err, http.StatusConflict) {
		return res, fmt.Errorf("campaign %q already exists, link to it with campaign: %w", newName, err)
	}
	return res, err
}

// NSSet lists the names whose current NS set is exactly ns, normalized,
// sorted and unique first.
func (s *Service) NSSet(ctx context.Context, ns []string) (NSSetResult, error) {
	set := make([]string, 0, len(ns))
	for _, n := range ns {
		if strings.TrimSpace(n) == "" {
			continue
		}
		name, err := normalizeFQDN(n)
		if err != nil {
			return NSSetResult{}, fmt.Errorf("nameserver: %w", err)
		}
		set = append(set, name)
	}
	set = slices.Compact(slices.Sorted(slices.Values(set)))
	if len(set) < minNSSet || len(set) > maxNSSet {
		return NSSetResult{}, fmt.Errorf("an NS set has %d to %d distinct nameservers, got %d", minNSSet, maxNSSet, len(set))
	}
	g, err := s.client.NSGraph(ctx, set)
	if err != nil {
		return NSSetResult{}, err
	}
	res := NSSetResult{NS: set, FetchedAt: s.stamp(), Domains: []NSSetDomain{}, Truncated: g.Truncated}
	for _, n := range g.Nodes {
		if n.Kind == "domain" {
			res.Domains = append(res.Domains, NSSetDomain{FQDN: n.Label, Watched: n.Watched, Campaign: n.Campaign})
		}
	}
	res.Returned = len(res.Domains)
	if g.Truncated {
		res.Note = fmt.Sprintf("%d names, Heimdall's graph cap: more may exist.", res.Returned)
	}
	return res, nil
}
