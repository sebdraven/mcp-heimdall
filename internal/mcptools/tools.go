// Package mcptools exposes the service over MCP.
//
// The descriptions carry what a model gets wrong otherwise: that rrname is the
// owner of a record rather than the name queried, that changes and events are
// computed on the tracked set after hysteresis rather than on raw answers, and
// that Heimdall only knows what its own resolvers saw for its own watchlist.
package mcptools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-heimdall/internal/heimdall"
	"github.com/sebdraven/mcp-heimdall/internal/service"
)

const (
	scope = "Heimdall resolves a watchlist of domains (Android RAT and stalkerware campaign infrastructure) continuously against its own recursive resolvers; it knows nothing outside that watchlist and those answers. "

	termRRName = "rrname is the owner name of a record, not the name that was queried: an A query for www.x answered through a CNAME to cdn.y yields (www.x, CNAME, cdn.y) and (cdn.y, A, <ip>), so reaching a watched name's IPs means following its CNAME targets. "

	termRData = "rdata is the value of a record: an IP address, a target name, or the text of an MX, TXT or SOA record. "

	termCOF = "Records follow the CIRCL Passive DNS Common Output Format: time_first and time_last are Unix epoch seconds, count is how many times the record was observed. "

	termTracked = "The tracked set is the set of values Heimdall retains for one (domain, qtype, resolver) after hysteresis: for A, AAAA, NS, MX and TXT a new value enters at once but leaves only after several consecutive answers without it (3 by default), so resolvers rotating through a pool do not produce churn. "

	termKinds = "Event kinds: " +
		"new_rdata: a value entered the tracked set. " +
		"removed_rdata: a value left the tracked set. " +
		"nxdomain: the name went from NOERROR to NXDOMAIN, reported on the A query only. " +
		"resurrection: the name went from NXDOMAIN back to NOERROR, reported on the A query only. " +
		"ns_sinkhole: a new NS value matches a pattern the operator classed as a sinkhole. " +
		"ns_parking: a new NS value matches a pattern the operator classed as parking. " +
		"soa_serial_change: the SOA serial changed. " +
		"ttl_change: with the tracked set unchanged, the TTL rose above twice its learnt ceiling or stayed below a quarter of it for a full window. "

	termWrite = "The role of the API token decides: a viewer token gets the 403 back as is. "
)

type registry struct{ svc *service.Service }

func Register(s *mcp.Server, svc *service.Service) {
	r := &registry{svc: svc}

	mcp.AddTool(s, &mcp.Tool{
		Name: "hd_pdns_query",
		Description: "Passive DNS by owner name: every (rrtype, rdata) Heimdall recorded with this rrname as owner, newest first. " +
			scope + termRRName + termRData + termCOF +
			"Server default and maximum limit: 10000.",
	}, r.pdnsQuery)

	mcp.AddTool(s, &mcp.Tool{
		Name: "hd_pdns_rdata",
		Description: "Passive DNS by value: every owner name Heimdall saw holding this rdata, newest first. " +
			"IPs are matched in canonical form and names case-insensitively without the trailing dot; MX, SOA and TXT values are matched exactly as given. " +
			scope + termRRName + termRData + termCOF +
			"Server default and maximum limit: 10000.",
	}, r.pdnsRdata)

	mcp.AddTool(s, &mcp.Tool{
		Name: "hd_domain",
		Description: "Everything Heimdall shows for one name: its watchlist entry (null if the name is not watched, which is not an error), " +
			"the current state (latest answer per qtype and resolver over the last 7 days: rcode, TTL, rdata), " +
			"the change timeline (each change is a move of the tracked set, rcode or TTL, with the values added and removed) " +
			"and the passive DNS records it owns (first_seen, last_seen in RFC 3339 UTC). " +
			scope + termRRName + termRData + termTracked +
			"changes_limit: default 200, max 1000; passive DNS is capped at 1000 records.",
	}, r.domain)

	mcp.AddTool(s, &mcp.Tool{
		Name: "hd_pivots",
		Description: "Other owner names that shared an A, AAAA or NS rdata with this name, with each side's observation period and their overlap (null when the periods never met). " +
			"Shared hosting makes shared IPs common: an overlap is a lead, not attribution. " +
			"Only values owned by the name itself count, so for a CNAME'd name pivot on its CNAME target; results may include names outside the watchlist. " +
			scope + termRRName + termRData +
			"Server default limit 1000, max 10000.",
	}, r.pivots)

	mcp.AddTool(s, &mcp.Tool{
		Name: "hd_events",
		Description: "The event stream, newest first, optionally filtered by kind and campaign. " +
			"since is RFC 3339 or a duration back from now (90m, 24h, 7d); without it the server returns the last 24 hours. " +
			"detail is a JSON object specific to the kind (values, prev_rdata, matches, serials or TTLs). " +
			scope + termTracked + termKinds +
			"Server default limit 1000, max 10000.",
	}, r.events)

	mcp.AddTool(s, &mcp.Tool{
		Name: "hd_campaigns",
		Description: "List the campaigns: id, name, malware family, description, number of watched domains. " +
			"Campaigns group watchlist entries; the name is what hd_events filters on. " + scope,
	}, r.campaigns)

	mcp.AddTool(s, &mcp.Tool{
		Name: "hd_campaign_domains",
		Description: "List the watched domains of one campaign, given its id or exact name. " +
			"Names are case-sensitive; a value matching no campaign, or both one campaign's id and another's name, is an error naming the candidates. " +
			"interval_seconds is how often each domain is resolved; a disabled domain is no longer measured but keeps its history. " + scope,
	}, r.campaignDomains)

	mcp.AddTool(s, &mcp.Tool{
		Name: "hd_domains",
		Description: "List the whole watchlist, optionally only enabled or only disabled domains. " +
			"interval_seconds is how often each domain is resolved; a disabled domain is no longer measured but keeps its history. " + scope,
	}, r.domains)

	mcp.AddTool(s, &mcp.Tool{
		Name: "hd_add_domains",
		Description: "Add domains to the watchlist under one campaign (id or exact, case-sensitive name), one request per domain. " +
			"Returns which were added, which were already present (left untouched, even if in another campaign) and which failed with their error. " +
			"interval_seconds defaults to 43200 (12 hours), minimum 10. " + termWrite,
	}, r.addDomains)

	mcp.AddTool(s, &mcp.Tool{
		Name: "hd_set_domain",
		Description: "Change one watched domain: enable or disable its measurement, its interval_seconds (minimum 10), or its campaign (id or exact name; an empty string detaches it). " +
			"Fields left out are unchanged. Disabling stops measurement and keeps the history. There is no deletion. " + termWrite,
	}, r.setDomain)
}

type pdnsInput struct {
	RRName string `json:"rrname" jsonschema:"owner name, e.g. www.example.com"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max records (default and max 10000)"`
}

type rdataInput struct {
	Value string `json:"value" jsonschema:"rdata to look for: an IP, a name, or an MX/SOA/TXT value as stored"`
	Limit int    `json:"limit,omitempty" jsonschema:"max records (default and max 10000)"`
}

type domainInput struct {
	FQDN         string `json:"fqdn" jsonschema:"domain name"`
	ChangesLimit int    `json:"changes_limit,omitempty" jsonschema:"max changes in the timeline (default 200, max 1000)"`
}

type pivotsInput struct {
	FQDN  string `json:"fqdn" jsonschema:"domain name"`
	Limit int    `json:"limit,omitempty" jsonschema:"max pivots (default 1000, max 10000)"`
}

type eventsInput struct {
	Since    string `json:"since,omitempty" jsonschema:"RFC 3339 instant or duration back from now: 90m, 24h, 7d (default 24h)"`
	Kind     string `json:"kind,omitempty" jsonschema:"one event kind, e.g. ns_sinkhole"`
	Campaign string `json:"campaign,omitempty" jsonschema:"campaign name, exact"`
	Limit    int    `json:"limit,omitempty" jsonschema:"max events (default 1000, max 10000)"`
}

type campaignsInput struct{}

type campaignDomainsInput struct {
	Campaign string `json:"campaign" jsonschema:"campaign id or exact, case-sensitive name"`
}

type domainsInput struct {
	Enabled *bool `json:"enabled,omitempty" jsonschema:"true for enabled domains only, false for disabled only; omit for all"`
}

type addDomainsInput struct {
	FQDNs           []string `json:"fqdns" jsonschema:"domain names to add"`
	Campaign        string   `json:"campaign" jsonschema:"campaign id or exact, case-sensitive name"`
	IntervalSeconds int      `json:"interval_seconds,omitempty" jsonschema:"measurement interval in seconds (default 43200, min 10)"`
}

type setDomainInput struct {
	FQDN            string  `json:"fqdn" jsonschema:"watched domain name"`
	Enabled         *bool   `json:"enabled,omitempty" jsonschema:"enable or disable measurement"`
	IntervalSeconds *int    `json:"interval_seconds,omitempty" jsonschema:"measurement interval in seconds (min 10)"`
	Campaign        *string `json:"campaign,omitempty" jsonschema:"campaign id or exact name; empty string detaches the domain"`
}

func (r *registry) pdnsQuery(ctx context.Context, _ *mcp.CallToolRequest, in pdnsInput) (*mcp.CallToolResult, service.PDNSResult, error) {
	res, err := r.svc.PDNSQuery(ctx, in.RRName, in.Limit)
	return nil, res, err
}

func (r *registry) pdnsRdata(ctx context.Context, _ *mcp.CallToolRequest, in rdataInput) (*mcp.CallToolResult, service.PDNSResult, error) {
	res, err := r.svc.PDNSRdata(ctx, in.Value, in.Limit)
	return nil, res, err
}

func (r *registry) domain(ctx context.Context, _ *mcp.CallToolRequest, in domainInput) (*mcp.CallToolResult, service.DomainResult, error) {
	res, err := r.svc.Domain(ctx, in.FQDN, in.ChangesLimit)
	return nil, res, err
}

func (r *registry) pivots(ctx context.Context, _ *mcp.CallToolRequest, in pivotsInput) (*mcp.CallToolResult, service.PivotsResult, error) {
	res, err := r.svc.Pivots(ctx, in.FQDN, in.Limit)
	return nil, res, err
}

func (r *registry) events(ctx context.Context, _ *mcp.CallToolRequest, in eventsInput) (*mcp.CallToolResult, service.EventsResult, error) {
	res, err := r.svc.Events(ctx, in.Since, in.Kind, in.Campaign, in.Limit)
	return nil, res, err
}

func (r *registry) campaigns(ctx context.Context, _ *mcp.CallToolRequest, _ campaignsInput) (*mcp.CallToolResult, service.CampaignsResult, error) {
	res, err := r.svc.Campaigns(ctx)
	return nil, res, err
}

func (r *registry) campaignDomains(ctx context.Context, _ *mcp.CallToolRequest, in campaignDomainsInput) (*mcp.CallToolResult, service.DomainsResult, error) {
	res, err := r.svc.CampaignDomains(ctx, in.Campaign)
	return nil, res, err
}

func (r *registry) domains(ctx context.Context, _ *mcp.CallToolRequest, in domainsInput) (*mcp.CallToolResult, service.DomainsResult, error) {
	res, err := r.svc.Domains(ctx, in.Enabled)
	return nil, res, err
}

func (r *registry) addDomains(ctx context.Context, _ *mcp.CallToolRequest, in addDomainsInput) (*mcp.CallToolResult, service.AddDomainsResult, error) {
	res, err := r.svc.AddDomains(ctx, in.FQDNs, in.Campaign, in.IntervalSeconds)
	return nil, res, err
}

func (r *registry) setDomain(ctx context.Context, _ *mcp.CallToolRequest, in setDomainInput) (*mcp.CallToolResult, heimdall.Domain, error) {
	res, err := r.svc.SetDomain(ctx, in.FQDN, in.Enabled, in.IntervalSeconds, in.Campaign)
	return nil, res, err
}
