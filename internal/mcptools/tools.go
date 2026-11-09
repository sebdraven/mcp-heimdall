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

	termVT = "VirusTotal data is a history from another source than Heimdall's own measurements, kept in Heimdall's cache: " +
		"looked_up_at and status (ok, empty or error) describe the last lookup and are null when there was none. "

	termVTCache = "Read from Heimdall's cache only: this never calls VirusTotal nor spends its budget. " +
		"An error if Heimdall has no VirusTotal configured. "
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
			"Each change has a scope: name for a change of the name's own records, zone for a change of the parent zone tracked as zone:<fqdn> (its SOA or NS), not of the name. " +
			"A current entry whose rdata holds CDN addresses has cdn, mapping each such IP to its provider: unrelated names share these IPs, so they are no infrastructure link. " +
			"vt holds the past resolutions VirusTotal saw for the name (ip, first_seen, last_seen), a history from another source than Heimdall's measurements, " +
			"read from Heimdall's cache: this tool never calls VirusTotal. vt is null when Heimdall has no VirusTotal configured; " +
			"its looked_up_at and status are null when the domain has not been enriched yet (hd_vt_enrich), though resolutions cached by lookups of its addresses may already show. " +
			scope + termRRName + termRData + termTracked +
			"changes_limit: default 200, max 1000; passive DNS is capped at 1000 records, VirusTotal resolutions at 500.",
	}, r.domain)

	mcp.AddTool(s, &mcp.Tool{
		Name: "hd_pivots",
		Description: "Other owner names linked to this name, two ways, each with both sides' observation periods and their overlap (null when the periods never met). " +
			"pivots: names that shared one of its A or AAAA values. Shared hosting makes shared IPs common: an overlap is a lead, not attribution. " +
			"A and AAAA values that are CDN addresses (from the operator's list of CDN prefixes) are not pivoted on and are listed in excluded_cdn with their provider. " +
			"Only values owned by the name itself count, so for a CNAME'd name pivot on its CNAME target. " +
			"ns_pairs: the zone of the name (the name itself or its nearest ancestor owning NS records seen in the last 7 days), its sorted NS set, and in matches the other names whose current NS set is strictly identical. " +
			"An identical set is a strong sign of one operator: providers such as Cloudflare give each account its own nameserver pair, so the same pair means the same account; CDN prefixes do not apply here. " +
			"ns_pairs is null when no zone is found or its set has fewer than 2 nameservers. " +
			"Results may include names outside the watchlist. An older Heimdall returns excluded_cdn empty and ns_pairs null. " +
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
		Name: "hd_create_campaign",
		Description: "Create a campaign (name, optional malware family and description) to group watchlist entries; " +
			"names are exact and case-sensitive, and hd_add_domains takes the name or the returned id. " + termWrite,
	}, r.createCampaign)

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

	mcp.AddTool(s, &mcp.Tool{
		Name: "hd_vt_ip",
		Description: "The names VirusTotal saw resolving to an IP (host_name, first_seen, last_seen), each with watched and, when watched, its campaign: " +
			"the names not watched are candidates for hd_add_domains. " +
			termVTCache + termVT + "Capped at 500 names.",
	}, r.vtIP)

	mcp.AddTool(s, &mcp.Tool{
		Name: "hd_vt_enrich",
		Description: "Look up with VirusTotal the domains and IPs of the graph of a domain (depth 1 or 2, default 1) or of a campaign (id or exact, case-sensitive name), " +
			"or a single IP address (the names VirusTotal saw on it), storing what it saw in Heimdall's cache for hd_domain and hd_vt_ip. " +
			"Give exactly one of domain, campaign and ip; depth applies to a domain only. " +
			"This costs VirusTotal lookups from a daily budget shared by every Heimdall user: prefer hd_vt_budget before enriching a whole campaign. " +
			"Objects fetched recently count as cached, private and CDN addresses are skipped, and the run stops when the budget is spent. " +
			"With wait (default true) the job is polled every 2 s until done or failed, for at most 5 minutes, and its summary returned " +
			"(looked_up, cached, skipped_budget, skipped_cdn, skipped_reserved, stopped_reason); a job still running then comes back with state running, summary null and a note. " +
			"Without wait the started job comes back at once. Enriching a target whose enrichment is running returns that job rather than starting another. " +
			"An error if Heimdall has no VirusTotal configured. " + termWrite,
	}, r.vtEnrich)

	mcp.AddTool(s, &mcp.Tool{
		Name: "hd_vt_budget",
		Description: "The VirusTotal lookups of the current UTC day: budget, used_today, remaining. " +
			"The budget is shared by every Heimdall user; hd_vt_enrich spends it, no other tool does. " +
			"An error if Heimdall has no VirusTotal configured.",
	}, r.vtBudget)

	mcp.AddTool(s, &mcp.Tool{
		Name: "hd_domain_enrich",
		Description: "Enrich one name on demand, watched or not, from four sources queried by the Heimdall server, not by this client: " +
			"dns: its live records (one answer per qtype: rcode, TTL, rdata) from Heimdall's first active resolver, with zone, the zone found (name, SOA, NS); " +
			"rdap: its registration through the IANA RDAP bootstrap (registrar, registration, expiration and last_changed dates, statuses, nameservers, entities); " +
			"ct: the certificates Cert Spotter lists for the zone and below (issuer, validity, revoked, names, cert_sha256 as a full SHA-256), capped at 500; " +
			"subdomains: the names below the zone in Heimdall's own passive DNS (first_seen, last_seen), capped at 500. " +
			"Each source can fail alone: it is then null and its message is in errors, and status is ok, partial (some failed) or error (all failed). " +
			"Cert Spotter without an API key on the Heimdall side is rate-limited, so ct is the source most likely to fail. " +
			"The result is stored by Heimdall and replaces the previous one; hd_domain_enrichment reads it back without querying anything. " +
			"With wait (default true) the job is polled every 2 s until done or failed, for at most 5 minutes, then the stored enrichment is returned with the job " +
			"(summary: status, counts per source, errors, a one-line summary); a job still running then comes back with state running, enrichment null and a note, " +
			"a failed job (Heimdall could not store the result) with its error and enrichment null. " +
			"Without wait the started job comes back at once, enrichment null. Enriching a name whose enrichment is running returns that job rather than starting another. " +
			"The graph Heimdall draws from the enrichment (addresses, CNAME and MX targets, NS set, subdomains, certificate names) is left out unless include_graph is true. " +
			termWrite,
	}, r.domainEnrich)

	mcp.AddTool(s, &mcp.Tool{
		Name: "hd_domain_enrichment",
		Description: "The last enrichment Heimdall stored for a name (dns, zone, rdap, ct, subdomains, errors, status, fetched_at being when it ran), read only: nothing is queried. " +
			"An error naming hd_domain_enrich when the name was never enriched. " +
			"Certificates carry cert_sha256 as a full SHA-256. The graph is left out unless include_graph is true.",
	}, r.domainEnrichment)

	mcp.AddTool(s, &mcp.Tool{
		Name: "hd_link_domain",
		Description: "Put a name in a campaign: give either campaign (id or exact, case-sensitive name) or new_campaign_name, a campaign created first (with new_campaign_description). " +
			"A name not watched is added to the watchlist with the default interval, its measurements starting at the collector's next cycle; a watched name is moved to the campaign. " +
			"Returns action (added, moved or unchanged), the campaign (id, name) and created_campaign. " +
			"A new_campaign_name already taken is an error: link with campaign instead. " + termWrite,
	}, r.linkDomain)

	mcp.AddTool(s, &mcp.Tool{
		Name: "hd_ns_set",
		Description: "The names whose current NS set (NS records seen in the last 7 days) is strictly identical to the given one, each with watched and its campaign. " +
			"Give 2 to 16 nameservers; they are lowercased, stripped of the trailing dot, sorted and deduplicated first. " +
			"An identical set is a strong sign of one operator: providers such as Cloudflare give each account its own nameserver pair, so the same pair means the same account. " +
			"hd_pivots gives the NS set of a name in ns_pairs. Results may include names outside the watchlist. " + scope,
	}, r.nsSet)
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

type createCampaignInput struct {
	Name        string `json:"name" jsonschema:"campaign name, exact and case-sensitive"`
	Family      string `json:"family,omitempty" jsonschema:"malware family, e.g. SpyNote"`
	Description string `json:"description,omitempty" jsonschema:"free text"`
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

type vtIPInput struct {
	IP string `json:"ip" jsonschema:"IPv4 or IPv6 address"`
}

type vtEnrichInput struct {
	Domain   string `json:"domain,omitempty" jsonschema:"domain name to enrich; give exactly one of domain, campaign and ip"`
	Campaign string `json:"campaign,omitempty" jsonschema:"campaign id or exact, case-sensitive name; give exactly one of domain, campaign and ip"`
	IP       string `json:"ip,omitempty" jsonschema:"IPv4 or IPv6 address to enrich; give exactly one of domain, campaign and ip"`
	Depth    int    `json:"depth,omitempty" jsonschema:"graph depth around the domain: 1 (default) or 2; domain only"`
	Wait     *bool  `json:"wait,omitempty" jsonschema:"poll the job until it ends, at most 5 minutes (default true)"`
}

type vtBudgetInput struct{}

type domainEnrichInput struct {
	FQDN         string `json:"fqdn" jsonschema:"domain name, watched or not"`
	Wait         *bool  `json:"wait,omitempty" jsonschema:"poll the job until it ends, at most 5 minutes, and return the enrichment (default true)"`
	IncludeGraph bool   `json:"include_graph,omitempty" jsonschema:"also return the graph drawn from the enrichment (default false)"`
}

type domainEnrichmentInput struct {
	FQDN         string `json:"fqdn" jsonschema:"domain name"`
	IncludeGraph bool   `json:"include_graph,omitempty" jsonschema:"also return the graph drawn from the enrichment (default false)"`
}

type linkDomainInput struct {
	FQDN                   string `json:"fqdn" jsonschema:"domain name, watched or not"`
	Campaign               string `json:"campaign,omitempty" jsonschema:"campaign id or exact, case-sensitive name; give this or new_campaign_name"`
	NewCampaignName        string `json:"new_campaign_name,omitempty" jsonschema:"name of a campaign to create; give this or campaign"`
	NewCampaignDescription string `json:"new_campaign_description,omitempty" jsonschema:"free text, with new_campaign_name only"`
}

type nsSetInput struct {
	NS []string `json:"ns" jsonschema:"2 to 16 nameserver names, e.g. ana.ns.cloudflare.com and bob.ns.cloudflare.com"`
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

func (r *registry) createCampaign(ctx context.Context, _ *mcp.CallToolRequest, in createCampaignInput) (*mcp.CallToolResult, heimdall.Campaign, error) {
	res, err := r.svc.CreateCampaign(ctx, in.Name, in.Family, in.Description)
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

func (r *registry) vtIP(ctx context.Context, _ *mcp.CallToolRequest, in vtIPInput) (*mcp.CallToolResult, service.VTIPResult, error) {
	res, err := r.svc.VTIP(ctx, in.IP)
	return nil, res, err
}

func (r *registry) vtEnrich(ctx context.Context, _ *mcp.CallToolRequest, in vtEnrichInput) (*mcp.CallToolResult, service.VTEnrichResult, error) {
	res, err := r.svc.VTEnrichRequest(ctx, service.VTRequest{Domain: in.Domain, Campaign: in.Campaign, IP: in.IP, Depth: in.Depth}, in.Wait == nil || *in.Wait)
	return nil, res, err
}

func (r *registry) vtBudget(ctx context.Context, _ *mcp.CallToolRequest, _ vtBudgetInput) (*mcp.CallToolResult, service.VTBudgetResult, error) {
	res, err := r.svc.VTBudget(ctx)
	return nil, res, err
}

func (r *registry) domainEnrich(ctx context.Context, _ *mcp.CallToolRequest, in domainEnrichInput) (*mcp.CallToolResult, service.DomainEnrichResult, error) {
	res, err := r.svc.DomainEnrich(ctx, in.FQDN, in.Wait == nil || *in.Wait, in.IncludeGraph)
	return nil, res, err
}

func (r *registry) domainEnrichment(ctx context.Context, _ *mcp.CallToolRequest, in domainEnrichmentInput) (*mcp.CallToolResult, service.DomainEnrichmentResult, error) {
	res, err := r.svc.DomainEnrichment(ctx, in.FQDN, in.IncludeGraph)
	return nil, res, err
}

func (r *registry) linkDomain(ctx context.Context, _ *mcp.CallToolRequest, in linkDomainInput) (*mcp.CallToolResult, heimdall.LinkResult, error) {
	res, err := r.svc.LinkDomain(ctx, in.FQDN, in.Campaign, in.NewCampaignName, in.NewCampaignDescription)
	return nil, res, err
}

func (r *registry) nsSet(ctx context.Context, _ *mcp.CallToolRequest, in nsSetInput) (*mcp.CallToolResult, service.NSSetResult, error) {
	res, err := r.svc.NSSet(ctx, in.NS)
	return nil, res, err
}
