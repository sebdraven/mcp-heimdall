// Package heimdall is a client over the Heimdall REST API (cmd/heimdall-api in
// github.com/sebdraven/heimdall).
//
// Dates are kept as the RFC 3339 strings the API sends, and passive DNS
// records in the COF form it streams (epoch seconds), so nothing is reformatted
// on the way through.
package heimdall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const DefaultTimeout = 30 * time.Second

// maxErrBody caps the response body carried by an APIError.
const maxErrBody = 500

type Domain struct {
	FQDN            string `json:"fqdn"`
	Campaign        string `json:"campaign"`
	IntervalSeconds int    `json:"interval_seconds"`
	Enabled         bool   `json:"enabled"`
	Source          string `json:"source"`
	AddedAt         string `json:"added_at"`
}

type Campaign struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Family      string `json:"family"`
	Description string `json:"description"`
	Domains     int    `json:"domains"`
	CreatedAt   string `json:"created_at"`
}

// COFRecord is one line of the Passive DNS Common Output Format.
type COFRecord struct {
	RRName    string `json:"rrname"`
	RRType    string `json:"rrtype"`
	RData     string `json:"rdata"`
	TimeFirst int64  `json:"time_first"`
	TimeLast  int64  `json:"time_last"`
	Count     uint64 `json:"count"`
}

// Current is the latest answer of one qtype and resolver. CDN maps the CDN
// addresses among Rdata to their provider.
type Current struct {
	QType    string            `json:"qtype"`
	Resolver string            `json:"resolver"`
	TS       string            `json:"ts"`
	Rcode    string            `json:"rcode"`
	TTL      uint32            `json:"ttl"`
	Rdata    []string          `json:"rdata"`
	CDN      map[string]string `json:"cdn,omitempty"`
}

// Change is a move of a tracked set. Scope is "name", or "zone" for a change
// of the zone tracked as zone:<fqdn>.
type Change struct {
	TS        string   `json:"ts"`
	Scope     string   `json:"scope"`
	QType     string   `json:"qtype"`
	Resolver  string   `json:"resolver"`
	PrevRcode string   `json:"prev_rcode"`
	NewRcode  string   `json:"new_rcode"`
	Added     []string `json:"added"`
	Removed   []string `json:"removed"`
	PrevTTL   uint32   `json:"prev_ttl"`
	NewTTL    uint32   `json:"new_ttl"`
}

type PDNSEntry struct {
	RRName    string `json:"rrname"`
	RRType    string `json:"rrtype"`
	RData     string `json:"rdata"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Count     uint64 `json:"count"`
}

// DomainDetail is what the /domains/{fqdn} page shows. Domain is nil when the
// name is not in the watchlist, VT when Heimdall has no VirusTotal.
type DomainDetail struct {
	Domain  *Domain     `json:"domain"`
	Current []Current   `json:"current"`
	Changes []Change    `json:"changes"`
	PDNS    []PDNSEntry `json:"pdns"`
	VT      *VTInfo     `json:"vt"`
}

// VTInfo is what Heimdall's cache holds of VirusTotal for a domain.
// LookedUpAt and Status are nil until the domain itself is looked up.
type VTInfo struct {
	LookedUpAt  *string        `json:"looked_up_at"`
	Status      *string        `json:"status"`
	Resolutions []VTResolution `json:"resolutions"`
}

type VTResolution struct {
	IP        string `json:"ip"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// VTIP is what Heimdall's cache holds of VirusTotal for an address.
type VTIP struct {
	IP         string   `json:"ip"`
	LookedUpAt *string  `json:"looked_up_at"`
	Status     *string  `json:"status"`
	Names      []VTName `json:"names"`
}

// VTName is a name VirusTotal saw on an address. Campaign is set when the
// name is watched.
type VTName struct {
	HostName  string `json:"host_name"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Watched   bool   `json:"watched"`
	Campaign  string `json:"campaign"`
}

type VTBudget struct {
	Budget    int `json:"budget"`
	UsedToday int `json:"used_today"`
	Remaining int `json:"remaining"`
}

type VTSummary struct {
	LookedUp        int    `json:"looked_up"`
	Cached          int    `json:"cached"`
	SkippedCDN      int    `json:"skipped_cdn"`
	SkippedReserved int    `json:"skipped_reserved"`
	SkippedBudget   int    `json:"skipped_budget"`
	StoppedReason   string `json:"stopped_reason"`
}

// VTJob is the state of an enrichment: running, done, failed, or none.
// VTSummary is nil until it has finished.
type VTJob struct {
	Job        string  `json:"job"`
	State      string  `json:"state"`
	StartedAt  *string `json:"started_at"`
	FinishedAt *string `json:"finished_at"`
	Error      string  `json:"error"`
	*VTSummary
}

// VTTarget is what an enrichment covers: FQDN to Depth, or else IP, or else
// Campaign.
type VTTarget struct {
	FQDN     string
	Depth    int
	IP       string
	Campaign int64
}

// ErrNotEnriched is the 404 of a name never enriched.
var ErrNotEnriched = errors.New("not enriched yet")

type EnrichCounts struct {
	DNS        int `json:"dns"`
	RDAP       int `json:"rdap"`
	CT         int `json:"ct"`
	Subdomains int `json:"subdomains"`
}

// EnrichSummary ends a domain enrichment; Errors maps a failed source to its
// message.
type EnrichSummary struct {
	Status  string            `json:"status"`
	Counts  EnrichCounts      `json:"counts"`
	Errors  map[string]string `json:"errors,omitempty"`
	Summary string            `json:"summary"`
}

// EnrichJob is the state of a domain enrichment: running, done, failed, or
// none. EnrichSummary is nil until it has finished.
type EnrichJob struct {
	Job        string  `json:"job"`
	State      string  `json:"state"`
	StartedAt  *string `json:"started_at"`
	FinishedAt *string `json:"finished_at"`
	Error      string  `json:"error"`
	*EnrichSummary
}

type DNSRecord struct {
	QType string   `json:"qtype"`
	Rcode string   `json:"rcode"`
	TTL   uint32   `json:"ttl"`
	Rdata []string `json:"rdata"`
}

// LiveDNS is the answer of Resolver to each qtype.
type LiveDNS struct {
	Resolver string      `json:"resolver"`
	Records  []DNSRecord `json:"records"`
}

type Zone struct {
	Name string   `json:"name"`
	SOA  []string `json:"soa"`
	NS   []string `json:"ns"`
}

type Registrar struct {
	Name   string `json:"name"`
	IANAID string `json:"iana_id"`
}

type RDAPEntity struct {
	Roles []string `json:"roles"`
	Name  string   `json:"name"`
}

// RDAP dates are absent when the registry gave none.
type RDAP struct {
	Domain       string       `json:"domain"`
	Registrar    *Registrar   `json:"registrar"`
	Registration string       `json:"registration,omitempty"`
	Expiration   string       `json:"expiration,omitempty"`
	LastChanged  string       `json:"last_changed,omitempty"`
	Status       []string     `json:"status"`
	Nameservers  []string     `json:"nameservers"`
	Entities     []RDAPEntity `json:"entities"`
}

type Certificate struct {
	ID         string   `json:"id"`
	CertSHA256 string   `json:"cert_sha256"`
	Issuer     string   `json:"issuer"`
	NotBefore  string   `json:"not_before"`
	NotAfter   string   `json:"not_after"`
	Revoked    bool     `json:"revoked"`
	Names      []string `json:"names"`
}

// CT holds the Cert Spotter issuances for Zone and below; Names is the union
// of their names.
type CT struct {
	Zone         string        `json:"zone"`
	Total        int           `json:"total"`
	Certificates []Certificate `json:"certificates"`
	Names        []string      `json:"names"`
	Truncated    bool          `json:"truncated"`
}

type Subdomain struct {
	Name      string `json:"name"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

type Subdomains struct {
	Zone      string      `json:"zone"`
	Names     []Subdomain `json:"names"`
	Truncated bool        `json:"truncated"`
}

type GraphNode struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Label    string `json:"label"`
	Watched  bool   `json:"watched"`
	Campaign string `json:"campaign"`
	Href     string `json:"href"`
	Source   string `json:"source"`
}

// GraphEdge has FirstSeen and LastSeen for a VirusTotal edge only.
type GraphEdge struct {
	From      string  `json:"from"`
	To        string  `json:"to"`
	Kind      string  `json:"kind"`
	FirstSeen *string `json:"first_seen,omitempty"`
	LastSeen  *string `json:"last_seen,omitempty"`
}

// Graph is a Heimdall graph; ExcludedCDN counts the CDN addresses left out.
type Graph struct {
	Nodes       []GraphNode `json:"nodes"`
	Edges       []GraphEdge `json:"edges"`
	Truncated   bool        `json:"truncated"`
	ExcludedCDN int         `json:"excluded_cdn"`
}

// DomainEnrichment is the last enrichment of a name. A source that failed is
// nil, its message in Errors.
type DomainEnrichment struct {
	FQDN       string            `json:"fqdn"`
	FetchedAt  string            `json:"fetched_at"`
	Status     string            `json:"status"`
	DNS        *LiveDNS          `json:"dns"`
	Zone       *Zone             `json:"zone"`
	RDAP       *RDAP             `json:"rdap"`
	CT         *CT               `json:"ct"`
	Subdomains *Subdomains       `json:"subdomains"`
	Errors     map[string]string `json:"errors"`
	Graph      *Graph            `json:"graph,omitempty"`
}

// LinkRequest names exactly one of Campaign and NewCampaign.
type LinkRequest struct {
	Campaign    *int64           `json:"campaign,omitempty"`
	NewCampaign *LinkNewCampaign `json:"new_campaign,omitempty"`
}

type LinkNewCampaign struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type CampaignRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// LinkResult tells whether the name was added to the watchlist, moved to the
// campaign or already in it.
type LinkResult struct {
	FQDN            string      `json:"fqdn"`
	Campaign        CampaignRef `json:"campaign"`
	Action          string      `json:"action"`
	CreatedCampaign bool        `json:"created_campaign"`
}

// Event is one entry of the event stream. Detail is decoded with UseNumber, so
// SOA serials and TTLs keep every digit.
type Event struct {
	TS       string `json:"ts"`
	Domain   string `json:"domain"`
	Campaign string `json:"campaign"`
	Kind     string `json:"kind"`
	QType    string `json:"qtype"`
	Resolver string `json:"resolver"`
	Detail   any    `json:"detail"`
}

type Period struct {
	First string `json:"first"`
	Last  string `json:"last"`
}

type Pivot struct {
	Domain  string  `json:"domain"`
	RRType  string  `json:"rrtype"`
	RData   string  `json:"rdata"`
	Target  Period  `json:"target"`
	Other   Period  `json:"other"`
	Overlap *Period `json:"overlap"`
}

type ExcludedCDN struct {
	Value    string `json:"value"`
	Provider string `json:"provider"`
}

// NSMatch is another name whose NS set equals the zone's.
type NSMatch struct {
	Domain  string  `json:"domain"`
	Other   Period  `json:"other"`
	Target  Period  `json:"target"`
	Overlap *Period `json:"overlap"`
}

// NSPairs is the zone of a name, its sorted NS set and the other names holding
// exactly that set.
type NSPairs struct {
	Zone    string    `json:"zone"`
	NS      []string  `json:"ns"`
	Matches []NSMatch `json:"matches"`
}

// PivotsResult is the answer of /api/pivots. ExcludedCDN lists the A and AAAA
// values left out as CDN addresses; NSPairs is nil without a zone of at least
// two nameservers.
type PivotsResult struct {
	Pivots      []Pivot       `json:"pivots"`
	ExcludedCDN []ExcludedCDN `json:"excluded_cdn"`
	NSPairs     *NSPairs      `json:"ns_pairs"`
}

// Analytics is the analytics of a campaign over Days days. KPI series,
// liveness cells and timeline days hold one entry per UTC day of
// Liveness.Days, oldest first, the last one being today.
type Analytics struct {
	Days     int             `json:"days"`
	Header   AnalyticsHeader `json:"header"`
	KPIs     KPIs            `json:"kpis"`
	Timeline Timeline        `json:"timeline"`
	Liveness Liveness        `json:"liveness"`
	Clusters Clusters        `json:"clusters"`
	Events   []Event         `json:"events"`
	VTLeads  []VTLead        `json:"vt_leads"`
}

type AnalyticsCampaign struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Family      string `json:"family"`
	Description string `json:"description"`
}

// AnalyticsHeader has VT nil when Heimdall has no VirusTotal.
type AnalyticsHeader struct {
	Campaign       AnalyticsCampaign `json:"campaign"`
	Domains        int               `json:"domains"`
	Enabled        int               `json:"enabled"`
	LastMeasuredAt *string           `json:"last_measured_at"`
	VT             *VTBudget         `json:"vt"`
}

// KPI holds one value per day; Value is the last one.
type KPI struct {
	Value  float64   `json:"value"`
	Series []float64 `json:"series"`
}

// KPIs has CDNShare as a fraction, from 0 to 1.
type KPIs struct {
	Resolving  KPI `json:"resolving"`
	NXDomain   KPI `json:"nxdomain"`
	Failing    KPI `json:"failing"`
	Unmeasured KPI `json:"unmeasured"`
	ActiveIPs  KPI `json:"active_ips"`
	CDNShare   KPI `json:"cdn_share"`
	NSSets     KPI `json:"ns_sets"`
	Events7d   KPI `json:"events_7d"`
}

type Timeline struct {
	Kinds []string      `json:"kinds"`
	Days  []TimelineDay `json:"days"`
}

type TimelineDay struct {
	Day    string            `json:"day"`
	Counts map[string]uint64 `json:"counts"`
}

// Liveness gives each domain one state per day: ok, nx, fail or none.
type Liveness struct {
	Days []string      `json:"days"`
	Rows []LivenessRow `json:"rows"`
}

type LivenessRow struct {
	FQDN      string   `json:"fqdn"`
	Enabled   bool     `json:"enabled"`
	FirstSeen *string  `json:"first_seen"`
	Cells     []string `json:"cells"`
}

type Clusters struct {
	IPs          []IPCluster `json:"ips"`
	NSSets       []NSCluster `json:"ns_sets"`
	NewIPsPerDay []NewIPs    `json:"new_ips_per_day"`
	ExcludedCDN  int         `json:"excluded_cdn"`
}

// IPCluster is an address answered for several domains; its dates are days.
type IPCluster struct {
	IP        string   `json:"ip"`
	Domains   []string `json:"domains"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
}

type NSCluster struct {
	NS      []string `json:"ns"`
	Zones   []string `json:"zones"`
	Domains []string `json:"domains"`
}

type NewIPs struct {
	Day string   `json:"day"`
	IPs []string `json:"ips"`
}

// VTLead is a name not watched that VirusTotal saw on the campaign's
// addresses.
type VTLead struct {
	HostName string   `json:"host_name"`
	IPs      []string `json:"ips"`
	LastSeen string   `json:"last_seen"`
}

// Correlations holds the pairs of campaigns of Heimdall's last computation,
// ComputedAt nil before the first, and the links first seen since the query's
// since.
type Correlations struct {
	Campaigns  []CampaignRef     `json:"campaigns"`
	Pairs      []CorrelationPair `json:"pairs"`
	NewLinks   []CorrelationLink `json:"new_links"`
	ComputedAt *string           `json:"computed_at"`
}

// CorrelationPair links campaigns A < B; Counts holds the distinct values
// linked per kind.
type CorrelationPair struct {
	A         int64          `json:"a"`
	B         int64          `json:"b"`
	Score     float64        `json:"score"`
	Counts    map[string]int `json:"counts"`
	FirstSeen *string        `json:"first_seen"`
	LastSeen  *string        `json:"last_seen"`
}

// CorrelationLink is a link of Heimdall's history, DomainA < DomainB.
type CorrelationLink struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	DomainA   string `json:"domain_a"`
	CampaignA int64  `json:"campaign_a"`
	DomainB   string `json:"domain_b"`
	CampaignB int64  `json:"campaign_b"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// CorrelationEvidence is a current link. Period is when both domains held
// the value, the validity of a certificate or the two registration dates.
type CorrelationEvidence struct {
	Kind      string  `json:"kind"`
	Value     string  `json:"value"`
	DomainA   string  `json:"domain_a"`
	CampaignA int64   `json:"campaign_a"`
	DomainB   string  `json:"domain_b"`
	CampaignB int64   `json:"campaign_b"`
	Weight    float64 `json:"weight"`
	Period    *Period `json:"period"`
	FirstSeen *string `json:"first_seen"`
	LastSeen  *string `json:"last_seen"`
}

// CorrelationPairDetail holds the current links of a pair and, in Past, the
// links of its history no longer found.
type CorrelationPairDetail struct {
	A          CampaignRef           `json:"a"`
	B          CampaignRef           `json:"b"`
	Score      float64               `json:"score"`
	Counts     map[string]int        `json:"counts"`
	Evidence   []CorrelationEvidence `json:"evidence"`
	Past       []CorrelationLink     `json:"past"`
	ComputedAt *string               `json:"computed_at"`
}

// CorrelationQuery leaves out of the request what is nil or empty.
type CorrelationQuery struct {
	MinScore *float64
	Kinds    []string
	Since    string
}

type NewDomain struct {
	FQDN            string `json:"fqdn"`
	Campaign        string `json:"campaign,omitempty"`
	IntervalSeconds int    `json:"interval_seconds,omitempty"`
}

// DomainPatch leaves nil fields unchanged. An empty Campaign detaches the
// domain from its campaign.
type DomainPatch struct {
	Campaign        *string `json:"campaign,omitempty"`
	IntervalSeconds *int    `json:"interval_seconds,omitempty"`
	Enabled         *bool   `json:"enabled,omitempty"`
}

type newCampaign struct {
	Name        string `json:"name"`
	Family      string `json:"family"`
	Description string `json:"description"`
}

type EventQuery struct {
	Since    string
	Kind     string
	Campaign string
	Limit    int
}

type Client struct {
	token   string
	baseURL string
	http    *http.Client
}

type Option func(*Client)

func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

func New(baseURL, token string, opts ...Option) *Client {
	c := &Client{
		token:   token,
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: DefaultTimeout},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// FromEnv builds a client from HEIMDALL_URL, HEIMDALL_TIMEOUT and Token.
func FromEnv() (*Client, error) {
	base := strings.TrimSpace(os.Getenv("HEIMDALL_URL"))
	if base == "" {
		return nil, errors.New("HEIMDALL_URL is not set, e.g. https://heimdall.example.ts.net")
	}
	if u, err := url.Parse(base); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("HEIMDALL_URL %q: want an http(s) URL", base)
	}
	timeout := DefaultTimeout
	if v := strings.TrimSpace(os.Getenv("HEIMDALL_TIMEOUT")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("HEIMDALL_TIMEOUT %q: want a positive duration such as 30s", v)
		}
		timeout = d
	}
	token, err := Token()
	if err != nil {
		return nil, err
	}
	return New(base, token, WithHTTPClient(&http.Client{Timeout: timeout})), nil
}

// APIError carries the status of a rejected request and the start of its body.
type APIError struct {
	StatusCode int
	Method     string
	Path       string
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("heimdall %s %s: HTTP %d: %s", e.Method, e.Path, e.StatusCode, e.Body)
}

// IsStatus reports whether err is an APIError with the given status.
func IsStatus(err error, status int) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.StatusCode == status
}

func (c *Client) send(ctx context.Context, method, path string, q url.Values, in any) (*http.Response, error) {
	if c.token == "" {
		return nil, fmt.Errorf("heimdall %s %s: no API token", method, path)
	}
	u := c.baseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("heimdall %s %s: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBody))
		resp.Body.Close()
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Method:     method,
			Path:       path,
			Body:       strings.ToValidUTF8(strings.TrimSpace(string(b)), ""),
		}
	}
	return resp, nil
}

func call[T any](ctx context.Context, c *Client, method, path string, q url.Values, in any) (T, error) {
	var out T
	resp, err := c.send(ctx, method, path, q, in)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("heimdall %s %s: decoding: %w", method, path, err)
	}
	return out, nil
}

func limitQuery(limit int) url.Values {
	if limit <= 0 {
		return nil
	}
	return url.Values{"limit": {strconv.Itoa(limit)}}
}

// PDNSQuery returns the records owned by rrname.
func (c *Client) PDNSQuery(ctx context.Context, rrname string, limit int) ([]COFRecord, error) {
	return c.cof(ctx, "/api/pdns/query/"+url.PathEscape(rrname), limit)
}

// PDNSRdata returns the records whose value is rdata.
func (c *Client) PDNSRdata(ctx context.Context, rdata string, limit int) ([]COFRecord, error) {
	return c.cof(ctx, "/api/pdns/rdata/"+url.PathEscape(rdata), limit)
}

func (c *Client) cof(ctx context.Context, path string, limit int) ([]COFRecord, error) {
	resp, err := c.send(ctx, http.MethodGet, path, limitQuery(limit), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	recs, err := DecodeCOF(resp.Body)
	if err != nil {
		return recs, fmt.Errorf("heimdall GET %s: %w", path, err)
	}
	return recs, nil
}

// DecodeCOF reads NDJSON COF records until EOF.
func DecodeCOF(r io.Reader) ([]COFRecord, error) {
	out := []COFRecord{}
	dec := json.NewDecoder(r)
	for {
		var rec COFRecord
		err := dec.Decode(&rec)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, fmt.Errorf("decoding COF record %d: %w", len(out)+1, err)
		}
		out = append(out, rec)
	}
}

func (c *Client) Domains(ctx context.Context) ([]Domain, error) {
	return call[[]Domain](ctx, c, http.MethodGet, "/api/domains", nil, nil)
}

func (c *Client) CreateDomain(ctx context.Context, d NewDomain) (Domain, error) {
	return call[Domain](ctx, c, http.MethodPost, "/api/domains", nil, d)
}

func (c *Client) PatchDomain(ctx context.Context, fqdn string, p DomainPatch) (Domain, error) {
	return call[Domain](ctx, c, http.MethodPatch, "/api/domains/"+url.PathEscape(fqdn), nil, p)
}

// DomainDetail returns the page view of fqdn; changes caps the change list.
func (c *Client) DomainDetail(ctx context.Context, fqdn string, changes int) (DomainDetail, error) {
	return call[DomainDetail](ctx, c, http.MethodGet, "/api/domains/"+url.PathEscape(fqdn)+"/detail", limitQuery(changes), nil)
}

func (c *Client) Campaigns(ctx context.Context) ([]Campaign, error) {
	return call[[]Campaign](ctx, c, http.MethodGet, "/api/campaigns", nil, nil)
}

func (c *Client) CreateCampaign(ctx context.Context, name, family, description string) (Campaign, error) {
	return call[Campaign](ctx, c, http.MethodPost, "/api/campaigns", nil, newCampaign{Name: name, Family: family, Description: description})
}

func (c *Client) CampaignDomains(ctx context.Context, id int64) ([]Domain, error) {
	return call[[]Domain](ctx, c, http.MethodGet, "/api/campaigns/"+strconv.FormatInt(id, 10)+"/domains", nil, nil)
}

// CampaignAnalytics reads the analytics of campaign id over 90 days when days
// is 90, over the server's 30 otherwise.
func (c *Client) CampaignAnalytics(ctx context.Context, id int64, days int) (Analytics, error) {
	var q url.Values
	if days == 90 {
		q = url.Values{"days": {"90"}}
	}
	return call[Analytics](ctx, c, http.MethodGet, "/api/campaigns/"+strconv.FormatInt(id, 10)+"/analytics", q, nil)
}

func (c *Client) Events(ctx context.Context, q EventQuery) ([]Event, error) {
	v := url.Values{}
	for k, s := range map[string]string{"since": q.Since, "kind": q.Kind, "campaign": q.Campaign} {
		if s != "" {
			v.Set(k, s)
		}
	}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	return call[[]Event](ctx, c, http.MethodGet, "/api/events", v, nil)
}

func (c *Client) Pivots(ctx context.Context, fqdn string, limit int) (PivotsResult, error) {
	path := "/api/pivots/" + url.PathEscape(fqdn)
	raw, err := call[json.RawMessage](ctx, c, http.MethodGet, path, limitQuery(limit), nil)
	if err != nil {
		return PivotsResult{}, err
	}
	res, err := DecodePivots(raw)
	if err != nil {
		return res, fmt.Errorf("heimdall GET %s: decoding: %w", path, err)
	}
	return res, nil
}

// DecodePivots accepts the object of current servers and the bare array of
// servers predating excluded_cdn, which leaves NSPairs nil, so either side
// can be deployed first.
func DecodePivots(raw []byte) (PivotsResult, error) {
	var res PivotsResult
	var err error
	if b := bytes.TrimLeft(raw, " \t\r\n"); len(b) > 0 && b[0] == '[' {
		err = json.Unmarshal(b, &res.Pivots)
	} else {
		err = json.Unmarshal(raw, &res)
	}
	if res.Pivots == nil {
		res.Pivots = []Pivot{}
	}
	if res.ExcludedCDN == nil {
		res.ExcludedCDN = []ExcludedCDN{}
	}
	if res.NSPairs != nil && res.NSPairs.Matches == nil {
		res.NSPairs.Matches = []NSMatch{}
	}
	return res, err
}

// VTIP reads the names VirusTotal saw on ip from Heimdall's cache.
func (c *Client) VTIP(ctx context.Context, ip string) (VTIP, error) {
	return call[VTIP](ctx, c, http.MethodGet, "/api/vt/ip/"+url.PathEscape(ip), nil, nil)
}

// VTBudget returns the VirusTotal lookups of the UTC day.
func (c *Client) VTBudget(ctx context.Context) (VTBudget, error) {
	return call[VTBudget](ctx, c, http.MethodGet, "/api/vt/budget", nil, nil)
}

func (t VTTarget) path() string {
	switch {
	case t.FQDN != "":
		return "/api/vt/enrich/domain/" + url.PathEscape(t.FQDN)
	case t.IP != "":
		return "/api/vt/enrich/ip/" + url.PathEscape(t.IP)
	}
	return "/api/vt/enrich/campaign/" + strconv.FormatInt(t.Campaign, 10)
}

// StartVTEnrich starts enriching t, or returns the job already running on it.
func (c *Client) StartVTEnrich(ctx context.Context, t VTTarget) (VTJob, error) {
	var q url.Values
	if t.FQDN != "" && t.Depth > 0 {
		q = url.Values{"depth": {strconv.Itoa(t.Depth)}}
	}
	return call[VTJob](ctx, c, http.MethodPost, t.path(), q, nil)
}

func (c *Client) VTEnrichState(ctx context.Context, t VTTarget) (VTJob, error) {
	return call[VTJob](ctx, c, http.MethodGet, t.path(), nil, nil)
}

// StartDomainEnrich starts enriching fqdn, or returns the job already running
// on it.
func (c *Client) StartDomainEnrich(ctx context.Context, fqdn string) (EnrichJob, error) {
	return call[EnrichJob](ctx, c, http.MethodPost, "/api/enrich/domain/"+url.PathEscape(fqdn), nil, nil)
}

func (c *Client) DomainEnrichState(ctx context.Context, fqdn string) (EnrichJob, error) {
	return call[EnrichJob](ctx, c, http.MethodGet, "/api/enrich/domain/"+url.PathEscape(fqdn), nil, nil)
}

// DomainEnrichment returns the last enrichment of fqdn with its graph, an
// error wrapping ErrNotEnriched before the first one.
func (c *Client) DomainEnrichment(ctx context.Context, fqdn string) (DomainEnrichment, error) {
	e, err := call[DomainEnrichment](ctx, c, http.MethodGet, "/api/domains/"+url.PathEscape(fqdn)+"/enrich", nil, nil)
	if IsStatus(err, http.StatusNotFound) {
		return e, fmt.Errorf("%s: %w: %w", fqdn, ErrNotEnriched, err)
	}
	if err == nil && e.Errors == nil {
		e.Errors = map[string]string{}
	}
	return e, err
}

// LinkDomain adds fqdn to the watchlist in a campaign, or moves it there.
func (c *Client) LinkDomain(ctx context.Context, fqdn string, r LinkRequest) (LinkResult, error) {
	return call[LinkResult](ctx, c, http.MethodPost, "/api/domains/"+url.PathEscape(fqdn)+"/link", nil, r)
}

// NSGraph returns the names whose current NS set is exactly ns.
func (c *Client) NSGraph(ctx context.Context, ns []string) (Graph, error) {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = url.PathEscape(n)
	}
	return call[Graph](ctx, c, http.MethodGet, "/api/graph/ns/"+strings.Join(parts, ","), nil, nil)
}

func kindsQuery(v url.Values, kinds []string) url.Values {
	if len(kinds) > 0 {
		v.Set("kinds", strings.Join(kinds, ","))
	}
	return v
}

// Correlations reads the pairs of campaigns Heimdall linked.
func (c *Client) Correlations(ctx context.Context, q CorrelationQuery) (Correlations, error) {
	v := kindsQuery(url.Values{}, q.Kinds)
	if q.MinScore != nil {
		v.Set("min_score", strconv.FormatFloat(*q.MinScore, 'f', -1, 64))
	}
	if q.Since != "" {
		v.Set("since", q.Since)
	}
	return call[Correlations](ctx, c, http.MethodGet, "/api/correlations", v, nil)
}

// CorrelationPair reads the links between campaigns a and b.
func (c *Client) CorrelationPair(ctx context.Context, a, b int64, kinds []string) (CorrelationPairDetail, error) {
	path := "/api/correlations/" + strconv.FormatInt(a, 10) + "/" + strconv.FormatInt(b, 10)
	return call[CorrelationPairDetail](ctx, c, http.MethodGet, path, kindsQuery(url.Values{}, kinds), nil)
}
