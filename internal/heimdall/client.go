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

type Current struct {
	QType    string   `json:"qtype"`
	Resolver string   `json:"resolver"`
	TS       string   `json:"ts"`
	Rcode    string   `json:"rcode"`
	TTL      uint32   `json:"ttl"`
	Rdata    []string `json:"rdata"`
}

type Change struct {
	TS        string   `json:"ts"`
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
// name is not in the watchlist.
type DomainDetail struct {
	Domain  *Domain     `json:"domain"`
	Current []Current   `json:"current"`
	Changes []Change    `json:"changes"`
	PDNS    []PDNSEntry `json:"pdns"`
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

func (c *Client) CampaignDomains(ctx context.Context, id int64) ([]Domain, error) {
	return call[[]Domain](ctx, c, http.MethodGet, "/api/campaigns/"+strconv.FormatInt(id, 10)+"/domains", nil, nil)
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

func (c *Client) Pivots(ctx context.Context, fqdn string, limit int) ([]Pivot, error) {
	return call[[]Pivot](ctx, c, http.MethodGet, "/api/pivots/"+url.PathEscape(fqdn), limitQuery(limit), nil)
}
