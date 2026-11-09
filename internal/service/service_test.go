package service

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sebdraven/mcp-heimdall/internal/heimdall"
)

const campaignsJSON = `[
  {"id":1,"name":"spynote","family":"SpyNote","description":"","domains":2,"created_at":"2026-03-01T12:00:00Z"},
  {"id":2,"name":"SpyNote","family":"SpyNote","description":"","domains":0,"created_at":"2026-03-01T12:00:00Z"},
  {"id":3,"name":"1","family":"","description":"","domains":1,"created_at":"2026-03-01T12:00:00Z"}
]`

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// stub serves /api/campaigns and whatever extra handles; requests records the
// paths it was asked for.
func stub(t *testing.T, extra http.HandlerFunc) (*Service, *[]string) {
	t.Helper()
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodGet && r.URL.Path == "/api/campaigns" {
			w.Write([]byte(campaignsJSON))
			return
		}
		if extra == nil {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		extra(w, r)
	}))
	t.Cleanup(srv.Close)
	s := New(heimdall.New(srv.URL, "TOK"))
	s.now = func() time.Time { return t0 }
	return s, &requests
}

func TestResolveCampaign(t *testing.T) {
	s, _ := stub(t, nil)
	for ref, want := range map[string]int64{"spynote": 1, "SpyNote": 2, "3": 3, " spynote ": 1} {
		c, err := s.ResolveCampaign(context.Background(), ref)
		if err != nil || c.ID != want {
			t.Errorf("%q: id %d, err %v; want id %d", ref, c.ID, err, want)
		}
	}
	for ref, msg := range map[string]string{
		"Spynote": "no campaign",
		"missing": "no campaign",
		"":        "required",
		"1":       "ambiguous",
	} {
		if _, err := s.ResolveCampaign(context.Background(), ref); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%q: err %v, want one mentioning %q", ref, err, msg)
		}
	}
}

func TestCampaignDomainsUsesResolvedID(t *testing.T) {
	s, reqs := stub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"fqdn":"a.example","campaign":"SpyNote","interval_seconds":300,"enabled":true,"source":"web:alice","added_at":"2026-03-01T12:00:00Z"}]`))
	})
	res, err := s.CampaignDomains(context.Background(), "SpyNote")
	if err != nil {
		t.Fatalf("CampaignDomains: %v", err)
	}
	if got := strings.Join(*reqs, ", "); got != "GET /api/campaigns, GET /api/campaigns/2/domains" {
		t.Errorf("requests = %s", got)
	}
	if res.Campaign == nil || res.Campaign.ID != 2 || res.Returned != 1 {
		t.Errorf("result = %+v", res)
	}
}

func TestEventsRelativeSince(t *testing.T) {
	var gotSince string
	s, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {
		gotSince = r.URL.Query().Get("since")
		w.Write([]byte(`[]`))
	})
	for since, want := range map[string]string{
		"7d":                        "2026-02-22T12:00:00Z",
		"24h":                       "2026-02-28T12:00:00Z",
		"90m":                       "2026-03-01T10:30:00Z",
		"2026-02-01T09:00:00+01:00": "2026-02-01T08:00:00Z",
		"":                          "",
	} {
		gotSince = "unset"
		res, err := s.Events(context.Background(), since, "", "", 0)
		if err != nil {
			t.Errorf("%q: %v", since, err)
			continue
		}
		if gotSince != want || res.Since != want {
			t.Errorf("%q: sent since=%q, reported %q, want %q", since, gotSince, res.Since, want)
		}
	}
}

func TestEventsRejectsBadSince(t *testing.T) {
	s, reqs := stub(t, nil)
	for _, bad := range []string{"7x", "-24h", "0d", "yesterday"} {
		if _, err := s.Events(context.Background(), bad, "", "", 0); err == nil {
			t.Errorf("since %q was accepted", bad)
		}
	}
	if len(*reqs) != 0 {
		t.Errorf("requests sent for invalid input: %v", *reqs)
	}
}

func TestAddDomainsOutcomes(t *testing.T) {
	var bodies []heimdall.NewDomain
	s, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {
		var d heimdall.NewDomain
		json.NewDecoder(r.Body).Decode(&d)
		bodies = append(bodies, d)
		switch d.FQDN {
		case "dup.example":
			http.Error(w, `{"error":"already exists"}`, http.StatusConflict)
		case "bad..example":
			http.Error(w, `{"error":"invalid FQDN"}`, http.StatusBadRequest)
		default:
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"fqdn": d.FQDN, "campaign": d.Campaign, "interval_seconds": d.IntervalSeconds, "enabled": true})
		}
	})
	res, err := s.AddDomains(context.Background(), []string{"new.example", "dup.example", "bad..example", "new.example", " "}, "spynote", 0)
	if err != nil {
		t.Fatalf("AddDomains: %v", err)
	}
	if len(bodies) != 3 {
		t.Errorf("%d POSTs, want one per distinct domain", len(bodies))
	}
	for _, b := range bodies {
		if b.Campaign != "spynote" || b.IntervalSeconds != DefaultInterval {
			t.Errorf("body = %+v", b)
		}
	}
	if len(res.Added) != 1 || res.Added[0].FQDN != "new.example" {
		t.Errorf("added = %+v", res.Added)
	}
	if len(res.AlreadyPresent) != 1 || res.AlreadyPresent[0] != "dup.example" {
		t.Errorf("already present = %v", res.AlreadyPresent)
	}
	if len(res.Failed) != 1 || res.Failed[0].FQDN != "bad..example" || !strings.Contains(res.Failed[0].Error, "HTTP 400") {
		t.Errorf("failed = %+v", res.Failed)
	}
}

func TestForbiddenStopsWrites(t *testing.T) {
	s, reqs := stub(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
	})
	_, err := s.AddDomains(context.Background(), []string{"a.example", "b.example"}, "spynote", 0)
	if !heimdall.IsStatus(err, http.StatusForbidden) || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("err = %v, want the 403 with its body", err)
	}
	if got := strings.Join(*reqs, ", "); got != "GET /api/campaigns, POST /api/domains" {
		t.Errorf("requests = %s, want a stop at the first 403", got)
	}

	enabled := false
	if _, err := s.SetDomain(context.Background(), "a.example", &enabled, nil, nil); !heimdall.IsStatus(err, http.StatusForbidden) {
		t.Errorf("SetDomain err = %v, want the 403", err)
	}
}

func TestCreateCampaign(t *testing.T) {
	for _, tc := range []struct {
		desc, name string
		status     int
		reply      string
		wantErr    string
		wantStatus int
		wantReqs   string
	}{
		{
			desc:     "created",
			name:     " spynote-2026 ",
			status:   http.StatusCreated,
			reply:    `{"id":4,"name":"spynote-2026","family":"SpyNote","description":"","domains":0,"created_at":"2026-03-01T12:00:00Z"}`,
			wantReqs: "POST /api/campaigns",
		},
		{
			desc:     "conflict",
			name:     "SpyNote",
			status:   http.StatusConflict,
			reply:    `{"error":"already exists"}`,
			wantErr:  `campaign "SpyNote" already exists (id 2)`,
			wantReqs: "POST /api/campaigns, GET /api/campaigns",
		},
		{
			desc:       "forbidden",
			name:       "spynote-2026",
			status:     http.StatusForbidden,
			reply:      `{"error":"forbidden"}`,
			wantErr:    "forbidden",
			wantStatus: http.StatusForbidden,
			wantReqs:   "POST /api/campaigns",
		},
		{desc: "empty", name: "", wantErr: "name is required"},
		{desc: "blank", name: " \t ", wantErr: "name is required"},
	} {
		var sent heimdall.Campaign
		s, reqs := stub(t, func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&sent)
			w.WriteHeader(tc.status)
			w.Write([]byte(tc.reply))
		})
		c, err := s.CreateCampaign(context.Background(), tc.name, "SpyNote", "")
		if got := strings.Join(*reqs, ", "); got != tc.wantReqs {
			t.Errorf("%s: requests = %q, want %q", tc.desc, got, tc.wantReqs)
		}
		if tc.wantErr == "" {
			if err != nil || c.ID != 4 || c.Name != "spynote-2026" {
				t.Errorf("%s: %+v, %v", tc.desc, c, err)
			}
			if sent.Name != "spynote-2026" || sent.Family != "SpyNote" {
				t.Errorf("%s: sent %+v, want the trimmed name", tc.desc, sent)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: err %v, want one mentioning %q", tc.desc, err, tc.wantErr)
		}
		if tc.wantStatus != 0 && !heimdall.IsStatus(err, tc.wantStatus) {
			t.Errorf("%s: err %v, want the HTTP %d as is", tc.desc, err, tc.wantStatus)
		}
	}
}

func TestPivotsExcludedCDN(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{
			body: `[]`,
			want: `"returned":0,"pivots":[],"excluded_cdn":[],"ns_pairs":null`,
		},
		{
			body: `{"pivots":[],"excluded_cdn":[{"value":"104.16.0.1","provider":"Cloudflare"}]}`,
			want: `"returned":0,"pivots":[],"excluded_cdn":[{"value":"104.16.0.1","provider":"Cloudflare"}],"ns_pairs":null`,
		},
		{
			body: `{"pivots":[],"excluded_cdn":[],"ns_pairs":null}`,
			want: `"excluded_cdn":[],"ns_pairs":null`,
		},
		{
			body: `{"pivots":[],"excluded_cdn":[],"ns_pairs":{"zone":"a.example","ns":["ana.ns.cloudflare.com","bob.ns.cloudflare.com"],"matches":[{"domain":"same.example","other":{"first":"2026-03-01T13:00:00Z","last":"2026-03-01T15:00:00Z"},"target":{"first":"2026-03-01T12:00:00Z","last":"2026-03-01T14:00:00Z"},"overlap":null}]}}`,
			want: `"ns_pairs":{"zone":"a.example","ns":["ana.ns.cloudflare.com","bob.ns.cloudflare.com"],"matches":[{"domain":"same.example","other":{"first":"2026-03-01T13:00:00Z","last":"2026-03-01T15:00:00Z"},"target":{"first":"2026-03-01T12:00:00Z","last":"2026-03-01T14:00:00Z"},"overlap":null}]}`,
		},
	} {
		s, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(tc.body))
		})
		res, err := s.Pivots(context.Background(), "www.x.example", 0)
		if err != nil {
			t.Errorf("%s: %v", tc.body, err)
			continue
		}
		b, _ := json.Marshal(res)
		if !strings.Contains(string(b), tc.want) {
			t.Errorf("%s: result %s lacks %s", tc.body, b, tc.want)
		}
	}
}

func TestDomainsFilter(t *testing.T) {
	s, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"fqdn":"a.example","enabled":true},{"fqdn":"b.example","enabled":false}]`))
	})
	off := false
	res, err := s.Domains(context.Background(), &off)
	if err != nil {
		t.Fatalf("Domains: %v", err)
	}
	if res.Returned != 1 || res.Domains[0].FQDN != "b.example" {
		t.Errorf("result = %+v", res)
	}
}

const (
	enrichA    = "/api/vt/enrich/domain/a.example"
	jobRunning = `{"job":"domain:a.example","state":"running","started_at":"2026-03-01T12:00:00Z"}`
	jobDone    = `{"job":"domain:a.example","state":"done","started_at":"2026-03-01T12:00:00Z","finished_at":"2026-03-01T12:00:05Z","looked_up":3,"cached":1,"skipped_cdn":1,"skipped_reserved":0,"skipped_budget":0,"stopped_reason":""}`
	jobFailed  = `{"job":"campaign:2","state":"failed","started_at":"2026-03-01T12:00:00Z","finished_at":"2026-03-01T12:10:00Z","looked_up":2,"cached":0,"skipped_cdn":0,"skipped_reserved":0,"skipped_budget":0,"stopped_reason":"","error":"timed out after 10m0s"}`
	vtNames    = `{"host_name":"a.example","first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-02-01T00:00:00Z","watched":true,"campaign":"spynote"},{"host_name":"new.example","first_seen":"2026-01-15T00:00:00Z","last_seen":"2026-02-15T00:00:00Z","watched":false,"campaign":""}`
)

func TestDomainVT(t *testing.T) {
	for _, tc := range []struct{ vt, want string }{
		{vt: `null`, want: `"vt":null`},
		{
			vt:   `{"looked_up_at":null,"status":null,"resolutions":[{"ip":"192.0.2.1","first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-02-01T00:00:00Z"}]}`,
			want: `"vt":{"looked_up_at":null,"status":null,"resolutions":[{"ip":"192.0.2.1","first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-02-01T00:00:00Z"}]}`,
		},
		{
			vt:   `{"looked_up_at":"2026-03-01T11:00:00Z","status":"empty","resolutions":[]}`,
			want: `"vt":{"looked_up_at":"2026-03-01T11:00:00Z","status":"empty","resolutions":[]}`,
		},
	} {
		s, _ := stub(t, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"domain":null,"current":[],"changes":[],"pdns":[],"vt":` + tc.vt + `}`))
		})
		res, err := s.Domain(context.Background(), "a.example", 0)
		if err != nil {
			t.Errorf("%s: %v", tc.vt, err)
			continue
		}
		if (res.VT == nil) != (tc.vt == "null") {
			t.Errorf("%s: vt = %+v", tc.vt, res.VT)
		}
		b, _ := json.Marshal(res)
		if !strings.Contains(string(b), tc.want) {
			t.Errorf("%s: result %s lacks %s", tc.vt, b, tc.want)
		}
	}
}

func TestVTIP(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{
			body: `{"ip":"192.0.2.1","looked_up_at":"2026-03-01T11:00:00Z","status":"ok","names":[` + vtNames + `]}`,
			want: `"ip":"192.0.2.1","fetched_at":"2026-03-01T12:00:00Z","looked_up_at":"2026-03-01T11:00:00Z","status":"ok","returned":2,"names":[` + vtNames + `]}`,
		},
		{
			body: `{"ip":"192.0.2.1","looked_up_at":null,"status":null,"names":[]}`,
			want: `"looked_up_at":null,"status":null,"returned":0,"names":[]}`,
		},
	} {
		s, reqs := stub(t, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(tc.body))
		})
		res, err := s.VTIP(context.Background(), " 192.0.2.1 ")
		if err != nil {
			t.Errorf("%s: %v", tc.body, err)
			continue
		}
		if got := strings.Join(*reqs, ", "); got != "GET /api/vt/ip/192.0.2.1" {
			t.Errorf("%s: requests = %s", tc.body, got)
		}
		b, _ := json.Marshal(res)
		if !strings.Contains(string(b), tc.want) {
			t.Errorf("%s: result %s lacks %s", tc.body, b, tc.want)
		}
	}
}

func TestVTBudget(t *testing.T) {
	s, reqs := stub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"budget":500,"used_today":120,"remaining":380}`))
	})
	res, err := s.VTBudget(context.Background())
	if err != nil {
		t.Fatalf("VTBudget: %v", err)
	}
	if got := strings.Join(*reqs, ", "); got != "GET /api/vt/budget" {
		t.Errorf("requests = %s", got)
	}
	if res != (VTBudgetResult{FetchedAt: "2026-03-01T12:00:00Z", Budget: 500, UsedToday: 120, Remaining: 380}) {
		t.Errorf("result = %+v", res)
	}
}

func TestVTErrors(t *testing.T) {
	s, reqs := stub(t, nil)
	if _, err := s.VTIP(context.Background(), " "); err == nil || len(*reqs) != 0 {
		t.Errorf("empty ip: err %v, requests %v", err, *reqs)
	}
	_, err := s.VTIP(context.Background(), "192.0.2.1")
	if !heimdall.IsStatus(err, http.StatusNotFound) || !strings.Contains(err.Error(), "not configured") {
		t.Errorf("VTIP err = %v, want the 404 named as no VirusTotal", err)
	}
	_, err = s.VTBudget(context.Background())
	if !heimdall.IsStatus(err, http.StatusNotFound) || !strings.Contains(err.Error(), "not configured") {
		t.Errorf("VTBudget err = %v, want the 404 named as no VirusTotal", err)
	}
}

func TestVTEnrich(t *testing.T) {
	for _, tc := range []struct {
		desc     string
		domain   string
		campaign string
		ip       string
		depth    int
		wait     bool
		status   int
		post     string
		gets     []string
		waitFor  time.Duration
		wantReqs string
		wantQ    string
		wantErr  string
		state    string
		summary  bool
		note     string
	}{
		{
			desc:     "domain, wait until done",
			domain:   "a.example",
			depth:    2,
			wait:     true,
			post:     jobRunning,
			gets:     []string{jobRunning, jobDone},
			wantReqs: "POST " + enrichA + ", GET " + enrichA + ", GET " + enrichA,
			wantQ:    "depth=2",
			state:    "done",
			summary:  true,
		},
		{
			desc:     "campaign by name, wait until failed",
			campaign: "SpyNote",
			wait:     true,
			post:     jobRunning,
			gets:     []string{jobFailed},
			wantReqs: "GET /api/campaigns, POST /api/vt/enrich/campaign/2, GET /api/vt/enrich/campaign/2",
			state:    "failed",
			summary:  true,
		},
		{
			desc:    "still running when the wait ends",
			domain:  "a.example",
			wait:    true,
			post:    jobRunning,
			gets:    []string{jobRunning},
			waitFor: 20 * time.Millisecond,
			wantQ:   "depth=1",
			state:   "running",
			note:    "still running after 20ms",
		},
		{desc: "no wait", domain: "a.example", post: jobRunning, wantReqs: "POST " + enrichA, wantQ: "depth=1", state: "running"},
		{
			desc:     "viewer token",
			domain:   "a.example",
			wait:     true,
			status:   http.StatusForbidden,
			post:     `{"error":"forbidden"}`,
			wantReqs: "POST " + enrichA,
			wantQ:    "depth=1",
			wantErr:  "forbidden",
		},
		{
			desc:     "VirusTotal not configured",
			domain:   "a.example",
			status:   http.StatusNotFound,
			post:     `{"error":"not found"}`,
			wantReqs: "POST " + enrichA,
			wantQ:    "depth=1",
			wantErr:  "not configured",
		},
		{desc: "unknown campaign", campaign: "missing", wantReqs: "GET /api/campaigns", wantErr: "no campaign"},
		{desc: "both", domain: "a.example", campaign: "spynote", wantErr: "either"},
		{desc: "neither", wantErr: "either"},
		{desc: "depth 3", domain: "a.example", depth: 3, wantErr: "depth must be 1 or 2"},
		{desc: "depth on a campaign", campaign: "spynote", depth: 2, wantErr: "domain only"},
		{
			desc:     "ip, wait until done",
			ip:       " 2001:DB8::1 ",
			wait:     true,
			post:     jobRunning,
			gets:     []string{jobDone},
			wantReqs: "POST /api/vt/enrich/ip/2001:db8::1, GET /api/vt/enrich/ip/2001:db8::1",
			state:    "done",
			summary:  true,
		},
		{desc: "ip, no wait", ip: "192.0.2.1", post: jobRunning, wantReqs: "POST /api/vt/enrich/ip/192.0.2.1", state: "running"},
		{desc: "depth on an ip", ip: "192.0.2.1", depth: 2, wantErr: "domain only"},
		{desc: "invalid ip", ip: "192.0.2", wantErr: "not an IP address"},
		{desc: "domain and ip", domain: "a.example", ip: "192.0.2.1", wantErr: "either"},
		{desc: "campaign and ip", campaign: "spynote", ip: "192.0.2.1", wantErr: "either"},
	} {
		gets := 0
		var gotQuery string
		s, reqs := stub(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				gotQuery = r.URL.RawQuery
				w.WriteHeader(cmp.Or(tc.status, http.StatusAccepted))
				w.Write([]byte(tc.post))
				return
			}
			w.Write([]byte(tc.gets[min(gets, len(tc.gets)-1)]))
			gets++
		})
		s.poll, s.maxWait = time.Millisecond, cmp.Or(tc.waitFor, 5*time.Second)
		res, err := s.VTEnrichRequest(context.Background(), VTRequest{Domain: tc.domain, Campaign: tc.campaign, IP: tc.ip, Depth: tc.depth}, tc.wait)
		// The polls of a wait that ran out are not counted.
		if got := strings.Join(*reqs, ", "); tc.waitFor == 0 && got != tc.wantReqs {
			t.Errorf("%s: requests = %q, want %q", tc.desc, got, tc.wantReqs)
		}
		if gotQuery != tc.wantQ {
			t.Errorf("%s: query %q, want %q", tc.desc, gotQuery, tc.wantQ)
		}
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: err %v, want one mentioning %q", tc.desc, err, tc.wantErr)
			}
			if tc.status != 0 && !heimdall.IsStatus(err, tc.status) {
				t.Errorf("%s: err %v, want the HTTP %d as is", tc.desc, err, tc.status)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.desc, err)
			continue
		}
		if res.State != tc.state || (res.Summary != nil) != tc.summary || (res.State == "failed") != (res.Error != "") {
			t.Errorf("%s: result %+v", tc.desc, res)
		}
		if (tc.note == "") != (res.Note == "") || !strings.Contains(res.Note, tc.note) {
			t.Errorf("%s: note %q, want one mentioning %q", tc.desc, res.Note, tc.note)
		}
	}
}

func TestVTEnrichKeepsItsSignature(t *testing.T) {
	s, reqs := stub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(jobRunning))
	})
	res, err := s.VTEnrich(context.Background(), "a.example", "", 2, false)
	if err != nil || res.Domain != "a.example" || res.Depth != 2 || res.IP != "" || res.State != "running" {
		t.Errorf("result %+v, %v", res, err)
	}
	if got := strings.Join(*reqs, ", "); got != "POST "+enrichA {
		t.Errorf("requests = %s", got)
	}
}

const (
	certSHA256    = "8f7a1c52e0b3d94a6c1f2e7b0d5a3c9e4b8f6a2d1c7e5b3a9f0d4c2e6b8a1f3d"
	domainEnrich  = "/api/enrich/domain/a.example"
	enrichStored  = "/api/domains/a.example/enrich"
	enrichRunning = `{"job":"domain:a.example","state":"running","started_at":"2026-03-01T12:00:00Z"}`
	enrichDone    = `{"job":"domain:a.example","state":"done","started_at":"2026-03-01T12:00:00Z","finished_at":"2026-03-01T12:00:04Z","status":"partial","counts":{"dns":1,"rdap":1,"ct":1,"subdomains":0},"errors":{"subdomains":"passive DNS: timeout"},"summary":"partial: dns 1, rdap 1, ct 1, subdomains failed"}`
	enrichFailed  = `{"job":"domain:a.example","state":"failed","started_at":"2026-03-01T12:00:00Z","finished_at":"2026-03-01T12:00:04Z","status":"ok","counts":{"dns":1,"rdap":1,"ct":1,"subdomains":0},"summary":"ok: dns 1, rdap 1, ct 1, subdomains 0","error":"internal error"}`
	enrichBody    = `{"fqdn":"a.example","fetched_at":"2026-03-01T12:00:04Z","status":"partial",` +
		`"dns":{"resolver":"9.9.9.9:53","records":[{"qtype":"A","rcode":"NOERROR","ttl":300,"rdata":["192.0.2.1"]}]},` +
		`"zone":{"name":"a.example","soa":[],"ns":["ana.ns.cloudflare.com","bob.ns.cloudflare.com"]},` +
		`"rdap":{"domain":"a.example","registrar":{"name":"NameCheap, Inc.","iana_id":"1068"},"registration":"2026-02-01T00:00:00Z","status":[],"nameservers":[],"entities":[]},` +
		`"ct":{"zone":"a.example","total":1,"certificates":[{"id":"7392018311","cert_sha256":"` + certSHA256 + `","issuer":"R11","not_before":"2026-02-01T00:00:00Z","not_after":"2026-05-02T00:00:00Z","revoked":false,"names":["a.example"]}],"names":["a.example"],"truncated":false},` +
		`"subdomains":null,"errors":{"subdomains":"passive DNS: timeout"},` +
		`"graph":{"nodes":[{"id":"d:a.example","kind":"domain","label":"a.example","watched":false,"campaign":"","href":"/domains/a.example","source":"heimdall"}],"edges":[],"truncated":false,"excluded_cdn":0}}`
)

func TestDomainEnrich(t *testing.T) {
	for _, tc := range []struct {
		desc         string
		fqdn         string
		wait         bool
		includeGraph bool
		status       int
		post         string
		gets         []string
		waitFor      time.Duration
		wantReqs     string
		wantErr      string
		state        string
		summary      bool
		enrichment   bool
		note         string
	}{
		{
			desc:       "wait until done",
			fqdn:       " A.Example. ",
			wait:       true,
			post:       enrichRunning,
			gets:       []string{enrichRunning, enrichDone},
			wantReqs:   "POST " + domainEnrich + ", GET " + domainEnrich + ", GET " + domainEnrich + ", GET " + enrichStored,
			state:      "done",
			summary:    true,
			enrichment: true,
		},
		{
			desc:         "wait until done, with the graph",
			fqdn:         "a.example",
			wait:         true,
			includeGraph: true,
			post:         enrichRunning,
			gets:         []string{enrichDone},
			wantReqs:     "POST " + domainEnrich + ", GET " + domainEnrich + ", GET " + enrichStored,
			state:        "done",
			summary:      true,
			enrichment:   true,
		},
		{
			desc:     "wait until failed",
			fqdn:     "a.example",
			wait:     true,
			post:     enrichRunning,
			gets:     []string{enrichFailed},
			wantReqs: "POST " + domainEnrich + ", GET " + domainEnrich,
			state:    "failed",
			summary:  true,
		},
		{
			desc:    "still running when the wait ends",
			fqdn:    "a.example",
			wait:    true,
			post:    enrichRunning,
			gets:    []string{enrichRunning},
			waitFor: 20 * time.Millisecond,
			state:   "running",
			note:    "still running after 20ms",
		},
		{desc: "no wait", fqdn: "a.example", post: enrichRunning, wantReqs: "POST " + domainEnrich, state: "running"},
		{
			desc:     "viewer token",
			fqdn:     "a.example",
			wait:     true,
			status:   http.StatusForbidden,
			post:     `{"error":"forbidden"}`,
			wantReqs: "POST " + domainEnrich,
			wantErr:  "forbidden",
		},
		{desc: "empty", fqdn: " ", wantErr: "fqdn is required"},
		{desc: "one label", fqdn: "localhost", wantErr: "invalid fqdn"},
		{desc: "empty label", fqdn: "a..example", wantErr: "invalid fqdn"},
		{desc: "bad character", fqdn: "a b.example", wantErr: "invalid fqdn"},
		{desc: "path", fqdn: "a.example/x", wantErr: "invalid fqdn"},
	} {
		gets := 0
		s, reqs := stub(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost:
				w.WriteHeader(cmp.Or(tc.status, http.StatusAccepted))
				w.Write([]byte(tc.post))
			case r.URL.Path == enrichStored:
				w.Write([]byte(enrichBody))
			default:
				w.Write([]byte(tc.gets[min(gets, len(tc.gets)-1)]))
				gets++
			}
		})
		s.poll, s.maxWait = time.Millisecond, cmp.Or(tc.waitFor, 5*time.Second)
		res, err := s.DomainEnrich(context.Background(), tc.fqdn, tc.wait, tc.includeGraph)
		// The polls of a wait that ran out are not counted.
		if got := strings.Join(*reqs, ", "); tc.waitFor == 0 && got != tc.wantReqs {
			t.Errorf("%s: requests = %q, want %q", tc.desc, got, tc.wantReqs)
		}
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: err %v, want one mentioning %q", tc.desc, err, tc.wantErr)
			}
			if tc.status != 0 && !heimdall.IsStatus(err, tc.status) {
				t.Errorf("%s: err %v, want the HTTP %d as is", tc.desc, err, tc.status)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.desc, err)
			continue
		}
		if res.FQDN != "a.example" || res.State != tc.state || (res.Summary != nil) != tc.summary || (res.State == "failed") != (res.Error != "") {
			t.Errorf("%s: result %+v", tc.desc, res)
		}
		if (res.Enrichment != nil) != tc.enrichment {
			t.Errorf("%s: enrichment %+v, want present %v", tc.desc, res.Enrichment, tc.enrichment)
		}
		if res.Enrichment != nil && (res.Enrichment.Graph != nil) != tc.includeGraph {
			t.Errorf("%s: graph %+v, want present %v", tc.desc, res.Enrichment.Graph, tc.includeGraph)
		}
		if (tc.note == "") != (res.Note == "") || !strings.Contains(res.Note, tc.note) {
			t.Errorf("%s: note %q, want one mentioning %q", tc.desc, res.Note, tc.note)
		}
		b, _ := json.Marshal(res)
		if !strings.Contains(string(b), `"enrichment":`) || strings.Contains(string(b), `"graph"`) != tc.includeGraph {
			t.Errorf("%s: encoded as %s", tc.desc, b)
		}
		if tc.enrichment && !strings.Contains(string(b), `"cert_sha256":"`+certSHA256+`"`) {
			t.Errorf("%s: encoded without the whole SHA-256: %s", tc.desc, b)
		}
	}
}

func TestDomainEnrichment(t *testing.T) {
	for _, tc := range []struct {
		desc         string
		fqdn         string
		includeGraph bool
		status       int
		wantReqs     string
		wantErr      string
		notEnriched  bool
	}{
		{desc: "without graph", fqdn: "a.example.", wantReqs: "GET " + enrichStored},
		{desc: "with graph", fqdn: "a.example", includeGraph: true, wantReqs: "GET " + enrichStored},
		{desc: "never enriched", fqdn: "a.example", status: http.StatusNotFound, wantReqs: "GET " + enrichStored, wantErr: "not enriched yet, run hd_domain_enrich", notEnriched: true},
		{desc: "server error", fqdn: "a.example", status: http.StatusInternalServerError, wantReqs: "GET " + enrichStored, wantErr: "HTTP 500"},
		{desc: "invalid", fqdn: "a..example", wantErr: "invalid fqdn"},
	} {
		s, reqs := stub(t, func(w http.ResponseWriter, r *http.Request) {
			if tc.status != 0 {
				http.Error(w, `{"error":"not found"}`, tc.status)
				return
			}
			w.Write([]byte(enrichBody))
		})
		res, err := s.DomainEnrichment(context.Background(), tc.fqdn, tc.includeGraph)
		if got := strings.Join(*reqs, ", "); got != tc.wantReqs {
			t.Errorf("%s: requests = %q, want %q", tc.desc, got, tc.wantReqs)
		}
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || errors.Is(err, heimdall.ErrNotEnriched) != tc.notEnriched {
				t.Errorf("%s: err %v, want one mentioning %q", tc.desc, err, tc.wantErr)
			}
			continue
		}
		if err != nil || res.FQDN != "a.example" || res.Enrichment == nil || (res.Enrichment.Graph != nil) != tc.includeGraph {
			t.Errorf("%s: result %+v, %v", tc.desc, res, err)
			continue
		}
		if e := res.Enrichment; e.Errors["subdomains"] == "" || e.Subdomains != nil || e.CT == nil || e.CT.Certificates[0].CertSHA256 != certSHA256 {
			t.Errorf("%s: enrichment %+v", tc.desc, e)
		}
	}
}

func TestLinkDomain(t *testing.T) {
	for _, tc := range []struct {
		desc, fqdn, campaign, newName, newDesc string
		status                                 int
		wantReqs                               string
		wantBody                               string
		wantErr                                string
	}{
		{
			desc:     "campaign by name",
			fqdn:     "A.example",
			campaign: "SpyNote",
			wantReqs: "GET /api/campaigns, POST /api/domains/a.example/link",
			wantBody: `{"campaign":2}`,
		},
		{
			desc:     "campaign by id",
			fqdn:     "a.example",
			campaign: "3",
			wantReqs: "GET /api/campaigns, POST /api/domains/a.example/link",
			wantBody: `{"campaign":3}`,
		},
		{
			desc:     "new campaign",
			fqdn:     "a.example",
			newName:  " spynote-2026 ",
			newDesc:  "March wave",
			wantReqs: "POST /api/domains/a.example/link",
			wantBody: `{"new_campaign":{"name":"spynote-2026","description":"March wave"}}`,
		},
		{
			desc:     "new campaign exists",
			fqdn:     "a.example",
			newName:  "SpyNote",
			status:   http.StatusConflict,
			wantReqs: "POST /api/domains/a.example/link",
			wantBody: `{"new_campaign":{"name":"SpyNote","description":""}}`,
			wantErr:  `campaign "SpyNote" already exists`,
		},
		{
			desc:     "viewer token",
			fqdn:     "a.example",
			newName:  "x",
			status:   http.StatusForbidden,
			wantReqs: "POST /api/domains/a.example/link",
			wantBody: `{"new_campaign":{"name":"x","description":""}}`,
			wantErr:  "HTTP 403",
		},
		{desc: "unknown campaign", fqdn: "a.example", campaign: "missing", wantReqs: "GET /api/campaigns", wantErr: "no campaign"},
		{desc: "both", fqdn: "a.example", campaign: "spynote", newName: "x", wantErr: "either"},
		{desc: "neither", fqdn: "a.example", wantErr: "either"},
		{desc: "description without new campaign", fqdn: "a.example", campaign: "spynote", newDesc: "x", wantErr: "new campaign only"},
		{desc: "invalid fqdn", fqdn: "a", campaign: "spynote", wantErr: "invalid fqdn"},
	} {
		var gotBody string
		s, reqs := stub(t, func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			if tc.status != 0 {
				http.Error(w, `{"error":"campaign exists"}`, tc.status)
				return
			}
			w.Write([]byte(`{"fqdn":"a.example","campaign":{"id":2,"name":"SpyNote"},"action":"added","created_campaign":false}`))
		})
		res, err := s.LinkDomain(context.Background(), tc.fqdn, tc.campaign, tc.newName, tc.newDesc)
		if got := strings.Join(*reqs, ", "); got != tc.wantReqs {
			t.Errorf("%s: requests = %q, want %q", tc.desc, got, tc.wantReqs)
		}
		if gotBody != tc.wantBody {
			t.Errorf("%s: body %s, want %s", tc.desc, gotBody, tc.wantBody)
		}
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: err %v, want one mentioning %q", tc.desc, err, tc.wantErr)
			}
			if tc.status != 0 && !heimdall.IsStatus(err, tc.status) {
				t.Errorf("%s: err %v, want the HTTP %d as is", tc.desc, err, tc.status)
			}
			continue
		}
		if err != nil || res.Action != "added" || res.Campaign.ID != 2 {
			t.Errorf("%s: result %+v, %v", tc.desc, res, err)
		}
	}
}

func TestNSSet(t *testing.T) {
	const graph = `{"nodes":[{"id":"ns:ana.ns.cloudflare.com,bob.ns.cloudflare.com","kind":"nsset","label":"ana.ns.cloudflare.com, bob.ns.cloudflare.com","watched":false,"campaign":"","href":"","source":"heimdall"},` +
		`{"id":"d:a.example","kind":"domain","label":"a.example","watched":true,"campaign":"spynote","href":"/domains/a.example","source":"heimdall"},` +
		`{"id":"d:b.example","kind":"domain","label":"b.example","watched":false,"campaign":"","href":"/domains/b.example","source":"heimdall"}],` +
		`"edges":[],"truncated":%s,"excluded_cdn":0}`
	many := make([]string, 17)
	for i := range many {
		many[i] = "ns" + strconv.Itoa(i) + ".example"
	}
	for _, tc := range []struct {
		desc      string
		ns        []string
		truncated bool
		wantPath  string
		wantErr   string
	}{
		{
			desc:     "normalized",
			ns:       []string{" Bob.NS.Cloudflare.com. ", "ana.ns.cloudflare.com", "ana.ns.cloudflare.com.", ""},
			wantPath: "/api/graph/ns/ana.ns.cloudflare.com,bob.ns.cloudflare.com",
		},
		{
			desc:      "truncated",
			ns:        []string{"ana.ns.cloudflare.com", "bob.ns.cloudflare.com"},
			truncated: true,
			wantPath:  "/api/graph/ns/ana.ns.cloudflare.com,bob.ns.cloudflare.com",
		},
		{desc: "16", ns: many[:16], wantPath: "/api/graph/ns/" + strings.Join(slices.Sorted(slices.Values(many[:16])), ",")},
		{desc: "one", ns: []string{"ana.ns.cloudflare.com"}, wantErr: "got 1"},
		{desc: "one, twice", ns: []string{"ana.ns.cloudflare.com", "ANA.ns.cloudflare.com."}, wantErr: "got 1"},
		{desc: "none", wantErr: "got 0"},
		{desc: "17", ns: many, wantErr: "got 17"},
		{desc: "invalid", ns: []string{"ana.ns.cloudflare.com", "bob..cloudflare.com"}, wantErr: "invalid fqdn"},
	} {
		var gotPath string
		s, reqs := stub(t, func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			fmt.Fprintf(w, graph, strconv.FormatBool(tc.truncated))
		})
		res, err := s.NSSet(context.Background(), tc.ns)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || len(*reqs) != 0 {
				t.Errorf("%s: err %v, requests %v; want one mentioning %q and no request", tc.desc, err, *reqs, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.desc, err)
			continue
		}
		if gotPath != tc.wantPath {
			t.Errorf("%s: path %q, want %q", tc.desc, gotPath, tc.wantPath)
		}
		want := []NSSetDomain{{FQDN: "a.example", Watched: true, Campaign: "spynote"}, {FQDN: "b.example"}}
		if res.Returned != 2 || !slices.Equal(res.Domains, want) || res.Truncated != tc.truncated || (res.Note != "") != tc.truncated {
			t.Errorf("%s: result %+v", tc.desc, res)
		}
		if tc.desc == "normalized" && strings.Join(res.NS, " ") != "ana.ns.cloudflare.com bob.ns.cloudflare.com" {
			t.Errorf("%s: ns %v", tc.desc, res.NS)
		}
	}
}
