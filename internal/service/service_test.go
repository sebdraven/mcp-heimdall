package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
