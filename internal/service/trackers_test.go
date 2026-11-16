package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sebdraven/mcp-heimdall/internal/heimdall"
)

func watchJSON(fqdn, campaign string) string {
	return `{"fqdn":"` + fqdn + `","campaign":"` + campaign + `","interval_seconds":43200,"enabled":true,"source":"web:alice","added_at":"2026-03-01T12:00:00Z"}`
}

func trackerJSON(kind, id string) string {
	return `{"kind":"` + kind + `","id":"` + id + `","first_seen":"2026-10-02T14:10:00Z","last_seen":"2026-11-10T08:58:00Z","captures":1}`
}

func lookylooJSON(found int, trackers ...string) string {
	return `{"instance":"https://lookyloo.example","captures_found":` + strconv.Itoa(found) + `,"captures_read":` + strconv.Itoa(found) + `,"truncated":false,"submitted":null,` +
		`"trackers":[` + strings.Join(trackers, ",") + `],"hosts":[{"name":"www.example","first_seen":"2026-10-02T14:10:00Z","last_seen":"2026-11-10T08:58:00Z"}]}`
}

// storedJSON is a stored enrichment with a certificate, to check CT is left
// out.
func storedJSON(fqdn, lookyloo, errs string) string {
	return `{"fqdn":"` + fqdn + `","fetched_at":"2026-11-10T09:00:00Z","status":"ok","dns":null,"zone":null,"rdap":null,` +
		`"ct":{"zone":"` + fqdn + `","total":1,"certificates":[{"id":"9120344517","cert_sha256":"` + certSHA256 + `","issuer":"R11","not_before":"2026-09-01T00:00:00Z","not_after":"2026-11-30T00:00:00Z","revoked":false,"names":["` + fqdn + `"]}],"names":["` + fqdn + `"],"truncated":false},` +
		`"subdomains":null,"lookyloo":` + lookyloo + `,"errors":` + errs + `}`
}

// trackersReplies: SpyNote (2) holds a, b and c; d is FluBot's, e watched
// without campaign, x not watched. c was never enriched, d's Lookyloo failed
// after reading a capture, e has no Lookyloo block and f answers a 500.
var trackersReplies = map[string]string{
	"/api/campaigns":           campaignsJSON,
	"/api/campaigns/2/domains": `[` + watchJSON("a.example", "SpyNote") + `,` + watchJSON("B.example.", "SpyNote") + `,` + watchJSON("c.example", "SpyNote") + `]`,
	"/api/domains": `[` + watchJSON("a.example", "SpyNote") + `,` + watchJSON("b.example", "SpyNote") + `,` + watchJSON("c.example", "SpyNote") + `,` +
		watchJSON("d.example", "FluBot") + `,` + watchJSON("e.example", "") + `]`,
	"/api/domains/a.example/enrich": storedJSON("a.example", lookylooJSON(2, trackerJSON("adsense", "ca-pub-1111"), trackerJSON("gtm", "GTM-AAAA")), `{}`),
	"/api/domains/b.example/enrich": storedJSON("b.example", lookylooJSON(1, trackerJSON("adsense", "ca-pub-1111"), trackerJSON("gtm", "GTM-AAAA"), trackerJSON("jivosite", "abc")), `{}`),
	"/api/domains/d.example/enrich": storedJSON("d.example", lookylooJSON(3, trackerJSON("gtm", "GTM-AAAA")), `{"lookyloo":"lookyloo: timeout"}`),
	"/api/domains/e.example/enrich": storedJSON("e.example", `null`, `{}`),
	"/api/domains/x.example/enrich": storedJSON("x.example", lookylooJSON(0), `{}`),
}

// trackersStub serves trackersReplies; requests, sent concurrently, come back
// sorted.
func trackersStub(t *testing.T) (*Service, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		mu.Unlock()
		body, ok := trackersReplies[r.URL.Path]
		switch {
		case r.URL.Path == "/api/domains/f.example/enrich":
			http.Error(w, `{"error":"database is locked"}`, http.StatusInternalServerError)
		case ok && r.Method == http.MethodGet:
			w.Write([]byte(body))
		default:
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	s := New(heimdall.New(srv.URL, "TOK"))
	s.now = func() time.Time { return t0 }
	return s, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Sorted(slices.Values(requests))
	}
}

func enrichGet(fqdns ...string) []string {
	out := make([]string, 0, len(fqdns))
	for _, f := range fqdns {
		out = append(out, "GET /api/domains/"+f+"/enrich")
	}
	return out
}

func TestTrackers(t *testing.T) {
	many := make([]string, 0, maxTrackerNames+1)
	for i := range maxTrackerNames + 1 {
		many = append(many, fmt.Sprintf("n%d.example", i))
	}
	for _, tc := range []struct {
		desc        string
		campaign    string
		fqdns       []string
		wantErr     string
		wantReqs    []string
		campaignRef *heimdall.CampaignRef
		domains     []string // fqdn/campaign/trackers
		shared      []string // value=domains
		notEnriched []string
		failed      []string
		counts      TrackersCounts
		want        []string
	}{
		{
			desc:        "campaign",
			campaign:    "SpyNote",
			wantReqs:    append([]string{"GET /api/campaigns", "GET /api/campaigns/2/domains"}, enrichGet("a.example", "b.example", "c.example")...),
			campaignRef: &heimdall.CampaignRef{ID: 2, Name: "SpyNote"},
			domains:     []string{"a.example/SpyNote/2", "b.example/SpyNote/3"},
			shared:      []string{"adsense:ca-pub-1111=a.example,b.example", "gtm:GTM-AAAA=a.example,b.example"},
			notEnriched: []string{"c.example"},
			counts:      TrackersCounts{Names: 3, Enriched: 2, NotEnriched: 1, WithTrackers: 2},
			want:        []string{`"campaign":{"id":2,"name":"SpyNote"}`, `"kind":"jivosite","id":"abc"`, `"failed":[]`},
		},
		{
			desc:     "fqdns",
			fqdns:    []string{"D.example.", "e.example", " ", "x.example", "f.example"},
			wantReqs: append([]string{"GET /api/domains"}, enrichGet("d.example", "e.example", "f.example", "x.example")...),
			domains:  []string{"d.example/FluBot/1", "e.example//0", "x.example//0"},
			failed:   []string{"f.example"},
			counts:   TrackersCounts{Names: 4, Enriched: 3, Failed: 1, LookylooError: 1, NoCapture: 2, WithTrackers: 1},
			want: []string{`"campaign":null`, `"shared":[]`, `"not_enriched":[]`,
				`{"fqdn":"d.example","campaign":"FluBot","enriched_at":"2026-11-10T09:00:00Z","lookyloo_error":"lookyloo: timeout","captures_found":3,"captures_read":3,"truncated":false,"trackers":[`,
				`{"fqdn":"e.example","campaign":"","enriched_at":"2026-11-10T09:00:00Z","lookyloo_error":"","captures_found":0,"captures_read":0,"truncated":false,"trackers":[]}`},
		},
		{
			desc:        "campaign and fqdns",
			campaign:    "2",
			fqdns:       []string{"a.example", "D.example", "A.EXAMPLE."},
			wantReqs:    append([]string{"GET /api/campaigns", "GET /api/campaigns/2/domains", "GET /api/domains"}, enrichGet("a.example", "b.example", "c.example", "d.example")...),
			campaignRef: &heimdall.CampaignRef{ID: 2, Name: "SpyNote"},
			domains:     []string{"a.example/SpyNote/2", "b.example/SpyNote/3", "d.example/FluBot/1"},
			shared:      []string{"gtm:GTM-AAAA=a.example,b.example,d.example", "adsense:ca-pub-1111=a.example,b.example"},
			notEnriched: []string{"c.example"},
			counts:      TrackersCounts{Names: 4, Enriched: 3, NotEnriched: 1, LookylooError: 1, WithTrackers: 3},
		},
		{
			desc:        "campaign and one of its fqdns",
			campaign:    "SpyNote",
			fqdns:       []string{"b.example"},
			wantReqs:    append([]string{"GET /api/campaigns", "GET /api/campaigns/2/domains"}, enrichGet("a.example", "b.example", "c.example")...),
			campaignRef: &heimdall.CampaignRef{ID: 2, Name: "SpyNote"},
			domains:     []string{"a.example/SpyNote/2", "b.example/SpyNote/3"},
			shared:      []string{"adsense:ca-pub-1111=a.example,b.example", "gtm:GTM-AAAA=a.example,b.example"},
			notEnriched: []string{"c.example"},
			counts:      TrackersCounts{Names: 3, Enriched: 2, NotEnriched: 1, WithTrackers: 2},
		},
		{desc: "nothing", fqdns: []string{" "}, wantErr: "give a campaign, fqdns or both"},
		{desc: "too many", fqdns: many, wantErr: "at most 200 names, got 201"},
		{desc: "invalid fqdn", fqdns: []string{"a..example"}, wantErr: "invalid fqdn"},
		{desc: "unknown campaign", campaign: "Spynote", wantErr: "no campaign", wantReqs: []string{"GET /api/campaigns"}},
	} {
		s, reqs := trackersStub(t)
		res, err := s.Trackers(context.Background(), tc.campaign, tc.fqdns)
		if got, want := strings.Join(reqs(), ", "), strings.Join(slices.Sorted(slices.Values(tc.wantReqs)), ", "); got != want {
			t.Errorf("%s: requests %s, want %s", tc.desc, got, want)
		}
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: err %v, want one mentioning %q", tc.desc, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.desc, err)
			continue
		}
		if res.FetchedAt != "2026-03-01T12:00:00Z" {
			t.Errorf("%s: fetched_at %q", tc.desc, res.FetchedAt)
		}
		if (res.Campaign == nil) != (tc.campaignRef == nil) || res.Campaign != nil && *res.Campaign != *tc.campaignRef {
			t.Errorf("%s: campaign %+v, want %+v", tc.desc, res.Campaign, tc.campaignRef)
		}
		var domains, shared, failed []string
		for _, d := range res.Domains {
			domains = append(domains, fmt.Sprintf("%s/%s/%d", d.FQDN, d.Campaign, len(d.Trackers)))
		}
		for _, sh := range res.Shared {
			if sh.Value != sh.Kind+":"+sh.ID {
				t.Errorf("%s: shared %+v", tc.desc, sh)
			}
			shared = append(shared, sh.Value+"="+strings.Join(sh.Domains, ","))
		}
		for _, f := range res.Failed {
			if !strings.Contains(f.Error, "HTTP 500") {
				t.Errorf("%s: failed %+v", tc.desc, f)
			}
			failed = append(failed, f.FQDN)
		}
		for _, c := range []struct {
			name      string
			got, want []string
		}{
			{"domains", domains, tc.domains},
			{"shared", shared, tc.shared},
			{"not_enriched", res.NotEnriched, tc.notEnriched},
			{"failed", failed, tc.failed},
		} {
			if !slices.Equal(c.got, c.want) {
				t.Errorf("%s: %s %q, want %q", tc.desc, c.name, c.got, c.want)
			}
		}
		if res.Counts != tc.counts {
			t.Errorf("%s: counts %+v, want %+v", tc.desc, res.Counts, tc.counts)
		}
		b, _ := json.Marshal(res)
		for _, w := range tc.want {
			if !strings.Contains(string(b), w) {
				t.Errorf("%s: encoded as %s, lacks %s", tc.desc, b, w)
			}
		}
		for _, w := range []string{`"hosts"`, `"captures":[`, `"cert_sha256"`, `"ct"`, `"trackers":null`} {
			if strings.Contains(string(b), w) {
				t.Errorf("%s: encoded as %s, holds %s", tc.desc, b, w)
			}
		}
	}
}
