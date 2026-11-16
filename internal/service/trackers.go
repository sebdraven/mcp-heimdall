package service

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/sebdraven/mcp-heimdall/internal/heimdall"
)

// Trackers reads at most maxTrackerNames enrichments, trackerFetches at a
// time.
const (
	maxTrackerNames = 200
	trackerFetches  = 8
)

type TrackersCounts struct {
	Names         int `json:"names"`
	Enriched      int `json:"enriched"`
	NotEnriched   int `json:"not_enriched"`
	Failed        int `json:"failed"`
	LookylooError int `json:"lookyloo_error"`
	NoCapture     int `json:"no_capture"`
	WithTrackers  int `json:"with_trackers"`
}

// TrackersDomain is the Lookyloo block of one stored enrichment; Campaign is
// empty for a name not watched.
type TrackersDomain struct {
	FQDN          string                     `json:"fqdn"`
	Campaign      string                     `json:"campaign"`
	EnrichedAt    string                     `json:"enriched_at"`
	LookylooError string                     `json:"lookyloo_error"`
	CapturesFound int                        `json:"captures_found"`
	CapturesRead  int                        `json:"captures_read"`
	Truncated     bool                       `json:"truncated"`
	Trackers      []heimdall.LookylooTracker `json:"trackers"`
}

// SharedTracker is a tracker identifier held by at least two names.
type SharedTracker struct {
	Value   string   `json:"value"`
	Kind    string   `json:"kind"`
	ID      string   `json:"id"`
	Domains []string `json:"domains"`
}

type TrackersResult struct {
	FetchedAt   string                `json:"fetched_at"`
	Campaign    *heimdall.CampaignRef `json:"campaign"`
	Counts      TrackersCounts        `json:"counts"`
	Domains     []TrackersDomain      `json:"domains"`
	Shared      []SharedTracker       `json:"shared"`
	NotEnriched []string              `json:"not_enriched"`
	Failed      []DomainError         `json:"failed"`
}

// Trackers reads the Lookyloo trackers of the stored enrichments of a
// campaign's domains (id or exact name) and of fqdns, and the identifiers
// they share. A campaign domain Heimdall holds under an invalid name is
// failed rather than read.
func (s *Service) Trackers(ctx context.Context, campaign string, fqdns []string) (TrackersResult, error) {
	var names []string
	for _, f := range fqdns {
		if strings.TrimSpace(f) == "" {
			continue
		}
		n, err := normalizeFQDN(f)
		if err != nil {
			return TrackersResult{}, err
		}
		names = append(names, n)
	}
	campaign = strings.TrimSpace(campaign)
	if campaign == "" && len(names) == 0 {
		return TrackersResult{}, fmt.Errorf("give a campaign, fqdns or both")
	}

	res := TrackersResult{Domains: []TrackersDomain{}, Shared: []SharedTracker{}, NotEnriched: []string{}, Failed: []DomainError{}}
	watched := map[string]string{}
	if campaign != "" {
		c, err := s.ResolveCampaign(ctx, campaign)
		if err != nil {
			return TrackersResult{}, err
		}
		ds, err := s.client.CampaignDomains(ctx, c.ID)
		if err != nil {
			return TrackersResult{}, err
		}
		res.Campaign = &heimdall.CampaignRef{ID: c.ID, Name: c.Name}
		for _, d := range ds {
			n, err := normalizeFQDN(d.FQDN)
			if err != nil {
				res.Failed = append(res.Failed, DomainError{FQDN: d.FQDN, Error: err.Error()})
				continue
			}
			watched[n] = cmp.Or(d.Campaign, c.Name)
			names = append(names, n)
		}
	}
	names = slices.Compact(slices.Sorted(slices.Values(names)))
	res.Counts.Names = len(names) + len(res.Failed)
	if res.Counts.Names > maxTrackerNames {
		return TrackersResult{}, fmt.Errorf("at most %d names, got %d", maxTrackerNames, res.Counts.Names)
	}

	// Names outside the campaign take theirs from the watchlist.
	if slices.ContainsFunc(names, func(n string) bool { return watched[n] == "" }) {
		ds, err := s.client.Domains(ctx)
		if err != nil {
			return TrackersResult{}, err
		}
		for _, d := range ds {
			if n, err := normalizeFQDN(d.FQDN); err == nil {
				if _, ok := watched[n]; !ok {
					watched[n] = d.Campaign
				}
			}
		}
	}

	type fetched struct {
		e   heimdall.DomainEnrichment
		err error
	}
	got := make([]fetched, len(names))
	sem := make(chan struct{}, trackerFetches)
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			got[i].e, got[i].err = s.client.DomainEnrichment(ctx, n)
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return TrackersResult{}, err
	}

	holders := map[heimdall.Tracker][]string{}
	for i, n := range names {
		e, err := got[i].e, got[i].err
		switch {
		case errors.Is(err, heimdall.ErrNotEnriched):
			res.NotEnriched = append(res.NotEnriched, n)
			continue
		case err != nil:
			res.Failed = append(res.Failed, DomainError{FQDN: n, Error: err.Error()})
			continue
		}
		d := TrackersDomain{FQDN: n, Campaign: watched[n], EnrichedAt: e.FetchedAt, LookylooError: e.Errors["lookyloo"], Trackers: []heimdall.LookylooTracker{}}
		if l := e.Lookyloo; l != nil {
			d.CapturesFound, d.CapturesRead, d.Truncated = l.CapturesFound, l.CapturesRead, l.Truncated
			if l.Trackers != nil {
				d.Trackers = l.Trackers
			}
		}
		switch {
		case d.LookylooError != "":
			res.Counts.LookylooError++
		case d.CapturesFound == 0:
			res.Counts.NoCapture++
		}
		if len(d.Trackers) > 0 {
			res.Counts.WithTrackers++
		}
		for _, t := range d.Trackers {
			k := heimdall.Tracker{Kind: t.Kind, ID: t.ID}
			if hs := holders[k]; len(hs) == 0 || hs[len(hs)-1] != n {
				holders[k] = append(hs, n)
			}
		}
		res.Domains = append(res.Domains, d)
	}

	for k, ds := range holders {
		if len(ds) >= 2 {
			res.Shared = append(res.Shared, SharedTracker{Value: k.Kind + ":" + k.ID, Kind: k.Kind, ID: k.ID, Domains: ds})
		}
	}
	slices.SortFunc(res.Shared, func(a, b SharedTracker) int {
		return cmp.Or(cmp.Compare(len(b.Domains), len(a.Domains)), strings.Compare(a.Value, b.Value))
	})
	slices.SortFunc(res.Failed, func(a, b DomainError) int { return strings.Compare(a.FQDN, b.FQDN) })

	res.FetchedAt = s.stamp()
	res.Counts.Enriched, res.Counts.NotEnriched = len(res.Domains), len(res.NotEnriched)
	res.Counts.Failed = len(res.Failed)
	return res, nil
}
