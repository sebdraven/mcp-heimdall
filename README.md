# mcp-heimdall

An MCP server and a command-line client for
[Heimdall](https://github.com/sebdraven/heimdall), active DNS measurement of a
watchlist of domains (Android RAT and stalkerware campaign infrastructure).

Heimdall resolves every watched domain continuously against its own recursive
resolvers, keeps every answer, and derives from them a passive DNS view in the
CIRCL Common Output Format and a stream of change events. This server puts that
history, the event stream and the watchlist in front of a model.

Requires a Heimdall instance and an API token, created on the Heimdall side:

```sh
heimdall-cli token create --username alice --label mcp
```

The token inherits the role of its user: `viewer` reads, `analyst` can also add
and change domains and run VirusTotal enrichments.

## Tools

| Tool | What it answers |
|---|---|
| `hd_pdns_query` | which records a name owns — rrtype, rdata, first and last seen, count |
| `hd_pdns_rdata` | which names held a value — IP, target name, MX/TXT/SOA text |
| `hd_domain` | everything the domain page shows: watchlist entry, current state, change timeline, passive DNS; each change has a `scope`, current entries flag CDN addresses in `cdn`, `vt` holds VirusTotal's past resolutions |
| `hd_pivots` | which other names shared an A or AAAA value (CDN addresses listed in `excluded_cdn` instead) or exactly the same NS set, and when the periods overlapped |
| `hd_events` | what changed — new or removed values, NXDOMAIN, resurrection, sinkhole or parking NS, SOA serial, TTL |
| `hd_campaigns` | the campaigns and how many domains each watches |
| `hd_campaign_domains` | the domains of one campaign, by id or exact name |
| `hd_domains` | the whole watchlist, optionally only enabled or disabled entries |
| `hd_create_campaign` | create a campaign, with optional malware family and description |
| `hd_add_domains` | add domains to a campaign; reports added, already present and failed |
| `hd_set_domain` | enable, disable, re-time or move one domain |
| `hd_vt_ip` | which names VirusTotal saw on an IP, from Heimdall's cache, each `watched` or not with its campaign |
| `hd_vt_enrich` | look up with VirusTotal the graph of a domain (depth 1 or 2) or of a campaign; spends the daily budget |
| `hd_vt_budget` | the VirusTotal lookups of the UTC day: budget, used, remaining |

There is no deletion: disabling a domain stops measurement and keeps its
history. Write tools and `hd_vt_enrich` need an `analyst` token; with a
`viewer` token Heimdall's 403 comes back as is.

Results are compact JSON, untruncated.

In `hd_domain`, a change with `"scope": "zone"` is a change of the parent
zone, tracked by Heimdall as `zone:<fqdn>` (its SOA or NS), not of the name's
own records; `"scope": "name"` is the name itself. A `current` entry whose
`rdata` holds CDN addresses carries `"cdn": {"<ip>": "<provider>"}`, absent
otherwise.

`hd_pivots` returns `pivots`, `excluded_cdn` and `ns_pairs`:

- `pivots` are the names that shared one of the name's A or AAAA values. The
  values that fall in Heimdall's CDN prefixes are not pivoted on and are
  listed in `excluded_cdn` as `{"value", "provider"}`.
- `ns_pairs` is `{"zone", "ns", "matches"}`: the zone of the name (itself, or
  its nearest ancestor owning NS records seen in the last 7 days), its sorted
  NS set, and the other names whose current NS set is strictly identical. A
  single nameserver says nothing, but providers such as Cloudflare give each
  account its own pair, so an identical set is a strong sign of one operator.
  CDN prefixes do not apply. `ns_pairs` is `null` when no zone is found or
  its set has fewer than 2 nameservers.

Against an older Heimdall, `excluded_cdn` is empty and `ns_pairs` is `null`.

### VirusTotal

A Heimdall configured with a VirusTotal key caches what VirusTotal saw: the
past resolutions of names and the names seen on addresses, a history from
another source than Heimdall's own measurements.

- `hd_domain` carries `vt`: `{"looked_up_at", "status", "resolutions"}`, each
  resolution `{"ip", "first_seen", "last_seen"}`, read from the cache and never
  from VirusTotal. `vt` is `null` when Heimdall has no VirusTotal.
  `looked_up_at` and `status` (`ok`, `empty` or `error`) are `null` while the
  domain itself has not been enriched, though resolutions cached by lookups of
  its addresses may already show.
- `hd_vt_ip` lists, from the cache, the names VirusTotal saw on an address,
  each with `watched` and its `campaign`: the unwatched ones are candidates for
  `hd_add_domains`.
- `hd_vt_enrich` is the only tool that calls VirusTotal. It spends lookups
  from a daily budget shared by every user of the Heimdall, so check
  `hd_vt_budget` before enriching a whole campaign. With `wait` (the default)
  it polls the job every 2 seconds until it is done or failed, for at most 5
  minutes, and returns its `summary` (`looked_up`, `cached`, `skipped_budget`,
  `skipped_cdn`, `skipped_reserved`, `stopped_reason`); a job still running
  then comes back with `"state": "running"`, `summary` `null` and a note.
  Enriching a target already being enriched returns the running job.
- `hd_vt_budget` returns `budget`, `used_today` and `remaining` for the UTC
  day.

Without VirusTotal on the Heimdall side, the `hd_vt_*` tools fail with
Heimdall's 404.

## Configuration

| Variable | Meaning |
|---|---|
| `HEIMDALL_URL` | base URL of the Heimdall API, e.g. `https://webarchive.tail399dd.ts.net`; required, there is no default |
| `HEIMDALL_TOKEN` | the API token; on macOS it can live in the keychain under the service name `mcp-heimdall` instead |
| `HEIMDALL_TIMEOUT` | per-request timeout, a Go duration (default `30s`) |

```json
{
  "mcpServers": {
    "heimdall": {
      "command": "/path/to/mcp-heimdall",
      "env": {
        "HEIMDALL_URL": "https://heimdall.example.ts.net",
        "HEIMDALL_TOKEN": "..."
      }
    }
  }
}
```

Storing the token in the keychain keeps it out of the config file:

```sh
security add-generic-password -s mcp-heimdall -a "$USER" -w
```

The `-w` with no value prompts, so the token never reaches your shell history.

An HTTP error is reported with its status and the first 500 bytes of the
response body.

## hdctl

The same operations from a shell, one subcommand per tool, JSON on stdout.
Flags come before arguments.

```sh
hdctl pdns-query www.example.com
hdctl pdns-rdata 192.0.2.1
hdctl domain -changes-limit 50 www.example.com
hdctl pivots www.example.com
hdctl events -since 7d -kind ns_sinkhole
hdctl campaigns
hdctl campaign-domains spynote-2026
hdctl domains -enabled=false
hdctl add-domains -campaign spynote-2026 -f domains.txt
hdctl set-domain -enabled=false www.example.com
hdctl set-domain -campaign '' www.example.com
hdctl vt-ip 192.0.2.1
hdctl vt-enrich -depth 2 www.example.com
hdctl vt-enrich -campaign spynote-2026 -wait=false
hdctl vt-budget
```

`pivots` prints `excluded_cdn` and `ns_pairs` next to `pivots`.
`add-domains` reads `-f` one domain per line, `#` starting a comment, `-` for
stdin, and defaults to a 43200-second (12-hour) interval. It exits 1 if any
domain failed. `vt-enrich` exits 1 if the enrichment failed.

## Terms

- **rrname** is the owner of a record, not the name that was queried. An A
  query for `www.x` answered through a CNAME to `cdn.y` yields two records,
  `(www.x, CNAME, cdn.y)` and `(cdn.y, A, <ip>)`: reaching a watched name's IPs
  means following its CNAME targets, and the A/AAAA pivots of `hd_pivots` only
  see values owned by the name itself.
- **rdata** is the value of a record: an IP, a target name, or MX, TXT or SOA
  text.
- **tracked set** is what Heimdall retains for one (domain, qtype, resolver)
  after hysteresis. For A, AAAA, NS, MX and TXT a new value enters at once but
  leaves only after several consecutive answers without it (3 by default), so a
  resolver rotating through a pool produces no churn. Changes and events are
  computed on the tracked set, not on raw answers.

| Event kind | Meaning |
|---|---|
| `new_rdata` | a value entered the tracked set |
| `removed_rdata` | a value left the tracked set |
| `nxdomain` | the name went from NOERROR to NXDOMAIN (A query only) |
| `resurrection` | the name went from NXDOMAIN back to NOERROR (A query only) |
| `ns_sinkhole` | a new NS matches a pattern classed as a sinkhole |
| `ns_parking` | a new NS matches a pattern classed as parking |
| `soa_serial_change` | the SOA serial changed |
| `ttl_change` | the TTL rose above twice its learnt ceiling, or stayed below a quarter of it for a full window, with the tracked set unchanged |

## Caveats

- **Heimdall only knows its watchlist and its resolvers.** A name it does not
  watch has no history, and passive DNS here is what Heimdall itself observed,
  not a global sensor network. Absence proves nothing.
- **Shared values are leads, not attribution.** Shared hosting, CDNs and
  parking providers put unrelated names on the same IPs and nameservers.
  Heimdall only sets aside the CDN prefixes its operator listed.
- **Passive DNS times are COF**, Unix epoch seconds in `time_first` and
  `time_last`; every other date is RFC 3339 UTC.
- **Campaign names are case-sensitive.** A value that matches one campaign's id
  and another's name is refused as ambiguous rather than guessed.

## License

MIT, see `LICENSE.md`.
