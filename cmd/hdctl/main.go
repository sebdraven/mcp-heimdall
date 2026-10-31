// Command hdctl runs the mcp-heimdall tools from a shell, one subcommand per
// tool, and prints the result as JSON. Flags come before arguments.
//
//	hdctl domain www.example.com
//	hdctl events -since 7d -kind ns_sinkhole
//	hdctl add-domains -campaign spynote-2026 -f domains.txt
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/sebdraven/mcp-heimdall/internal/heimdall"
	"github.com/sebdraven/mcp-heimdall/internal/service"
)

var version = "dev"

type runFunc func(context.Context, *service.Service, []string) (any, error)

var commands = []struct {
	name, usage string
	run         runFunc
}{
	{"pdns-query", "[-limit N] RRNAME", pdnsQuery},
	{"pdns-rdata", "[-limit N] VALUE", pdnsRdata},
	{"domain", "[-changes-limit N] FQDN", domain},
	{"pivots", "[-limit N] FQDN", pivots},
	{"events", "[-since 24h|7d|RFC3339] [-kind KIND] [-campaign NAME] [-limit N]", events},
	{"campaigns", "", campaigns},
	{"campaign-domains", "CAMPAIGN", campaignDomains},
	{"domains", "[-enabled=true|false]", domains},
	{"add-domains", "-campaign CAMPAIGN [-interval SECONDS] [-f FILE] [FQDN...]", addDomains},
	{"set-domain", "[-enabled=true|false] [-interval SECONDS] [-campaign CAMPAIGN] FQDN", setDomain},
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: hdctl COMMAND [flags] [args]")
	for _, c := range commands {
		fmt.Fprintf(os.Stderr, "  %s %s\n", c.name, c.usage)
	}
	fmt.Fprintln(os.Stderr, "  -version")
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "-version", "--version", "version":
		fmt.Println(version)
		return
	case "-h", "-help", "--help", "help":
		usage()
		return
	}
	var run runFunc
	for _, c := range commands {
		if c.name == os.Args[1] {
			run = c.run
		}
	}
	if run == nil {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := heimdall.FromEnv()
	if err != nil {
		log.Fatalf("%v", err)
	}
	res, err := run(ctx, service.New(client), os.Args[2:])
	if err != nil {
		log.Fatalf("%v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		log.Fatalf("encoding result: %v", err)
	}
	if r, ok := res.(service.AddDomainsResult); ok && len(r.Failed) > 0 {
		os.Exit(1)
	}
}

func parse(name string, fs *flag.FlagSet, args []string, nargs int) ([]string, error) {
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if nargs >= 0 && fs.NArg() != nargs {
		return nil, fmt.Errorf("%s: want %d argument(s), got %d", name, nargs, fs.NArg())
	}
	return fs.Args(), nil
}

func pdnsQuery(ctx context.Context, svc *service.Service, args []string) (any, error) {
	fs := flag.NewFlagSet("pdns-query", flag.ExitOnError)
	limit := fs.Int("limit", 0, "max records (default and max 10000)")
	a, err := parse("pdns-query", fs, args, 1)
	if err != nil {
		return nil, err
	}
	return svc.PDNSQuery(ctx, a[0], *limit)
}

func pdnsRdata(ctx context.Context, svc *service.Service, args []string) (any, error) {
	fs := flag.NewFlagSet("pdns-rdata", flag.ExitOnError)
	limit := fs.Int("limit", 0, "max records (default and max 10000)")
	a, err := parse("pdns-rdata", fs, args, 1)
	if err != nil {
		return nil, err
	}
	return svc.PDNSRdata(ctx, a[0], *limit)
}

func domain(ctx context.Context, svc *service.Service, args []string) (any, error) {
	fs := flag.NewFlagSet("domain", flag.ExitOnError)
	limit := fs.Int("changes-limit", 0, "max changes (default 200, max 1000)")
	a, err := parse("domain", fs, args, 1)
	if err != nil {
		return nil, err
	}
	return svc.Domain(ctx, a[0], *limit)
}

func pivots(ctx context.Context, svc *service.Service, args []string) (any, error) {
	fs := flag.NewFlagSet("pivots", flag.ExitOnError)
	limit := fs.Int("limit", 0, "max pivots (default 1000, max 10000)")
	a, err := parse("pivots", fs, args, 1)
	if err != nil {
		return nil, err
	}
	return svc.Pivots(ctx, a[0], *limit)
}

func events(ctx context.Context, svc *service.Service, args []string) (any, error) {
	fs := flag.NewFlagSet("events", flag.ExitOnError)
	since := fs.String("since", "", "RFC 3339 or duration back from now: 90m, 24h, 7d (default 24h)")
	kind := fs.String("kind", "", "event kind")
	campaign := fs.String("campaign", "", "campaign name, exact")
	limit := fs.Int("limit", 0, "max events (default 1000, max 10000)")
	if _, err := parse("events", fs, args, 0); err != nil {
		return nil, err
	}
	return svc.Events(ctx, *since, *kind, *campaign, *limit)
}

func campaigns(ctx context.Context, svc *service.Service, args []string) (any, error) {
	fs := flag.NewFlagSet("campaigns", flag.ExitOnError)
	if _, err := parse("campaigns", fs, args, 0); err != nil {
		return nil, err
	}
	return svc.Campaigns(ctx)
}

func campaignDomains(ctx context.Context, svc *service.Service, args []string) (any, error) {
	fs := flag.NewFlagSet("campaign-domains", flag.ExitOnError)
	a, err := parse("campaign-domains", fs, args, 1)
	if err != nil {
		return nil, err
	}
	return svc.CampaignDomains(ctx, a[0])
}

func domains(ctx context.Context, svc *service.Service, args []string) (any, error) {
	fs := flag.NewFlagSet("domains", flag.ExitOnError)
	var enabled optBool
	fs.Var(&enabled, "enabled", "only enabled (true) or disabled (false) domains")
	if _, err := parse("domains", fs, args, 0); err != nil {
		return nil, err
	}
	return svc.Domains(ctx, enabled.v)
}

func addDomains(ctx context.Context, svc *service.Service, args []string) (any, error) {
	fs := flag.NewFlagSet("add-domains", flag.ExitOnError)
	campaign := fs.String("campaign", "", "campaign id or exact name (required)")
	interval := fs.Int("interval", service.DefaultInterval, "measurement interval in seconds")
	file := fs.String("f", "", "file of domains, one per line, '#' comments ('-' for stdin)")
	fqdns, err := parse("add-domains", fs, args, -1)
	if err != nil {
		return nil, err
	}
	if *file != "" {
		more, err := readList(*file)
		if err != nil {
			return nil, err
		}
		fqdns = append(fqdns, more...)
	}
	return svc.AddDomains(ctx, fqdns, *campaign, *interval)
}

func setDomain(ctx context.Context, svc *service.Service, args []string) (any, error) {
	fs := flag.NewFlagSet("set-domain", flag.ExitOnError)
	var (
		enabled  optBool
		interval optInt
		campaign optString
	)
	fs.Var(&enabled, "enabled", "enable or disable measurement")
	fs.Var(&interval, "interval", "measurement interval in seconds")
	fs.Var(&campaign, "campaign", "campaign id or exact name; '' detaches the domain")
	a, err := parse("set-domain", fs, args, 1)
	if err != nil {
		return nil, err
	}
	return svc.SetDomain(ctx, a[0], enabled.v, interval.v, campaign.v)
}

// readList reads one entry per line; '#' starts a comment.
func readList(path string) ([]string, error) {
	f := os.Stdin
	if path != "-" {
		var err error
		if f, err = os.Open(path); err != nil {
			return nil, err
		}
		defer f.Close()
	}
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

// optBool, optInt and optString tell an absent flag from a zero value.
type optBool struct{ v *bool }

func (o *optBool) String() string {
	if o == nil || o.v == nil {
		return ""
	}
	return strconv.FormatBool(*o.v)
}

func (o *optBool) Set(s string) error {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	o.v = &b
	return nil
}

func (o *optBool) IsBoolFlag() bool { return true }

type optInt struct{ v *int }

func (o *optInt) String() string {
	if o == nil || o.v == nil {
		return ""
	}
	return strconv.Itoa(*o.v)
}

func (o *optInt) Set(s string) error {
	n, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	o.v = &n
	return nil
}

type optString struct{ v *string }

func (o *optString) String() string {
	if o == nil || o.v == nil {
		return ""
	}
	return *o.v
}

func (o *optString) Set(s string) error {
	o.v = &s
	return nil
}
