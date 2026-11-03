package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/cache"
	"github.com/riccivr/bugrouter/internal/httpx"
	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/version"
)

func resolveTarget(ctx context.Context, httpClient *httpx.Client, query string, noCache bool) (*resolver.Target, error) {
	if httpClient == nil {
		httpClient = httpx.NewClient(0)
	}
	wf := resolver.NewWaterfall(
		0,
		resolver.NewOrgCloudProbe(),
		resolver.NewDirectProbe(),
		resolver.NewWorkspaceProbe("."),
		resolver.NewOSPackageProbe(),
		resolver.NewRegistryProbe(httpClient, resolver.DefaultRegistryEndpoints()),
		resolver.NewWebDomainProbe(httpClient),
	)
	if !noCache {
		wf.WithCache(cache.NewStore("", 0))
	}
	return wf.Resolve(ctx, query)
}

func splitInterleavedFlags(args []string, valueFlags map[string]bool) (flagArgs, posArgs []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			posArgs = append(posArgs, args[i+1:]...)
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			posArgs = append(posArgs, arg)
			continue
		}
		flagArgs = append(flagArgs, arg)
		if strings.Contains(arg, "=") {
			continue
		}
		flagName := strings.TrimLeft(arg, "-")
		if (valueFlags[flagName] || valueFlags[arg]) && i+1 < len(args) {
			i++
			flagArgs = append(flagArgs, args[i])
		}
	}
	return flagArgs, posArgs
}

func recoverAndParkSelfBug(r any, stack []byte, storeDir string) (*adapter.ParkedBug, error) {
	if r == nil {
		return nil, nil
	}
	parkStore := adapter.NewParkedStore(storeDir)
	title := fmt.Sprintf("internal panic in bugrouter %s: %v", version.Version, r)
	snippet := string(stack)
	workaround := fmt.Sprintf("os=%s arch=%s", runtime.GOOS, runtime.GOARCH)
	bug, _, err := parkStore.Park("bugrouter", title, snippet, workaround, "")
	if err != nil {
		return nil, fmt.Errorf("park self bug: %w", err)
	}
	return bug, nil
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			bug, parkErr := recoverAndParkSelfBug(r, stack, "")
			if parkErr != nil {
				fmt.Fprintf(os.Stderr, "internal panic: %v\n%s\nfailed to park self bug: %v\n", r, string(stack), parkErr)
			} else if bug != nil {
				fmt.Fprintf(os.Stderr, "internal panic: %v\n%s\nParked breadcrumb bug %s.\nTo draft an upstream ticket, run:\n  bugrouter draft --from-parked %s\n", r, string(stack), bug.ID, bug.ID)
			}
			os.Exit(1)
		}
	}()

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]
	var subArgs []string
	if len(os.Args) > 2 {
		subArgs = os.Args[2:]
	}

	switch subcommand {
	case "version", "--version", "-version", "-v":
		fmt.Printf("bugrouter %s (%s/%s)\n", version.Version, runtime.GOOS, runtime.GOARCH)

	case "mcp":
		cmdMCP(subArgs)

	case "resolve":
		cmdResolve(subArgs)

	case "introspect":
		cmdIntrospect(subArgs)

	case "dedup":
		cmdDedup(subArgs)

	case "scrub":
		cmdScrub(subArgs)

	case "triage":
		cmdTriage(subArgs)

	case "verify":
		cmdVerify(subArgs)

	case "park":
		cmdPark(subArgs)

	case "parked":
		cmdParked(subArgs)

	case "patch":
		cmdPatch(subArgs)

	case "draft":
		cmdDraft(subArgs)

	case "report":
		cmdReport(subArgs)

	case "agent":
		cmdAgent(subArgs)

	case "crash-log":
		cmdCrashLog(subArgs)

	case "telemetry":
		cmdTelemetry(subArgs)

	case "stack":
		cmdStack(subArgs)

	case "serve":
		cmdServe(subArgs)

	case "paths":
		cmdPaths(subArgs)

	case "self-test":
		cmdSelfTest(subArgs)

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "bugrouter - Automated upstream bug routing, template introspection, deduplication, and staging daemon")
	fmt.Fprintln(os.Stderr, "\nUsage:")
	fmt.Fprintln(os.Stderr, "  bugrouter <command> [arguments]")
	fmt.Fprintln(os.Stderr, "\nCommands:")
	fmt.Fprintln(os.Stderr, "  version                     Print version information")
	fmt.Fprintln(os.Stderr, "  paths [--json]              Display resolved local filesystem storage paths (XDG)")
	fmt.Fprintln(os.Stderr, "  self-test [--json]          Run offline smoke test verifying resolution and secret scrubbing")
	fmt.Fprintln(os.Stderr, "  resolve [--json] [--no-cache] [--timeout <dur>] <target>")
	fmt.Fprintln(os.Stderr, "                              Resolve target query through waterfall architecture")
	fmt.Fprintln(os.Stderr, "  introspect [--json] [--no-cache] [--timeout <dur>] <target>")
	fmt.Fprintln(os.Stderr, "                              Discovers and displays upstream issue templates, forms, and policies")
	fmt.Fprintln(os.Stderr, "  dedup [--json] [--no-cache] [--timeout <dur>] <target> <title>")
	fmt.Fprintln(os.Stderr, "                              Query upstream tracker for existing duplicate bug reports")
	fmt.Fprintln(os.Stderr, "  scrub [--input <text>]      Deterministically scrub secrets and sensitive paths from input text")
	fmt.Fprintln(os.Stderr, "  triage [--log-file <path>] [--query <target>] [--title <t>] [--summary-md] [--timeout <dur>]")
	fmt.Fprintln(os.Stderr, "                              Autonomous triage of crash logs outputting machine-parseable JSON or Markdown")
	fmt.Fprintln(os.Stderr, "  verify [--timeout <dur>] [--expect-exit <code>] [--work-dir <dir>] -- <executable> [args...]")
	fmt.Fprintln(os.Stderr, "         or: verify --cmd <shell-command> (shell evaluation)")
	fmt.Fprintln(os.Stderr, "                              Bounded reproduction execution and deterministic proof generation (preferred: shell-free argv via '--')")
	fmt.Fprintln(os.Stderr, "  park [--snippet <s>] [--workaround <w>] [--file <f>] [--related-dep <pkg>] [--json] <dependency> <title>")
	fmt.Fprintln(os.Stderr, "                              Instantly park a 3rd-party anomaly in <5ms without hijacking session")
	fmt.Fprintln(os.Stderr, "  parked [list] [--all] [--json]")
	fmt.Fprintln(os.Stderr, "                              List active parked bug breadcrumbs in queue")
	fmt.Fprintln(os.Stderr, "  parked show [--json] <id>   Inspect details of a parked bug breadcrumb")
	fmt.Fprintln(os.Stderr, "  parked rm <id>              Remove a parked bug breadcrumb from queue")
	fmt.Fprintln(os.Stderr, "  patch list [--json]         List tracked dependency patches and temporary forks")
	fmt.Fprintln(os.Stderr, "  patch add --dep <d> --target <fork> [--ecosystem <e>] [--issue <url>] [--manifest <m>] [--reason <r>]")
	fmt.Fprintln(os.Stderr, "                              Record a temporary dependency fork/patch in the ledger")
	fmt.Fprintln(os.Stderr, "  patch scan [--dir <dir>] [--json]")
	fmt.Fprintln(os.Stderr, "                              Scan workspace manifests for local forks/patches and sync to ledger")
	fmt.Fprintln(os.Stderr, "  patch rm <id-or-dep>        Remove a dependency patch from the ledger")
	fmt.Fprintln(os.Stderr, "  patch check [--json] [--summary-md] [--fail-on-revertable] [--timeout <dur>]")
	fmt.Fprintln(os.Stderr, "                              Check upstream issue status for tracked patches and flag revertable forks")
	fmt.Fprintln(os.Stderr, "  draft [--title <t>] [--summary <s>] [--steps <st>] [--logs <l>] [--from-parked <id>] [--related-dep <pkg>]")
	fmt.Fprintln(os.Stderr, "        [--verify-cmd <cmd>] [--with-telemetry] [--body-file <path>] [--strict-quality] [--timeout <dur>] [--json] [--no-cache] [<q>]")
	fmt.Fprintln(os.Stderr, "                              Stage bug report draft and generate submission URLs")
	fmt.Fprintln(os.Stderr, "  report [--title <t>] [--summary <s>] [--steps <st>] [--expected <ex>] [--actual <ac>] [--logs <l>]")
	fmt.Fprintln(os.Stderr, "         [--with-telemetry] [--no-telemetry] [--json] [--no-cache] [--timeout <dur>] <q>")
	fmt.Fprintln(os.Stderr, "                              Interactive guided bug reporting wizard with live anti-slop quality linting")
	fmt.Fprintln(os.Stderr, "  telemetry [--json] [--timeout <dur>]")
	fmt.Fprintln(os.Stderr, "                              Inspect local operating system and hardware telemetry")
	fmt.Fprintln(os.Stderr, "  crash-log [--json] [--query <target>] [--no-cache] [--timeout <dur>]")
	fmt.Fprintln(os.Stderr, "                              Inspect and triage the latest native OS post-mortem crash log")
	fmt.Fprintln(os.Stderr, "  agent triage [--log-file <path>] [--query <target>] [--title <t>] [--summary-md] [--timeout <dur>]")
	fmt.Fprintln(os.Stderr, "                              Autonomous triage of crash logs outputting machine-parseable JSON or Markdown")
	fmt.Fprintln(os.Stderr, "  agent verify [--timeout <dur>] [--expect-exit <code>] [--work-dir <dir>] -- <executable> [args...]")
	fmt.Fprintln(os.Stderr, "               or: agent verify --cmd <shell-command> (shell evaluation)")
	fmt.Fprintln(os.Stderr, "                              Bounded reproduction execution and deterministic proof generation (preferred: shell-free argv via '--')")
	fmt.Fprintln(os.Stderr, "  agent telemetry [--json] [--timeout <dur>]")
	fmt.Fprintln(os.Stderr, "                              Inspect local telemetry as machine-parseable JSON")
	fmt.Fprintln(os.Stderr, "  stack [--dir <dir>] [--check-upstream] [--json] [--no-cache] [--timeout <dur>]")
	fmt.Fprintln(os.Stderr, "                              Scan workspace dependency manifests and downstream bug radar")
	fmt.Fprintln(os.Stderr, "  serve [--addr <addr>] [--drafts-dir <dir>] [--auth-token <tok>] [--audit-log <path>] [--webhook-url <url>] [--webhook-secret <sec>]")
	fmt.Fprintln(os.Stderr, "                              Start Cloud Control Plane HTTP daemon and Web UI")
	fmt.Fprintln(os.Stderr, "  mcp                         Start Model Context Protocol (MCP) stdio server")
}
