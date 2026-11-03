package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/httpx"
)

func runParked(out io.Writer, errOut io.Writer, args []string) int {
	var subAction string
	var subArgs []string
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		subAction = "list"
		subArgs = args
	} else {
		subAction = args[0]
		subArgs = args[1:]
	}

	parkStore := adapter.NewParkedStore("")
	switch subAction {
	case "list":
		fs := flag.NewFlagSet("parked list", flag.ContinueOnError)
		fs.SetOutput(errOut)
		jsonOut := fs.Bool("json", false, "output JSON array")
		showAll := fs.Bool("all", false, "include triaged parked bugs")
		if err := fs.Parse(subArgs); err != nil {
			return 1
		}
		bugs, err := parkStore.List()
		if err != nil {
			fmt.Fprintf(errOut, "error: list parked bugs: %v\n", err)
			return 1
		}
		var filtered []*adapter.ParkedBug
		for _, b := range bugs {
			if !*showAll && b.Status == "triaged" {
				continue
			}
			filtered = append(filtered, b)
		}
		if filtered == nil {
			filtered = []*adapter.ParkedBug{}
		}

		if *jsonOut {
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			if err := enc.Encode(filtered); err != nil {
				fmt.Fprintf(errOut, "error: encode json: %v\n", err)
				return 1
			}
			return 0
		}
		if len(filtered) == 0 {
			fmt.Fprintln(out, "No active parked bugs in queue.")
			return 0
		}
		fmt.Fprintf(out, "%-10s %-10s %-20s %-15s %-30s %s\n", "ID", "STATUS", "DEPENDENCY", "RELATED", "TITLE", "FILE")
		fmt.Fprintln(out, strings.Repeat("-", 100))
		for _, b := range filtered {
			related := b.RelatedDependency
			if related == "" {
				related = "-"
			}
			file := b.WorkspaceFile
			if file == "" {
				file = "-"
			}
			status := b.Status
			if status == "" {
				status = "parked"
			}
			fmt.Fprintf(out, "%-10s %-10s %-20s %-15s %-30s %s\n", b.ID, status, b.Dependency, related, b.Title, file)
		}
		return 0

	case "show":
		fs := flag.NewFlagSet("parked show", flag.ContinueOnError)
		fs.SetOutput(errOut)
		jsonOut := fs.Bool("json", false, "output structured JSON")
		if err := fs.Parse(subArgs); err != nil {
			return 1
		}
		posArgs := fs.Args()
		if len(posArgs) < 1 {
			fmt.Fprintln(errOut, "error: parked show requires <id>")
			fmt.Fprintln(errOut, "Usage: bugrouter parked show [--json] <id>")
			return 1
		}
		id := posArgs[0]
		b, err := parkStore.Get(id)
		if err != nil {
			fmt.Fprintf(errOut, "error: load parked bug %s: %v\n", id, err)
			return 1
		}
		if *jsonOut {
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			if err := enc.Encode(b); err != nil {
				fmt.Fprintf(errOut, "error: encode json: %v\n", err)
				return 1
			}
			return 0
		}
		fmt.Fprintf(out, "Parked Bug ID:   %s\n", b.ID)
		status := b.Status
		if status == "" {
			status = "parked"
		}
		fmt.Fprintf(out, "Status:          %s\n", status)
		fmt.Fprintf(out, "Dependency:      %s\n", b.Dependency)
		if b.RelatedDependency != "" {
			fmt.Fprintf(out, "Related Dep:     %s\n", b.RelatedDependency)
		}
		fmt.Fprintf(out, "Title:           %s\n", b.Title)
		if b.WorkspaceFile != "" {
			fmt.Fprintf(out, "Workspace File:  %s\n", b.WorkspaceFile)
		}
		if string(b.WorkaroundNote) != "" {
			fmt.Fprintf(out, "Workaround Note:\n  %s\n", b.WorkaroundNote)
		}
		if string(b.ErrorSnippet) != "" {
			fmt.Fprintf(out, "Error Snippet:\n%s\n", b.ErrorSnippet)
		}
		fmt.Fprintf(out, "\nTo stage a draft bug report from this parked bug:\n  bugrouter draft --from-parked %s\n", b.ID)
		return 0

	case "rm":
		if len(subArgs) < 1 {
			fmt.Fprintln(errOut, "error: parked rm requires <id>")
			fmt.Fprintln(errOut, "Usage: bugrouter parked rm <id>")
			return 1
		}
		id := subArgs[0]
		if err := parkStore.Delete(id); err != nil {
			fmt.Fprintf(errOut, "error: remove parked bug %s: %v\n", id, err)
			return 1
		}
		fmt.Fprintf(out, "Removed parked bug %s from queue.\n", id)
		return 0

	default:
		fmt.Fprintf(errOut, "error: unknown parked subcommand %q\n", subAction)
		fmt.Fprintln(errOut, "Usage: bugrouter parked <list|show|rm> [arguments...]")
		return 1
	}
}

func runPatchScan(store *adapter.PatchStore, out, errOut io.Writer, args []string) int {
	fs := flag.NewFlagSet("patch scan", flag.ContinueOnError)
	fs.SetOutput(errOut)
	dir := fs.String("dir", ".", "workspace directory to scan for vendor patches and forks")
	jsonOut := fs.Bool("json", false, "output JSON array")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if store == nil {
		store = adapter.NewPatchStore("")
	}
	added, err := store.SyncWorkspace(*dir)
	if err != nil {
		fmt.Fprintf(errOut, "error: scan workspace patches: %v\n", err)
		return 1
	}
	if *jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(added); err != nil {
			fmt.Fprintf(errOut, "error: encode json: %v\n", err)
			return 1
		}
		return 0
	}
	if len(added) == 0 {
		fmt.Fprintln(out, "No new dependency patches discovered in workspace.")
		return 0
	}
	fmt.Fprintf(out, "%-10s %-25s %-10s %-30s %s\n", "ID", "DEPENDENCY", "ECOSYSTEM", "TARGET", "REASON")
	fmt.Fprintln(out, strings.Repeat("-", 90))
	for _, p := range added {
		fmt.Fprintf(out, "%-10s %-25s %-10s %-30s %s\n", p.ID, p.Dependency, p.Ecosystem, p.PatchTarget, p.Reason)
	}
	return 0
}

func escapeMarkdownTableCell(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "`", "\\`")
	return s
}

func runPatchCheck(ctx context.Context, httpClient *httpx.Client, out, errOut io.Writer, args []string) int {
	fs := flag.NewFlagSet("patch check", flag.ContinueOnError)
	fs.SetOutput(errOut)
	jsonOut := fs.Bool("json", false, "output JSON array of patch status results")
	summaryMD := fs.Bool("summary-md", false, "output GitHub-Flavored Markdown summary")
	failOnRevertable := fs.Bool("fail-on-revertable", false, "exit with code 2 if any patch can be reverted")
	timeout := fs.Duration("timeout", 15*time.Second, "timeout for checking upstream status")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	patchStore := adapter.NewPatchStore("")
	patches, err := patchStore.List()
	if err != nil {
		fmt.Fprintf(errOut, "error: list patches: %v\n", err)
		return 1
	}
	if len(patches) == 0 {
		if *summaryMD {
			fmt.Fprint(out, "### 🛡️ bugrouter Upstream Patch Audit\n\nNo active temporary dependency patches tracked in ledger.\n")
		} else if *jsonOut {
			fmt.Fprintln(out, "[]")
		} else {
			fmt.Fprintln(out, "No active dependency patches tracked in ledger.")
		}
		return 0
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	if httpClient == nil {
		httpClient = httpx.NewClient(5 * time.Second)
	}
	results, err := adapter.CheckPatchUpstreamStatus(ctx, httpClient, patches)
	if err != nil {
		fmt.Fprintf(errOut, "error: check patches: %v\n", err)
		return 1
	}

	revertableCount := 0
	for _, r := range results {
		if r.CanRevert {
			revertableCount++
		}
	}

	if *summaryMD {
		var sb strings.Builder
		if revertableCount > 0 {
			sb.WriteString(fmt.Sprintf("### ⚠️ bugrouter Upstream Patch Audit: %d Revertable Fork(s) Detected\n\n", revertableCount))
			sb.WriteString("The following tracked dependencies have resolved upstream issues and can be safely reverted:\n\n")
			sb.WriteString("| Dependency | State | Target | Upstream Issue |\n")
			sb.WriteString("| :--- | :--- | :--- | :--- |\n")
			for _, r := range results {
				if r.CanRevert {
					url := r.Patch.UpstreamIssueURL
					if url == "" {
						url = "-"
					}
					sb.WriteString(fmt.Sprintf("| `%s` | **%s** | `%s` | %s |\n",
						escapeMarkdownTableCell(r.Patch.Dependency),
						escapeMarkdownTableCell(r.UpstreamState),
						escapeMarkdownTableCell(r.Patch.PatchTarget),
						url,
					))
				}
			}
			sb.WriteString("\n<details><summary>All Tracked Patches</summary>\n\n")
			sb.WriteString("| Dependency | State | Status | Upstream Issue |\n")
			sb.WriteString("| :--- | :--- | :--- | :--- |\n")
			for _, r := range results {
				status := "Active Fork"
				if r.CanRevert {
					status = "✅ Ready to Revert"
				}
				url := r.Patch.UpstreamIssueURL
				if url == "" {
					url = "-"
				}
				sb.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s |\n",
					escapeMarkdownTableCell(r.Patch.Dependency),
					escapeMarkdownTableCell(r.UpstreamState),
					status,
					url,
				))
			}
			sb.WriteString("\n</details>\n")
		} else {
			sb.WriteString("### ✅ bugrouter Upstream Patch Audit: All Clear\n\nAll tracked dependency patches remain active upstream. No temporary forks are ready for revert.\n\n")
			sb.WriteString("| Dependency | State | Target | Upstream Issue |\n")
			sb.WriteString("| :--- | :--- | :--- | :--- |\n")
			for _, r := range results {
				url := r.Patch.UpstreamIssueURL
				if url == "" {
					url = "-"
				}
				sb.WriteString(fmt.Sprintf("| `%s` | %s | `%s` | %s |\n",
					escapeMarkdownTableCell(r.Patch.Dependency),
					escapeMarkdownTableCell(r.UpstreamState),
					escapeMarkdownTableCell(r.Patch.PatchTarget),
					url,
				))
			}
		}
		fmt.Fprint(out, sb.String())
		if *failOnRevertable && revertableCount > 0 {
			return 2
		}
		return 0
	}

	if *jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fmt.Fprintf(errOut, "error: encode json: %v\n", err)
			return 1
		}
		if *failOnRevertable && revertableCount > 0 {
			return 2
		}
		return 0
	}
	fmt.Fprintf(out, "%-10s %-25s %-12s %-20s %s\n", "ID", "DEPENDENCY", "STATE", "STATUS", "UPSTREAM ISSUE")
	fmt.Fprintln(out, strings.Repeat("-", 95))
	for _, r := range results {
		statusStr := "-"
		if r.CanRevert {
			statusStr = "[READY TO REVERT]"
		} else if r.UpstreamState == "open" {
			statusStr = "Upstream Open"
		} else if r.UpstreamState == "no_url" {
			statusStr = "No Upstream URL"
		} else if r.CheckError != "" {
			statusStr = "Check Error"
		}
		issueURL := r.Patch.UpstreamIssueURL
		if issueURL == "" {
			issueURL = "-"
		}
		fmt.Fprintf(out, "%-10s %-25s %-12s %-20s %s\n", r.Patch.ID, r.Patch.Dependency, r.UpstreamState, statusStr, issueURL)
	}
	if *failOnRevertable && revertableCount > 0 {
		return 2
	}
	return 0
}

func cmdPark(args []string) {
	fs := flag.NewFlagSet("park", flag.ContinueOnError)
	snippet := fs.String("snippet", "", "error snippet or stack trace")
	workaround := fs.String("workaround", "", "how the anomaly was mitigated or worked around")
	file := fs.String("file", "", "workspace file path where anomaly was discovered")
	relatedDep := fs.String("related-dep", "", "secondary/related dependency causing interaction anomaly")
	jsonOut := fs.Bool("json", false, "output JSON handoff payload")

	flagArgs, posArgs := splitInterleavedFlags(args, map[string]bool{
		"snippet":     true,
		"workaround":  true,
		"file":        true,
		"related-dep": true,
	})

	if err := fs.Parse(flagArgs); err != nil {
		os.Exit(1)
	}

	if len(posArgs) < 2 {
		fmt.Fprintln(os.Stderr, "error: park requires <dependency> and <title> arguments")
		fmt.Fprintln(os.Stderr, "Usage: bugrouter park [--snippet <s>] [--workaround <w>] [--file <f>] [--related-dep <pkg>] [--json] <dependency> <title>")
		os.Exit(1)
	}

	dep := posArgs[0]
	title := posArgs[1]

	parkStore := adapter.NewParkedStore("")
	bug, handoff, err := parkStore.Park(dep, title, *snippet, *workaround, *file, *relatedDep)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: park bug: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{
			"parked_bug": bug,
			"handoff":    handoff,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "error: encode json: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Printf("Bug parked successfully in <5ms!\n")
	fmt.Printf("Parked ID:       %s\n", bug.ID)
	fmt.Printf("Dependency:      %s\n", bug.Dependency)
	if bug.RelatedDependency != "" {
		fmt.Printf("Related Dep:     %s\n", bug.RelatedDependency)
	}
	fmt.Printf("Title:           %s\n", bug.Title)
	fmt.Printf("Resource URI:    %s\n", handoff.ResourceURI)
	fmt.Printf("CLI Command:     %s\n\n", handoff.CLICommand)
	fmt.Printf("Spawn Instruction:\n  %s\n\n", handoff.SpawnSessionPrompt)
	fmt.Printf("Patch Instructions:\n  %s\n\n", handoff.PatchInstructions)
	fmt.Println("User Options:")
	for _, opt := range handoff.UserOptions {
		fmt.Printf("  %s\n", opt)
	}
	fmt.Printf("\nDirective:\n  %s\n", handoff.AgentDirective)
}

func cmdParked(args []string) {
	if code := runParked(os.Stdout, os.Stderr, args); code != 0 {
		os.Exit(code)
	}
}

func cmdPatch(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: bugrouter patch <list|add|scan|check|rm> [arguments...]")
		os.Exit(1)
	}
	patchStore := adapter.NewPatchStore("")
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("patch list", flag.ContinueOnError)
		jsonOut := fs.Bool("json", false, "output JSON array")
		if err := fs.Parse(args[1:]); err != nil {
			os.Exit(1)
		}
		patches, err := patchStore.List()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: list patches: %v\n", err)
			os.Exit(1)
		}
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(patches); err != nil {
				fmt.Fprintf(os.Stderr, "error: encode json: %v\n", err)
				os.Exit(1)
			}
			return
		}
		if len(patches) == 0 {
			fmt.Println("No active dependency patches tracked in ledger.")
			return
		}
		fmt.Printf("%-10s %-25s %-10s %-30s %s\n", "ID", "DEPENDENCY", "ECOSYSTEM", "TARGET", "REASON")
		fmt.Println(strings.Repeat("-", 90))
		for _, p := range patches {
			fmt.Printf("%-10s %-25s %-10s %-30s %s\n", p.ID, p.Dependency, p.Ecosystem, p.PatchTarget, p.Reason)
		}
		return

	case "scan":
		var scanArgs []string
		if len(args) > 1 {
			scanArgs = args[1:]
		}
		if code := runPatchScan(patchStore, os.Stdout, os.Stderr, scanArgs); code != 0 {
			os.Exit(code)
		}
		return

	case "check":
		var checkArgs []string
		if len(args) > 1 {
			checkArgs = args[1:]
		}
		if code := runPatchCheck(context.Background(), nil, os.Stdout, os.Stderr, checkArgs); code != 0 {
			os.Exit(code)
		}
		return

	case "add":
		fs := flag.NewFlagSet("patch add", flag.ContinueOnError)
		dep := fs.String("dep", "", "dependency name (required)")
		target := fs.String("target", "", "fork repository URL, branch, or patch file (required)")
		ecosystem := fs.String("ecosystem", "", "ecosystem identifier (go, npm, cargo, python, custom)")
		manifest := fs.String("manifest", "", "manifest file (e.g. go.mod, package.json)")
		issue := fs.String("issue", "", "upstream issue URL being tracked")
		reason := fs.String("reason", "", "reason for patching locally")
		if err := fs.Parse(args[1:]); err != nil {
			os.Exit(1)
		}
		if strings.TrimSpace(*dep) == "" || strings.TrimSpace(*target) == "" {
			fmt.Fprintln(os.Stderr, "error: patch add requires --dep and --target")
			fmt.Fprintln(os.Stderr, "Usage: bugrouter patch add --dep <d> --target <fork> [--ecosystem <e>] [--issue <url>] [--manifest <m>] [--reason <r>]")
			os.Exit(1)
		}
		r := strings.TrimSpace(*reason)
		if r == "" {
			r = "Local patch tracked in bugrouter ledger"
		}
		patch, err := patchStore.Record(*dep, *ecosystem, *target, *manifest, *issue, r)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: record patch: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Recorded dependency patch %s for %s (%s) in patch ledger.\n", patch.ID, patch.Dependency, patch.PatchTarget)
		return

	case "rm":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "error: patch rm requires <id-or-dep>")
			fmt.Fprintln(os.Stderr, "Usage: bugrouter patch rm <id-or-dep>")
			os.Exit(1)
		}
		target := args[1]
		if err := patchStore.Remove(target); err != nil {
			fmt.Fprintf(os.Stderr, "error: remove patch: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Removed patch %q from patch ledger.\n", target)
		return

	default:
		fmt.Fprintf(os.Stderr, "error: unknown patch subcommand %q\n", args[0])
		fmt.Fprintln(os.Stderr, "Usage: bugrouter patch <list|add|scan|check|rm> [arguments...]")
		os.Exit(1)
	}
}
