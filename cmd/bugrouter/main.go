package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/cache"
	"github.com/riccivr/bugrouter/internal/httpx"
	"github.com/riccivr/bugrouter/internal/mcp"
	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/version"
)

func resolveTarget(query string, noCache bool) (*resolver.Target, error) {
	var store *cache.Store
	if !noCache {
		store = cache.NewStore("", 0)
		var cached resolver.Target
		hit, err := store.Get(query, &cached)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: cache read failed: %v\n", err)
		} else if hit {
			return &cached, nil
		}
	}

	httpClient := httpx.NewClient(0)
	wf := resolver.NewWaterfall(
		0,
		resolver.NewDirectProbe(),
		resolver.NewWorkspaceProbe("."),
		resolver.NewOSPackageProbe(),
		resolver.NewRegistryProbe(httpClient, resolver.DefaultRegistryEndpoints()),
		resolver.NewWebDomainProbe(httpClient),
	)
	resolved, err := wf.Resolve(context.Background(), query)
	if err != nil {
		return nil, err
	}

	if !noCache && store != nil {
		if err := store.Put(query, resolved); err != nil {
			fmt.Fprintf(os.Stderr, "warning: cache write failed: %v\n", err)
		}
	}

	return resolved, nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version", "--version", "-version", "-v":
		fmt.Printf("bugrouter %s\n", version.Version)
		return

	case "mcp":
		httpClient := httpx.NewClient(0)
		wf := resolver.NewWaterfall(
			0,
			resolver.NewDirectProbe(),
			resolver.NewWorkspaceProbe("."),
			resolver.NewOSPackageProbe(),
			resolver.NewRegistryProbe(httpClient, resolver.DefaultRegistryEndpoints()),
			resolver.NewWebDomainProbe(httpClient),
		)
		store := adapter.NewDraftStore("")
		srv := mcp.NewServer(wf, store)
		if err := srv.Run(context.Background(), os.Stdin, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "mcp server error: %v\n", err)
			os.Exit(1)
		}
		return

	case "resolve":
		fs := flag.NewFlagSet("resolve", flag.ContinueOnError)
		jsonOut := fs.Bool("json", false, "output structured JSON")
		noCache := fs.Bool("no-cache", false, "disable disk cache")
		if err := fs.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}

		args := fs.Args()
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "error: resolve requires a target query")
			os.Exit(1)
		}

		target, err := resolveTarget(args[0], *noCache)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(target); err != nil {
				fmt.Fprintf(os.Stderr, "encode json: %v\n", err)
				os.Exit(1)
			}
			return
		}

		fmt.Printf("Canonical Name: %s\n", target.CanonicalName)
		if target.LocalVersion != "" {
			fmt.Printf("Local Version:  %s\n", target.LocalVersion)
		}
		fmt.Printf("Layer:          %s\n", target.Layer)
		fmt.Printf("Protocol:       %s\n", target.Tracker.Protocol)
		if target.Tracker.URL != "" {
			fmt.Printf("Tracker URL:    %s\n", target.Tracker.URL)
		}
		if target.Tracker.Email != "" {
			fmt.Printf("Tracker Email:  %s\n", target.Tracker.Email)
		}

	case "draft":
		fs := flag.NewFlagSet("draft", flag.ContinueOnError)
		title := fs.String("title", "", "bug report title")
		summary := fs.String("summary", "", "summary of the issue")
		steps := fs.String("steps", "", "steps to reproduce")
		logs := fs.String("logs", "", "error logs or console output")
		jsonOut := fs.Bool("json", false, "output structured JSON")
		noCache := fs.Bool("no-cache", false, "disable disk cache")
		if err := fs.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}

		args := fs.Args()
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "error: draft requires a target query")
			os.Exit(1)
		}
		if strings.TrimSpace(*title) == "" {
			fmt.Fprintln(os.Stderr, "error: --title is required")
			os.Exit(1)
		}

		target, err := resolveTarget(args[0], *noCache)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		draft, err := adapter.BuildDraft(adapter.DraftInput{
			Target:           *target,
			Title:            *title,
			Summary:          *summary,
			StepsToReproduce: *steps,
			Logs:             *logs,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: build draft: %v\n", err)
			os.Exit(1)
		}

		draftStore := adapter.NewDraftStore("")
		savedPath, err := draftStore.Save(draft)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: save draft: %v\n", err)
			os.Exit(1)
		}

		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(draft); err != nil {
				fmt.Fprintf(os.Stderr, "encode json: %v\n", err)
				os.Exit(1)
			}
			return
		}

		fmt.Printf("Draft ID:       %s\n", draft.ID)
		fmt.Printf("Staged Path:    %s\n", savedPath)
		fmt.Printf("Target:         %s\n", draft.Target.CanonicalName)
		fmt.Printf("Title:          %s\n", draft.Title)
		if draft.SubmissionURL != "" {
			fmt.Printf("Submission URL: %s\n", draft.SubmissionURL)
		}
		if draft.DebbugsEmail != "" {
			fmt.Printf("\n--- Debbugs Email ---\n%s\n", draft.DebbugsEmail)
		}

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: bugrouter <command> [arguments]")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  version                     Print version information")
	fmt.Fprintln(os.Stderr, "  resolve [--json] [--no-cache] <q> Resolve software target to bug tracker")
	fmt.Fprintln(os.Stderr, "  draft [--title <t>] [--summary <s>] [--steps <st>] [--logs <l>] [--json] <q>")
	fmt.Fprintln(os.Stderr, "                              Stage bug report draft and generate submission URLs")
	fmt.Fprintln(os.Stderr, "  mcp                         Start Model Context Protocol (MCP) stdio server")
}
