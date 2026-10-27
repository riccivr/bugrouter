package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/version"
)

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
		fmt.Fprintln(os.Stderr, "mcp server mode: awaiting task spec #04")
		return

	case "resolve":
		fs := flag.NewFlagSet("resolve", flag.ContinueOnError)
		jsonOut := fs.Bool("json", false, "output structured JSON")
		if err := fs.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}

		args := fs.Args()
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "error: resolve requires a target query")
			os.Exit(1)
		}

		wf := resolver.NewWaterfall(0)
		target, err := wf.Resolve(context.Background(), args[0])
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
		fmt.Printf("Layer:          %s\n", target.Layer)
		fmt.Printf("Protocol:       %s\n", target.Tracker.Protocol)
		if target.Tracker.URL != "" {
			fmt.Printf("Tracker URL:    %s\n", target.Tracker.URL)
		}
		if target.Tracker.Email != "" {
			fmt.Printf("Tracker Email:  %s\n", target.Tracker.Email)
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
	fmt.Fprintln(os.Stderr, "  version              Print version information")
	fmt.Fprintln(os.Stderr, "  resolve [--json] <q> Resolve software target to bug tracker")
	fmt.Fprintln(os.Stderr, "  mcp                  Start MCP server")
}
