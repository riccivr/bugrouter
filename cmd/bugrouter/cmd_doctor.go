package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/cloud"
	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/scrubber"
)

// LocalPaths contains resolved local storage directories and file paths.
type LocalPaths struct {
	DraftsDir    string `json:"drafts_dir"`
	ParkedDir    string `json:"parked_dir"`
	PatchesFile  string `json:"patches_file"`
	ServicesFile string `json:"services_file"`
	CacheDir     string `json:"cache_dir"`
	AuditLog     string `json:"audit_log"`
}

func defaultCacheDir() string {
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "bugrouter", "targets")
	}
	if userCache, err := os.UserCacheDir(); err == nil && userCache != "" {
		return filepath.Join(userCache, "bugrouter", "targets")
	}
	return filepath.Join(os.TempDir(), "bugrouter", "targets")
}

// resolveLocalPaths queries each store/resolver subsystem for its canonical path.
func resolveLocalPaths() LocalPaths {
	return LocalPaths{
		DraftsDir:    adapter.NewDraftStore("").Dir(),
		ParkedDir:    adapter.NewParkedStore("").Dir(),
		PatchesFile:  adapter.NewPatchStore("").Path(),
		ServicesFile: resolver.ResolveOrgCloudConfigPath(),
		CacheDir:     defaultCacheDir(),
		AuditLog:     cloud.NewAuditLogger("").Path(),
	}
}

func runPaths(out, errOut io.Writer, args []string) int {
	fs := flag.NewFlagSet("paths", flag.ContinueOnError)
	fs.SetOutput(errOut)
	jsonOut := fs.Bool("json", false, "output structured JSON")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	paths := resolveLocalPaths()

	if *jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(paths); err != nil {
			fmt.Fprintf(errOut, "error: encode json: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Fprintf(out, "%-15s %s\n", "drafts_dir:", paths.DraftsDir)
	fmt.Fprintf(out, "%-15s %s\n", "parked_dir:", paths.ParkedDir)
	fmt.Fprintf(out, "%-15s %s\n", "patches_file:", paths.PatchesFile)
	fmt.Fprintf(out, "%-15s %s\n", "services_file:", paths.ServicesFile)
	fmt.Fprintf(out, "%-15s %s\n", "cache_dir:", paths.CacheDir)
	fmt.Fprintf(out, "%-15s %s\n", "audit_log:", paths.AuditLog)
	return 0
}

func cmdPaths(args []string) {
	if code := runPaths(os.Stdout, os.Stderr, args); code != 0 {
		os.Exit(code)
	}
}

// SelfTestResult encapsulates the health verification status of offline subsystems.
type SelfTestResult struct {
	Status         string `json:"status"`
	SelfResolution string `json:"self_resolution"`
	Scrubber       string `json:"scrubber"`
}

func runSelfTest(out, errOut io.Writer, args []string) int {
	fs := flag.NewFlagSet("self-test", flag.ContinueOnError)
	fs.SetOutput(errOut)
	jsonOut := fs.Bool("json", false, "output structured JSON")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	target, resolveErr := resolveTarget(ctx, nil, "bugrouter", true)
	selfResolutionPass := resolveErr == nil && target != nil && target.CanonicalName == "bugrouter"

	rawSecret := "AWS_KEY=AKIAIOSFODNN7EXAMPLE GITHUB_TOKEN=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345"
	scrubbed := string(scrubber.Scrub(rawSecret))
	scrubberPass := strings.Contains(scrubbed, "[REDACTED_AWS_KEY]") &&
		strings.Contains(scrubbed, "[REDACTED_GITHUB_TOKEN]") &&
		!strings.Contains(scrubbed, "AKIAIOSFODNN7EXAMPLE") &&
		!strings.Contains(scrubbed, "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345")

	allPassed := selfResolutionPass && scrubberPass

	if *jsonOut {
		status := "ok"
		if !allPassed {
			status = "fail"
		}
		resString := "pass"
		if !selfResolutionPass {
			resString = "fail"
		}
		scrubString := "pass"
		if !scrubberPass {
			scrubString = "fail"
		}
		res := SelfTestResult{
			Status:         status,
			SelfResolution: resString,
			Scrubber:       scrubString,
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(errOut, "error: encode json: %v\n", err)
			return 1
		}
		if !allPassed {
			return 1
		}
		return 0
	}

	if selfResolutionPass {
		fmt.Fprintln(out, "Self-Resolution: PASS")
	} else {
		fmt.Fprintf(errOut, "Self-Resolution: FAIL (error: %v)\n", resolveErr)
	}

	if scrubberPass {
		fmt.Fprintln(out, "Scrubber Redaction: PASS")
	} else {
		fmt.Fprintln(errOut, "Scrubber Redaction: FAIL")
	}

	if allPassed {
		fmt.Fprintln(out, "Self-Test: OK")
		return 0
	}

	fmt.Fprintln(errOut, "Self-Test: FAILED")
	return 1
}

func cmdSelfTest(args []string) {
	if code := runSelfTest(os.Stdout, os.Stderr, args); code != 0 {
		os.Exit(code)
	}
}
