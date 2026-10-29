package verifier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/scrubber"
)

// maxVerifyOutputBytes caps captured stdout/stderr to avoid memory exhaustion or buffer bloat.
const maxVerifyOutputBytes = 256 * 1024

// VerifyOptions configures a bounded reproduction run.
type VerifyOptions struct {
	Command    string        // Command string executed via sh -c (or cmd /C on Windows)
	WorkDir    string        // Optional working directory
	Timeout    time.Duration // Default: 15 * time.Second
	ExpectExit int           // Optional expected exit code; if 0, any non-zero exit code is considered reproduced
}

// VerificationProof records deterministic evidence from a bounded reproduction run.
type VerificationProof struct {
	Command        string                    `json:"command"`
	Reproduced     bool                      `json:"reproduced"`
	ExitCode       int                       `json:"exit_code"`
	TimedOut       bool                      `json:"timed_out,omitempty"`
	DurationMs     int64                     `json:"duration_ms"`
	ScrubbedOutput scrubber.ScrubbedText     `json:"scrubbed_output"`
	Candidates     []resolver.TraceCandidate `json:"candidates,omitempty"`
	ProofDigest    string                    `json:"proof_digest"` // SHA-256 hex of Command + ExitCode + ScrubbedOutput
	VerifiedAt     time.Time                 `json:"verified_at"`
}

// boundedBuffer is a thread-safe byte buffer capped at a fixed maximum capacity.
type boundedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	cap int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf.Len() >= b.cap {
		// Discard overflow bytes while reporting success to prevent broken pipe errors.
		return len(p), nil
	}
	rem := b.cap - b.buf.Len()
	if len(p) > rem {
		if _, err := b.buf.Write(p[:rem]); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Verify executes a bounded reproduction command, captures/scrubs output, extracts faulting
// package candidates, and returns a deterministic VerificationProof.
func Verify(ctx context.Context, opts VerifyOptions) (*VerificationProof, error) {
	trimmedCmd := strings.TrimSpace(opts.Command)
	if trimmedCmd == "" {
		return nil, errors.New("command cannot be empty")
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(runCtx, "cmd", "/C", trimmedCmd)
	} else {
		cmd = exec.CommandContext(runCtx, "sh", "-c", trimmedCmd)
	}

	if strings.TrimSpace(opts.WorkDir) != "" {
		cmd.Dir = opts.WorkDir
	}

	outBuf := &boundedBuffer{cap: maxVerifyOutputBytes}
	cmd.Stdout = outBuf
	cmd.Stderr = outBuf

	start := time.Now()
	err := cmd.Run()
	durationMs := time.Since(start).Milliseconds()

	var (
		exitCode int
		timedOut bool
	)

	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		timedOut = true
		exitCode = -1
	} else if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("execute command: %w", err)
		}
	} else {
		exitCode = 0
	}

	var reproduced bool
	if opts.ExpectExit != 0 {
		reproduced = (exitCode == opts.ExpectExit)
	} else {
		reproduced = (exitCode != 0 || timedOut)
	}

	rawOutput := outBuf.String()
	scrubbedCmd := string(scrubber.Scrub(trimmedCmd))
	scrubbedOutput := scrubber.Scrub(rawOutput)

	candidates := resolver.ExtractTargetsFromLog(rawOutput)

	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s\n%d\n%s", scrubbedCmd, exitCode, scrubbedOutput)))
	proofDigest := hex.EncodeToString(h.Sum(nil))

	return &VerificationProof{
		Command:        scrubbedCmd,
		Reproduced:     reproduced,
		ExitCode:       exitCode,
		TimedOut:       timedOut,
		DurationMs:     durationMs,
		ScrubbedOutput: scrubbedOutput,
		Candidates:     candidates,
		ProofDigest:    proofDigest,
		VerifiedAt:     time.Now().UTC(),
	}, nil
}
