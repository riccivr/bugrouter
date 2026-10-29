package verifier

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestVerifyEmptyCommand(t *testing.T) {
	_, err := Verify(context.Background(), VerifyOptions{Command: "   "})
	if err == nil {
		t.Fatal("expected error for empty command, got nil")
	}
}

func TestVerifyFailingCommandWithStackTrace(t *testing.T) {
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = `echo ghp_supersecret1234567890abcdef && echo panic: runtime error && echo goroutine 1 [running]: && echo github.com/example/worker.ProcessItems(0xc000088000) && echo /home/user/go/src/github.com/example/worker/worker.go:42 +0x26 && exit 1`
	} else {
		cmd = `echo "ghp_supersecret1234567890abcdef"; echo "panic: runtime error"; echo "goroutine 1 [running]:"; echo "github.com/example/worker.ProcessItems(0xc000088000)"; echo "/home/user/go/src/github.com/example/worker/worker.go:42 +0x26"; exit 1`
	}

	proof, err := Verify(context.Background(), VerifyOptions{Command: cmd})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !proof.Reproduced {
		t.Errorf("expected Reproduced=true, got false")
	}
	if proof.ExitCode != 1 {
		t.Errorf("expected ExitCode=1, got %d", proof.ExitCode)
	}
	if proof.TimedOut {
		t.Errorf("expected TimedOut=false, got true")
	}
	if proof.ProofDigest == "" {
		t.Errorf("expected non-empty ProofDigest")
	}
	if strings.Contains(string(proof.ScrubbedOutput), "ghp_supersecret") {
		t.Errorf("expected secret to be redacted from output: %s", proof.ScrubbedOutput)
	}
	if len(proof.Candidates) == 0 {
		t.Errorf("expected candidates extracted from stack trace, got none")
	} else if proof.Candidates[0].Query != "github.com/example/worker" {
		t.Errorf("expected top candidate github.com/example/worker, got %s", proof.Candidates[0].Query)
	}
}

func TestVerifyPassingCommand(t *testing.T) {
	cmd := "echo ok"
	proof, err := Verify(context.Background(), VerifyOptions{Command: cmd})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if proof.Reproduced {
		t.Errorf("expected Reproduced=false for exit 0, got true")
	}
	if proof.ExitCode != 0 {
		t.Errorf("expected ExitCode=0, got %d", proof.ExitCode)
	}
	if proof.TimedOut {
		t.Errorf("expected TimedOut=false, got true")
	}
}

func TestVerifyExpectedExitCode(t *testing.T) {
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "exit /b 42"
	} else {
		cmd = "exit 42"
	}

	// 1. Matches expected exit code
	proof, err := Verify(context.Background(), VerifyOptions{
		Command:    cmd,
		ExpectExit: 42,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !proof.Reproduced {
		t.Errorf("expected Reproduced=true for matching ExpectExit 42, got false")
	}
	if proof.ExitCode != 42 {
		t.Errorf("expected ExitCode=42, got %d", proof.ExitCode)
	}

	// 2. Does not match expected exit code
	proof2, err := Verify(context.Background(), VerifyOptions{
		Command:    cmd,
		ExpectExit: 99,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proof2.Reproduced {
		t.Errorf("expected Reproduced=false when ExitCode (42) != ExpectExit (99)")
	}
}

func TestVerifyTimeout(t *testing.T) {
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "ping -n 3 127.0.0.1 > nul"
	} else {
		cmd = "sleep 1"
	}

	proof, err := Verify(context.Background(), VerifyOptions{
		Command: cmd,
		Timeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !proof.TimedOut {
		t.Errorf("expected TimedOut=true, got false")
	}
	if !proof.Reproduced {
		t.Errorf("expected Reproduced=true on timeout, got false")
	}
	if proof.ExitCode != -1 {
		t.Errorf("expected ExitCode=-1 on timeout, got %d", proof.ExitCode)
	}
}

func TestBoundedBufferOverflow(t *testing.T) {
	buf := &boundedBuffer{cap: 10}
	n, err := buf.Write([]byte("hello world long string"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != len("hello world long string") {
		t.Errorf("expected full length reported written, got %d", n)
	}
	if buf.String() != "hello worl" {
		t.Errorf("expected capped string 'hello worl', got %q", buf.String())
	}
}
