package telemetry

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCollectSystemTelemetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	telemetry := Collect(ctx)
	if telemetry.OS == "" {
		t.Error("expected non-empty OS")
	}
	if telemetry.Arch == "" {
		t.Error("expected non-empty Arch")
	}
	if telemetry.NumCPU <= 0 {
		t.Errorf("expected NumCPU > 0, got %d", telemetry.NumCPU)
	}

	md := FormatMarkdown(telemetry)
	if !strings.Contains(md, "- **OS**:") {
		t.Errorf("expected markdown to contain '- **OS**:', got:\n%s", md)
	}
}

func TestFormatMarkdown(t *testing.T) {
	sample := SystemTelemetry{
		OS:            "linux",
		Arch:          "amd64",
		KernelVersion: "6.6.0-generic",
		CPUModel:      "AMD Ryzen 9 5900X",
		NumCPU:        12,
		GPUs:          []string{"NVIDIA GeForce RTX 3080", "Intel UHD Graphics 770"},
		DesktopEnv:    "GNOME",
		DisplayServer: "wayland",
	}

	md := FormatMarkdown(sample)
	expectedLines := []string{
		"- **OS**: linux (amd64)",
		"- **Kernel**: 6.6.0-generic",
		"- **CPU**: AMD Ryzen 9 5900X (12 cores)",
		"- **GPU**: NVIDIA GeForce RTX 3080, Intel UHD Graphics 770",
		"- **Desktop**: GNOME",
		"- **Display Server**: wayland",
	}

	for _, line := range expectedLines {
		if !strings.Contains(md, line) {
			t.Errorf("expected markdown to contain %q, got:\n%s", line, md)
		}
	}
}

func TestTelemetryScrubbing(t *testing.T) {
	// Verify that if a path or secret appears, Collect scrubs it
	t.Setenv("XDG_CURRENT_DESKTOP", "GNOME /home/alice/secret")
	telemetry := Collect(context.Background())
	if strings.Contains(telemetry.DesktopEnv, "/home/alice") {
		t.Errorf("user path leaked in DesktopEnv: %s", telemetry.DesktopEnv)
	}
}
