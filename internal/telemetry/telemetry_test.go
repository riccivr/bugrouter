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
		OS:                 "linux",
		Arch:               "amd64",
		KernelVersion:      "6.6.0-generic",
		CPUModel:           "AMD Ryzen 9 5900X",
		NumCPU:             12,
		GPUModels:          []string{"NVIDIA GeForce RTX 3080", "Intel UHD Graphics 770"},
		DriverVersion:      "550.54.14",
		DesktopEnvironment: "GNOME",
		DisplayServer:      "wayland",
	}

	md := FormatMarkdown(sample)
	expectedLines := []string{
		"- **OS**: linux (amd64)",
		"- **Kernel**: 6.6.0-generic",
		"- **CPU**: AMD Ryzen 9 5900X (12 cores)",
		"- **GPU**: NVIDIA GeForce RTX 3080, Intel UHD Graphics 770",
		"- **Driver Version**: 550.54.14",
		"- **Desktop**: GNOME",
		"- **Display Server**: wayland",
	}

	for _, line := range expectedLines {
		if !strings.Contains(md, line) {
			t.Errorf("expected markdown to contain %q, got:\n%s", line, md)
		}
	}
}

func TestFormatMarkdownBackwardCompatibility(t *testing.T) {
	sample := SystemTelemetry{
		OS:            "linux",
		Arch:          "amd64",
		KernelVersion: "6.6.0-generic",
		CPUModel:      "AMD Ryzen 9 5900X",
		NumCPU:        12,
		GPUs:          []string{"NVIDIA GeForce RTX 3080"},
		DesktopEnv:    "GNOME",
		DisplayServer: "wayland",
	}

	md := FormatMarkdown(sample)
	if !strings.Contains(md, "- **GPU**: NVIDIA GeForce RTX 3080") {
		t.Errorf("expected legacy GPUs to render under GPU: %s", md)
	}
	if !strings.Contains(md, "- **Desktop**: GNOME") {
		t.Errorf("expected legacy DesktopEnv to render under Desktop: %s", md)
	}
}

func TestTelemetryScrubbing(t *testing.T) {
	t.Setenv("XDG_CURRENT_DESKTOP", "GNOME /home/alice/secret")
	telemetry := Collect(context.Background())
	if strings.Contains(telemetry.DesktopEnv, "/home/alice") {
		t.Errorf("user path leaked in DesktopEnv: %s", telemetry.DesktopEnv)
	}
	if strings.Contains(telemetry.DesktopEnvironment, "/home/alice") {
		t.Errorf("user path leaked in DesktopEnvironment: %s", telemetry.DesktopEnvironment)
	}
}

func TestParseLspci(t *testing.T) {
	sample := `00:00.0 Host bridge: Intel Corporation 12th Gen Core Processor Host Bridge/DRAM Registers (rev 02)
00:02.0 VGA compatible controller: Intel Corporation Alder Lake-S GT1 [UHD Graphics 770] (rev 0c)
01:00.0 VGA compatible controller: NVIDIA Corporation GA102 [GeForce RTX 3080] (rev a1)
01:00.1 Audio device: NVIDIA Corporation GA102 High Definition Audio Controller (rev a1)`

	gpus := parseLspci(sample)
	if len(gpus) != 2 {
		t.Fatalf("expected 2 GPUs, got %d: %v", len(gpus), gpus)
	}
	if !strings.Contains(gpus[0], "UHD Graphics 770") {
		t.Errorf("expected first GPU UHD Graphics 770, got: %s", gpus[0])
	}
	if !strings.Contains(gpus[1], "GeForce RTX 3080") {
		t.Errorf("expected second GPU GeForce RTX 3080, got: %s", gpus[1])
	}
}

func TestParseDarwinDisplays(t *testing.T) {
	sample := `Graphics/Displays:

    Apple M1 Max:

      Chipset Model: Apple M1 Max
      Type: GPU
      Bus: Built-In
      Total Number of Cores: 32
      Vendor: Apple (0x106b)
      Metal Support: Metal 3

    AMD Radeon Pro 5500M:

      Chipset Model: AMD Radeon Pro 5500M
      Type: PCIe
      Slot: Slot-1
      PCIe Lane Width: x16
      VRAM (Total): 8 GB
      Vendor: AMD (0x1002)
      Device ID: 0x7340
      Revision ID: 0x0040
      ROM Revision: 113-D3220E-190
      EFI Driver Version: 01.01.200
      Metal Support: Metal 3`

	gpus, driverVersion := parseDarwinDisplays(sample)
	if len(gpus) != 2 {
		t.Fatalf("expected 2 GPUs, got %d: %v", len(gpus), gpus)
	}
	if gpus[0] != "Apple M1 Max" {
		t.Errorf("gpu[0] = %q, want 'Apple M1 Max'", gpus[0])
	}
	if gpus[1] != "AMD Radeon Pro 5500M" {
		t.Errorf("gpu[1] = %q, want 'AMD Radeon Pro 5500M'", gpus[1])
	}
	if driverVersion != "01.01.200" && driverVersion != "Metal 3" {
		t.Errorf("unexpected driverVersion: %s", driverVersion)
	}
}

func TestParseWindowsVideoControllerCSV(t *testing.T) {
	sample := `"Name","DriverVersion"
"NVIDIA GeForce RTX 4070 Ti","32.0.16.1714"
"AMD Radeon(TM) Graphics","32.0.11024.2"`

	gpus, driverVersion := parseWindowsVideoController(sample)
	if len(gpus) != 2 {
		t.Fatalf("expected 2 GPUs, got %d: %v", len(gpus), gpus)
	}
	if gpus[0] != "NVIDIA GeForce RTX 4070 Ti" {
		t.Errorf("gpu[0] = %q, want 'NVIDIA GeForce RTX 4070 Ti'", gpus[0])
	}
	if gpus[1] != "AMD Radeon(TM) Graphics" {
		t.Errorf("gpu[1] = %q, want 'AMD Radeon(TM) Graphics'", gpus[1])
	}
	if !strings.Contains(driverVersion, "32.0.16.1714") {
		t.Errorf("expected driverVersion to contain 32.0.16.1714, got: %s", driverVersion)
	}
}

func TestParseWindowsVideoControllerTable(t *testing.T) {
	sample := `DriverVersion  Name
32.0.16.1714   NVIDIA GeForce RTX 4070 Ti
32.0.11024.2   AMD Radeon(TM) Graphics
`

	gpus, driverVersion := parseWindowsVideoController(sample)
	if len(gpus) != 2 {
		t.Fatalf("expected 2 GPUs, got %d: %v", len(gpus), gpus)
	}
	if gpus[0] != "NVIDIA GeForce RTX 4070 Ti" {
		t.Errorf("gpu[0] = %q, want 'NVIDIA GeForce RTX 4070 Ti'", gpus[0])
	}
	if gpus[1] != "AMD Radeon(TM) Graphics" {
		t.Errorf("gpu[1] = %q, want 'AMD Radeon(TM) Graphics'", gpus[1])
	}
	if !strings.Contains(driverVersion, "32.0.16.1714") {
		t.Errorf("expected driverVersion to contain 32.0.16.1714, got: %s", driverVersion)
	}
}

func TestParseLinuxNvidiaVersion(t *testing.T) {
	sample := "NVRM version: NVIDIA UNIX x86_64 Kernel Module  550.54.14  Sun Feb 25 18:32:04 UTC 2024"
	v := parseLinuxNvidiaVersion(sample)
	if v != "550.54.14" {
		t.Errorf("version = %q, want '550.54.14'", v)
	}
}

func TestParsePciUevent(t *testing.T) {
	sample := `DRIVER=dxgkrnl
PCI_CLASS=30200
PCI_ID=1414:008E
PCI_SLOT_NAME=6900:00:00.0`

	pciClass, driver := parsePciUevent(sample)
	if pciClass != "30200" {
		t.Errorf("pciClass = %q, want '30200'", pciClass)
	}
	if driver != "dxgkrnl" {
		t.Errorf("driver = %q, want 'dxgkrnl'", driver)
	}
	if !isDisplayPciClass(pciClass) {
		t.Error("expected isDisplayPciClass to be true for 30200")
	}
}

func TestExtractDriverName(t *testing.T) {
	if d := extractDriverName("card0 (amdgpu driver)"); d != "amdgpu" {
		t.Errorf("got %q, want 'amdgpu'", d)
	}
	if d := extractDriverName("PCI 6900:00:00.0 (dxgkrnl)"); d != "dxgkrnl" {
		t.Errorf("got %q, want 'dxgkrnl'", d)
	}
}
