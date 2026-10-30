package telemetry

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/riccivr/bugrouter/internal/scrubber"
)

// SystemTelemetry captures operating system and hardware diagnostics.
type SystemTelemetry struct {
	OS                 string   `json:"os"`
	Arch               string   `json:"arch"`
	KernelVersion      string   `json:"kernel_version,omitempty"`
	CPUModel           string   `json:"cpu_model,omitempty"`
	NumCPU             int      `json:"num_cpu"`
	GPUs               []string `json:"gpus,omitempty"`
	GPUModels          []string `json:"gpu_models,omitempty"`
	DesktopEnv         string   `json:"desktop_env,omitempty"`
	DesktopEnvironment string   `json:"desktop_environment,omitempty"`
	DisplayServer      string   `json:"display_server,omitempty"`
	DriverVersion      string   `json:"driver_version,omitempty"`
}

// runBoundedCmd executes a subprocess under bounded context, capping output to 64 KiB.
func runBoundedCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("create stdout pipe for %s: %w", name, err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start command %s: %w", name, err)
	}

	const maxOutput = 64 * 1024
	lr := io.LimitReader(stdout, maxOutput+1)
	out, readErr := io.ReadAll(lr)
	if readErr != nil {
		if cmd.Process != nil {
			if killErr := cmd.Process.Kill(); killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
				// Non-fatal if process already exited.
			}
		}
		if waitErr := cmd.Wait(); waitErr != nil {
			// Drain exit state.
		}
		return nil, fmt.Errorf("read stdout from %s: %w", name, readErr)
	}
	if int64(len(out)) > maxOutput {
		if cmd.Process != nil {
			if killErr := cmd.Process.Kill(); killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
				// Non-fatal if process already exited.
			}
		}
		if waitErr := cmd.Wait(); waitErr != nil {
			// Drain exit state.
		}
		return nil, fmt.Errorf("output from %s exceeded %d bytes limit", name, maxOutput)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("wait for %s: %w", name, err)
	}

	scrubbed := scrubber.Scrub(string(out))
	return []byte(scrubbed), nil
}

// Collect gathers hardware, operating system, and display telemetry under bounded timeout.
func Collect(ctx context.Context) SystemTelemetry {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	t := SystemTelemetry{
		OS:     runtime.GOOS,
		Arch:   runtime.GOARCH,
		NumCPU: runtime.NumCPU(),
	}

	switch runtime.GOOS {
	case "linux":
		collectLinux(ctx, &t)
	case "darwin":
		collectDarwin(ctx, &t)
	case "windows":
		collectWindows(ctx, &t)
	default:
		collectGeneric(ctx, &t)
	}

	// Mirror GPU and Desktop fields for backward compatibility
	if len(t.GPUModels) > 0 && len(t.GPUs) == 0 {
		t.GPUs = make([]string, len(t.GPUModels))
		copy(t.GPUs, t.GPUModels)
	} else if len(t.GPUs) > 0 && len(t.GPUModels) == 0 {
		t.GPUModels = make([]string, len(t.GPUs))
		copy(t.GPUModels, t.GPUs)
	}
	if t.DesktopEnvironment != "" && t.DesktopEnv == "" {
		t.DesktopEnv = t.DesktopEnvironment
	} else if t.DesktopEnv != "" && t.DesktopEnvironment == "" {
		t.DesktopEnvironment = t.DesktopEnv
	}

	// Sanitize all collected strings through scrubber
	t.KernelVersion = strings.TrimSpace(string(scrubber.Scrub(t.KernelVersion)))
	t.CPUModel = strings.TrimSpace(string(scrubber.Scrub(t.CPUModel)))
	t.DesktopEnv = strings.TrimSpace(string(scrubber.Scrub(t.DesktopEnv)))
	t.DesktopEnvironment = strings.TrimSpace(string(scrubber.Scrub(t.DesktopEnvironment)))
	t.DisplayServer = strings.TrimSpace(string(scrubber.Scrub(t.DisplayServer)))
	t.DriverVersion = strings.TrimSpace(string(scrubber.Scrub(t.DriverVersion)))
	for i := range t.GPUs {
		t.GPUs[i] = strings.TrimSpace(string(scrubber.Scrub(t.GPUs[i])))
	}
	for i := range t.GPUModels {
		t.GPUModels[i] = strings.TrimSpace(string(scrubber.Scrub(t.GPUModels[i])))
	}

	return t
}

func collectLinux(ctx context.Context, t *SystemTelemetry) {
	// 1. Kernel version
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		t.KernelVersion = strings.TrimSpace(string(data))
	} else if out, err := runBoundedCmd(ctx, "uname", "-r"); err == nil {
		t.KernelVersion = strings.TrimSpace(string(out))
	}

	// 2. CPU Model
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "model name") || strings.HasPrefix(line, "Hardware") || strings.HasPrefix(line, "Processor") {
				if _, val, ok := strings.Cut(line, ":"); ok {
					t.CPUModel = strings.TrimSpace(val)
					break
				}
			}
		}
	}

	// 3. Desktop Environment & Session
	t.DesktopEnvironment = os.Getenv("XDG_CURRENT_DESKTOP")
	if t.DesktopEnvironment == "" {
		t.DesktopEnvironment = os.Getenv("DESKTOP_SESSION")
	}

	// 4. Display Server
	ds := strings.ToLower(os.Getenv("XDG_SESSION_TYPE"))
	if ds == "wayland" || ds == "x11" {
		t.DisplayServer = ds
	}
	if t.DisplayServer == "" {
		if os.Getenv("WAYLAND_DISPLAY") != "" {
			t.DisplayServer = "wayland"
		} else if os.Getenv("DISPLAY") != "" {
			t.DisplayServer = "x11"
		} else if ds != "" {
			t.DisplayServer = ds
		}
	}

	// 5. GPUs via lspci
	if out, err := runBoundedCmd(ctx, "lspci"); err == nil {
		t.GPUModels = parseLspci(string(out))
	}

	// Fallback to /sys/class/drm if no GPUs found from lspci
	if len(t.GPUModels) == 0 {
		if entries, err := os.ReadDir("/sys/class/drm"); err == nil {
			for _, entry := range entries {
				name := entry.Name()
				if strings.HasPrefix(name, "card") && !strings.Contains(name, "-") {
					driverPath := fmt.Sprintf("/sys/class/drm/%s/device/driver", name)
					if link, err := os.Readlink(driverPath); err == nil {
						parts := strings.Split(link, "/")
						if len(parts) > 0 {
							driverName := parts[len(parts)-1]
							t.GPUModels = append(t.GPUModels, fmt.Sprintf("%s (%s driver)", name, driverName))
						}
					}
				}
			}
		}
	}

	// Fallback to /sys/bus/pci/devices for virtualized/WSL environments
	if len(t.GPUModels) == 0 {
		if entries, err := os.ReadDir("/sys/bus/pci/devices"); err == nil {
			for _, entry := range entries {
				ueventPath := fmt.Sprintf("/sys/bus/pci/devices/%s/uevent", entry.Name())
				if data, err := os.ReadFile(ueventPath); err == nil {
					pciClass, driver := parsePciUevent(string(data))
					if isDisplayPciClass(pciClass) {
						if driver != "" {
							t.GPUModels = append(t.GPUModels, fmt.Sprintf("PCI %s (%s)", entry.Name(), driver))
						} else {
							t.GPUModels = append(t.GPUModels, fmt.Sprintf("PCI Display %s", entry.Name()))
						}
					}
				}
			}
		}
	}

	// 6. Driver Version
	if data, err := os.ReadFile("/proc/driver/nvidia/version"); err == nil {
		t.DriverVersion = parseLinuxNvidiaVersion(string(data))
	}
	if t.DriverVersion == "" {
		if out, err := runBoundedCmd(ctx, "nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader"); err == nil {
			t.DriverVersion = strings.TrimSpace(string(out))
		}
	}
	if t.DriverVersion == "" {
		for _, gpu := range t.GPUModels {
			driver := extractDriverName(gpu)
			if driver != "" {
				if data, err := os.ReadFile(fmt.Sprintf("/sys/module/%s/version", driver)); err == nil {
					t.DriverVersion = strings.TrimSpace(string(data))
					break
				}
			}
		}
	}
	if t.DriverVersion == "" {
		if data, err := os.ReadFile("/sys/class/drm/version"); err == nil {
			v := strings.TrimSpace(string(data))
			if v != "" {
				t.DriverVersion = v
			}
		}
	}
}

func collectDarwin(ctx context.Context, t *SystemTelemetry) {
	// 1. Kernel version
	if out, err := runBoundedCmd(ctx, "uname", "-r"); err == nil {
		t.KernelVersion = strings.TrimSpace(string(out))
	}

	// 2. CPU Model
	if out, err := runBoundedCmd(ctx, "sysctl", "-n", "machdep.cpu.brand_string"); err == nil {
		t.CPUModel = strings.TrimSpace(string(out))
	}

	t.DesktopEnvironment = "macOS Aqua"
	t.DisplayServer = "Quartz"

	// 3. GPU & Driver via system_profiler
	if out, err := runBoundedCmd(ctx, "system_profiler", "SPDisplaysDataType"); err == nil {
		gpus, driverVersion := parseDarwinDisplays(string(out))
		t.GPUModels = gpus
		if driverVersion != "" {
			t.DriverVersion = driverVersion
		}
	}
}

func collectWindows(ctx context.Context, t *SystemTelemetry) {
	// 1. Kernel / OS Version
	if out, err := runBoundedCmd(ctx, "cmd.exe", "/c", "ver"); err == nil {
		str := strings.TrimSpace(string(out))
		if strings.Contains(str, "[Version ") {
			start := strings.Index(str, "[Version ") + len("[Version ")
			end := strings.Index(str[start:], "]")
			if end != -1 {
				t.KernelVersion = str[start : start+end]
			}
		}
	}

	// 2. CPU Model
	t.CPUModel = os.Getenv("PROCESSOR_IDENTIFIER")
	if t.CPUModel == "" {
		psCmd := "(Get-CimInstance Win32_Processor).Name"
		if out, err := runBoundedCmd(ctx, "powershell", "-NoProfile", "-Command", psCmd); err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(out)))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					t.CPUModel = line
					break
				}
			}
		}
	}
	if t.CPUModel == "" {
		if out, err := runBoundedCmd(ctx, "wmic", "cpu", "get", "name"); err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(out)))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.EqualFold(line, "name") {
					t.CPUModel = line
					break
				}
			}
		}
	}

	t.DesktopEnvironment = "Windows DWM"
	t.DisplayServer = "DWM"

	// 3. GPU Models & Driver Version
	psCmd := "Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion | ConvertTo-Csv -NoTypeInformation"
	if out, err := runBoundedCmd(ctx, "powershell", "-NoProfile", "-Command", psCmd); err == nil {
		gpus, driverVersion := parseWindowsVideoController(string(out))
		if len(gpus) > 0 {
			t.GPUModels = gpus
			t.DriverVersion = driverVersion
		}
	}

	if len(t.GPUModels) == 0 {
		if out, err := runBoundedCmd(ctx, "wmic", "path", "win32_videocontroller", "get", "name,driverversion"); err == nil {
			gpus, driverVersion := parseWindowsVideoController(string(out))
			if len(gpus) > 0 {
				t.GPUModels = gpus
				if t.DriverVersion == "" {
					t.DriverVersion = driverVersion
				}
			}
		}
	}
}

func collectGeneric(ctx context.Context, t *SystemTelemetry) {
	if out, err := runBoundedCmd(ctx, "uname", "-r"); err == nil {
		t.KernelVersion = strings.TrimSpace(string(out))
	}
	t.DesktopEnvironment = os.Getenv("XDG_CURRENT_DESKTOP")
	t.DisplayServer = os.Getenv("XDG_SESSION_TYPE")
}

// FormatMarkdown formats system telemetry as a clean Markdown list for bug reports.
func FormatMarkdown(t SystemTelemetry) string {
	var sb strings.Builder

	if t.OS != "" {
		if t.Arch != "" {
			sb.WriteString(fmt.Sprintf("- **OS**: %s (%s)\n", t.OS, t.Arch))
		} else {
			sb.WriteString(fmt.Sprintf("- **OS**: %s\n", t.OS))
		}
	}

	if t.KernelVersion != "" {
		sb.WriteString(fmt.Sprintf("- **Kernel**: %s\n", t.KernelVersion))
	}

	if t.CPUModel != "" {
		if t.NumCPU > 0 {
			sb.WriteString(fmt.Sprintf("- **CPU**: %s (%d cores)\n", t.CPUModel, t.NumCPU))
		} else {
			sb.WriteString(fmt.Sprintf("- **CPU**: %s\n", t.CPUModel))
		}
	} else if t.NumCPU > 0 {
		sb.WriteString(fmt.Sprintf("- **CPU**: %d cores\n", t.NumCPU))
	}

	gpuList := t.GPUModels
	if len(gpuList) == 0 {
		gpuList = t.GPUs
	}
	if len(gpuList) > 0 {
		sb.WriteString(fmt.Sprintf("- **GPU**: %s\n", strings.Join(gpuList, ", ")))
	}

	if t.DriverVersion != "" {
		sb.WriteString(fmt.Sprintf("- **Driver Version**: %s\n", t.DriverVersion))
	}

	de := t.DesktopEnvironment
	if de == "" {
		de = t.DesktopEnv
	}
	if de != "" {
		sb.WriteString(fmt.Sprintf("- **Desktop**: %s\n", de))
	}

	if t.DisplayServer != "" {
		sb.WriteString(fmt.Sprintf("- **Display Server**: %s\n", t.DisplayServer))
	}

	return strings.TrimRight(sb.String(), "\n")
}

func parseLspci(out string) []string {
	var gpus []string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		lower := strings.ToLower(line)
		if strings.Contains(lower, "vga compatible controller") || strings.Contains(lower, "3d controller") || strings.Contains(lower, "display controller") {
			if _, val, ok := strings.Cut(line, ": "); ok {
				if _, dev, found := strings.Cut(val, ": "); found {
					gpus = append(gpus, strings.TrimSpace(dev))
				} else {
					gpus = append(gpus, strings.TrimSpace(val))
				}
			}
		}
	}
	return gpus
}

func parseDarwinDisplays(out string) ([]string, string) {
	var gpus []string
	var driverVersion string

	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Chipset Model:") {
			if _, val, ok := strings.Cut(line, ":"); ok {
				m := strings.TrimSpace(val)
				if m != "" {
					gpus = append(gpus, m)
				}
			}
		} else if strings.HasPrefix(line, "Driver Version:") || strings.HasPrefix(line, "EFI Driver Version:") {
			if driverVersion == "" {
				if _, val, ok := strings.Cut(line, ":"); ok {
					driverVersion = strings.TrimSpace(val)
				}
			}
		} else if strings.HasPrefix(line, "Metal Support:") || strings.HasPrefix(line, "Metal Family:") {
			if driverVersion == "" {
				if _, val, ok := strings.Cut(line, ":"); ok {
					driverVersion = strings.TrimSpace(val)
				}
			}
		}
	}
	return gpus, driverVersion
}

func parseWindowsVideoController(raw string) ([]string, string) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, ""
	}
	if strings.Contains(trimmed, ",") {
		return parseWindowsVideoControllerCSV(trimmed)
	}
	return parseWindowsVideoControllerTable(trimmed)
}

func parseWindowsVideoControllerCSV(raw string) ([]string, string) {
	r := csv.NewReader(strings.NewReader(raw))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true

	var gpus []string
	var driverVersions []string
	seenDrivers := make(map[string]bool)

	nameIdx := -1
	driverIdx := -1

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(record) == 0 {
			continue
		}

		if nameIdx == -1 {
			for i, col := range record {
				colClean := strings.ToLower(strings.TrimSpace(col))
				if colClean == "name" {
					nameIdx = i
				} else if colClean == "driverversion" || colClean == "driver_version" {
					driverIdx = i
				}
			}
			continue
		}

		var name, driver string
		if nameIdx >= 0 && nameIdx < len(record) {
			name = strings.TrimSpace(record[nameIdx])
		}
		if driverIdx >= 0 && driverIdx < len(record) {
			driver = strings.TrimSpace(record[driverIdx])
		}

		if name != "" && !strings.EqualFold(name, "name") {
			gpus = append(gpus, name)
		}
		if driver != "" && !strings.EqualFold(driver, "driverversion") && !seenDrivers[driver] {
			seenDrivers[driver] = true
			driverVersions = append(driverVersions, driver)
		}
	}

	return gpus, strings.Join(driverVersions, ", ")
}

func parseWindowsVideoControllerTable(raw string) ([]string, string) {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	var gpus []string
	var driverVersions []string
	seenDrivers := make(map[string]bool)

	headerFound := false
	nameStart := -1
	driverStart := -1

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if !headerFound {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "name") {
				nameStart = strings.Index(lower, "name")
				driverStart = strings.Index(lower, "driverversion")
				headerFound = true
			}
			continue
		}

		var name, driver string
		if nameStart >= 0 && driverStart >= 0 {
			if nameStart < driverStart {
				if len(line) > nameStart {
					end := driverStart
					if end > len(line) {
						end = len(line)
					}
					name = strings.TrimSpace(line[nameStart:end])
				}
				if len(line) > driverStart {
					driver = strings.TrimSpace(line[driverStart:])
				}
			} else {
				if len(line) > driverStart {
					end := nameStart
					if end > len(line) {
						end = len(line)
					}
					driver = strings.TrimSpace(line[driverStart:end])
				}
				if len(line) > nameStart {
					name = strings.TrimSpace(line[nameStart:])
				}
			}
		} else if nameStart >= 0 {
			if len(line) > nameStart {
				name = strings.TrimSpace(line[nameStart:])
			}
		} else {
			name = trimmed
		}

		if name != "" && !strings.EqualFold(name, "name") {
			gpus = append(gpus, name)
		}
		if driver != "" && !strings.EqualFold(driver, "driverversion") && !seenDrivers[driver] {
			seenDrivers[driver] = true
			driverVersions = append(driverVersions, driver)
		}
	}

	return gpus, strings.Join(driverVersions, ", ")
}

func parseLinuxNvidiaVersion(data string) string {
	fields := strings.Fields(data)
	for i, f := range fields {
		if (f == "Module" || strings.EqualFold(f, "version:")) && i+1 < len(fields) {
			v := fields[i+1]
			if len(v) > 0 && v[0] >= '0' && v[0] <= '9' {
				return v
			}
		}
	}
	return ""
}

func parsePciUevent(content string) (pciClass string, driver string) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if val, found := strings.CutPrefix(line, "PCI_CLASS="); found {
			pciClass = strings.TrimSpace(val)
		} else if val, found := strings.CutPrefix(line, "DRIVER="); found {
			driver = strings.TrimSpace(val)
		}
	}
	return pciClass, driver
}

func isDisplayPciClass(classStr string) bool {
	s := strings.TrimPrefix(strings.ToLower(classStr), "0x")
	return strings.HasPrefix(s, "30") || strings.HasPrefix(s, "030") || strings.HasPrefix(s, "380") || strings.HasPrefix(s, "038")
}

func extractDriverName(gpuStr string) string {
	if idx := strings.LastIndex(gpuStr, "("); idx != -1 {
		end := strings.LastIndex(gpuStr, ")")
		if end > idx {
			inside := strings.TrimSpace(gpuStr[idx+1 : end])
			inside = strings.TrimSuffix(inside, " driver")
			return strings.TrimSpace(inside)
		}
	}
	return ""
}
