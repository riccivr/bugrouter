package telemetry

import (
	"bufio"
	"context"
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
	OS            string   `json:"os"`
	Arch          string   `json:"arch"`
	KernelVersion string   `json:"kernel_version,omitempty"`
	CPUModel      string   `json:"cpu_model,omitempty"`
	NumCPU        int      `json:"num_cpu"`
	GPUs          []string `json:"gpus,omitempty"`
	DesktopEnv    string   `json:"desktop_env,omitempty"`
	DisplayServer string   `json:"display_server,omitempty"`
}

func runBoundedCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	const maxOutput = 64 * 1024
	lr := io.LimitReader(stdout, maxOutput+1)
	out, readErr := io.ReadAll(lr)
	if readErr != nil {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		return nil, readErr
	}
	if int64(len(out)) > maxOutput {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		return nil, errors.New("command output exceeded limit")
	}

	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	return out, nil
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

	// Sanitize all collected strings through scrubber
	t.KernelVersion = strings.TrimSpace(string(scrubber.Scrub(t.KernelVersion)))
	t.CPUModel = strings.TrimSpace(string(scrubber.Scrub(t.CPUModel)))
	t.DesktopEnv = strings.TrimSpace(string(scrubber.Scrub(t.DesktopEnv)))
	t.DisplayServer = strings.TrimSpace(string(scrubber.Scrub(t.DisplayServer)))
	for i := range t.GPUs {
		t.GPUs[i] = strings.TrimSpace(string(scrubber.Scrub(t.GPUs[i])))
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
	t.DesktopEnv = os.Getenv("XDG_CURRENT_DESKTOP")
	if t.DesktopEnv == "" {
		t.DesktopEnv = os.Getenv("DESKTOP_SESSION")
	}

	// 4. Display Server
	t.DisplayServer = os.Getenv("XDG_SESSION_TYPE")
	if t.DisplayServer == "" {
		if os.Getenv("WAYLAND_DISPLAY") != "" {
			t.DisplayServer = "wayland"
		} else if os.Getenv("DISPLAY") != "" {
			t.DisplayServer = "x11"
		}
	}

	// 5. GPUs via lspci
	if out, err := runBoundedCmd(ctx, "lspci"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			line := scanner.Text()
			lower := strings.ToLower(line)
			if strings.Contains(lower, "vga compatible controller") || strings.Contains(lower, "3d controller") || strings.Contains(lower, "display controller") {
				if _, val, ok := strings.Cut(line, ": "); ok {
					// Remove leading slot number if present
					if _, dev, found := strings.Cut(val, ": "); found {
						t.GPUs = append(t.GPUs, strings.TrimSpace(dev))
					} else {
						t.GPUs = append(t.GPUs, strings.TrimSpace(val))
					}
				}
			}
		}
	}

	// Fallback to /sys/class/drm if no GPUs found from lspci
	if len(t.GPUs) == 0 {
		if entries, err := os.ReadDir("/sys/class/drm"); err == nil {
			for _, entry := range entries {
				name := entry.Name()
				if strings.HasPrefix(name, "card") && !strings.Contains(name, "-") {
					driverPath := fmt.Sprintf("/sys/class/drm/%s/device/driver", name)
					if link, err := os.Readlink(driverPath); err == nil {
						parts := strings.Split(link, "/")
						if len(parts) > 0 {
							driverName := parts[len(parts)-1]
							t.GPUs = append(t.GPUs, fmt.Sprintf("%s (%s driver)", name, driverName))
						}
					}
				}
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

	t.DesktopEnv = "Aqua"
	t.DisplayServer = "Quartz"

	// 3. GPU via system_profiler
	if out, err := runBoundedCmd(ctx, "system_profiler", "SPDisplaysDataType"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Chipset Model:") {
				if _, val, ok := strings.Cut(line, ":"); ok {
					t.GPUs = append(t.GPUs, strings.TrimSpace(val))
				}
			}
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

	t.DesktopEnv = "Windows Explorer"
	t.DisplayServer = "DWM"

	// 3. GPUs via wmic or powershell
	if out, err := runBoundedCmd(ctx, "wmic", "path", "win32_VideoController", "get", "name"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.EqualFold(line, "name") {
				t.GPUs = append(t.GPUs, line)
			}
		}
	}
	if len(t.GPUs) == 0 {
		psCmd := "(Get-CimInstance Win32_VideoController).Name"
		if out, err := runBoundedCmd(ctx, "powershell", "-NoProfile", "-Command", psCmd); err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(out)))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					t.GPUs = append(t.GPUs, line)
				}
			}
		}
	}
}

func collectGeneric(ctx context.Context, t *SystemTelemetry) {
	if out, err := runBoundedCmd(ctx, "uname", "-r"); err == nil {
		t.KernelVersion = strings.TrimSpace(string(out))
	}
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

	if len(t.GPUs) > 0 {
		sb.WriteString(fmt.Sprintf("- **GPU**: %s\n", strings.Join(t.GPUs, ", ")))
	}

	if t.DesktopEnv != "" {
		sb.WriteString(fmt.Sprintf("- **Desktop**: %s\n", t.DesktopEnv))
	}

	if t.DisplayServer != "" {
		sb.WriteString(fmt.Sprintf("- **Display Server**: %s\n", t.DisplayServer))
	}

	return strings.TrimRight(sb.String(), "\n")
}
