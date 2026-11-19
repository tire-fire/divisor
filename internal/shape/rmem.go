package shape

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/vishvananda/netns"
)

// RcvBufMax is the tcp_rmem maximum Divisor gives runner network namespaces.
// Linux derives a socket's SYN window scale from max(tcp_rmem[2], rmem_max)
// capped by the socket's TCP_WINDOW_CLAMP; 16 MiB lets the runner's
// per-profile clamps (8 MiB Windows, 4 MiB Linux, 2 MiB macOS) give exactly
// scale 8, 7 and 6, so Divisor never has to raise a scale.
const RcvBufMax = 16 << 20

const tcpRmemPath = "/proc/sys/net/ipv4/tcp_rmem"

// EnsureRcvBufMax raises net.ipv4.tcp_rmem's maximum to at least max in the
// network namespace of process pid (0: the current one). The sysctl is per
// network namespace, so this changes the runner's namespace, not the host.
func EnsureRcvBufMax(pid, max int) error {
	if pid == 0 {
		return raiseRmem(max)
	}
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("current netns: %w", err)
	}
	defer orig.Close()
	target, err := netns.GetFromPid(pid)
	if err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("netns of pid %d: %w", pid, err)
	}
	defer target.Close()
	if err := netns.Set(target); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("enter netns of pid %d: %w", pid, err)
	}
	// /proc/sys/net is resolved against the opening thread's namespace.
	rerr := raiseRmem(max)
	if err := netns.Set(orig); err != nil {
		// Leave the thread locked: the runtime discards it when this
		// goroutine ends instead of reusing it in the runner's namespace.
		return fmt.Errorf("return to own netns: %w", err)
	}
	runtime.UnlockOSThread()
	return rerr
}

func raiseRmem(max int) error {
	raw, err := os.ReadFile(tcpRmemPath)
	if err != nil {
		return err
	}
	f := strings.Fields(string(raw))
	if len(f) != 3 {
		return fmt.Errorf("unexpected %s: %q", tcpRmemPath, raw)
	}
	cur, err := strconv.Atoi(f[2])
	if err != nil {
		return fmt.Errorf("unexpected %s: %q", tcpRmemPath, raw)
	}
	if cur >= max {
		return nil
	}
	return os.WriteFile(tcpRmemPath, []byte(f[0]+" "+f[1]+" "+strconv.Itoa(max)+"\n"), 0o644)
}
