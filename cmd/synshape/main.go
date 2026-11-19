// Command synshape runs Divisor's SYN shaping on its own: it installs the
// shaping table for TARGET_SUBNETS in the current network namespace, binds the
// NFQUEUE listeners, and optionally raises tcp_rmem in other network
// namespaces (-rmem-pids). Divisor itself does the same when SYN_SHAPE=on;
// this command is for testing a host or namespace without Redis or Docker.
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"divisor/internal/shape"
)

func main() {
	targets := flag.String("targets", os.Getenv("TARGET_SUBNETS"), "comma-separated destination subnets to shape")
	pids := flag.String("rmem-pids", "", "comma-separated PIDs whose network namespaces get tcp_rmem max raised")
	keep := flag.Bool("keep-table", false, "leave the nftables table installed on exit")
	every := flag.Duration("stats", 10*time.Second, "log counters this often")
	flag.Parse()

	if err := shape.Install(strings.Split(*targets, ",")); err != nil {
		log.Fatal(err)
	}
	for _, p := range strings.Split(*pids, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		pid, err := strconv.Atoi(p)
		if err != nil {
			log.Fatalf("bad pid %q", p)
		}
		if err := shape.EnsureRcvBufMax(pid, shape.RcvBufMax); err != nil {
			log.Fatalf("tcp_rmem for pid %d: %v", pid, err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var stats shape.Stats
	if err := shape.Listen(ctx, &stats); err != nil {
		log.Fatal(err)
	}
	report := func() {
		slog.Info("SYN shaping", "rewritten", stats.Rewritten.Load(), "passed_as_is", stats.PassedAsIs.Load(), "verdict_errors", stats.VerdictErrs.Load())
	}
	t := time.NewTicker(*every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			report()
			if !*keep {
				if err := shape.Remove(); err != nil {
					slog.Error("remove table", "error", err)
				}
			}
			return
		case <-t.C:
			report()
		}
	}
}
