package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"

	"divisor/internal/config"
	"divisor/internal/events"
	"divisor/internal/network"
	"divisor/internal/shape"
)

var shapeStats shape.Stats

var logLvels = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
}

var opts struct {
	logger struct {
		level string
	}
}

func main() {
	flag.StringVar(&opts.logger.level, "log-level", "debug", "Set the log level")
	flag.Parse()

	logLevel, ok := logLvels[opts.logger.level]
	if !ok {
		log.Fatalf("Invalid log level: %s", opts.logger.level)
	}
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(handler))

	if err := godotenv.Load(".env"); err != nil {
		log.Fatalf("Error loading .env file: %s", err)
	}

	// "divisor watchdog" runs the SYN-shaping watchdog. It must run as its own
	// process (its own container or sidecar): it exists to act when Divisor
	// itself is frozen.
	if flag.Arg(0) == "watchdog" {
		runWatchdog()
		return
	}

	cfg := config.Load()
	if err := cfg.ValidateMode(); err != nil {
		log.Fatalf("%s", err)
	}
	if err := cfg.ValidateBackend(); err != nil {
		log.Fatalf("%s", err)
	}

	// SYN shaping is set up before the first rotation and is independent of
	// it: the table matches the runner's DSCP mark and TARGET_SUBNETS, not the
	// rotated SNAT addresses.
	if cfg.SynShape {
		hops, err := cfg.ShapeExtraHopsOrDefault()
		if err != nil {
			log.Fatalf("%s", err)
		}
		if err := shape.Install(strings.Split(cfg.TargetSubnets, ","), hops); err != nil {
			log.Fatalf("SYN shaping: %s", err)
		}
		if err := shape.Listen(context.Background(), &shapeStats); err != nil {
			log.Fatalf("SYN shaping: %s", err)
		}
	}

	// In direct mode nothing else configures the interface, so do it on startup.
	if cfg.Mode == config.ModeDirect {
		// New addresses are added before the old ones are removed, so
		// without promote_secondaries we'd lose the new address as well.
		if err := network.DirectModeReady(cfg.InterfaceName); err != nil {
			log.Fatalf("%s", err)
		}
		if err := network.Reconfigure(); err != nil {
			log.Fatalf("Initial network configuration failed: %s", err)
		}
	}

	slog.Info("Starting the Divisor...")
	source, err := events.Open(cfg)
	if err != nil {
		log.Fatalf("%s", err)
	}
	rotate := network.Reconfigure
	if cfg.SynShape {
		rotate = func() error {
			err := network.Reconfigure()
			logShapeCounters()
			return err
		}
	}
	for {
		if err := source.Listen(context.Background(), rotate); err != nil {
			slog.Error("main loop errored out", "error", err)
		}
	}
}

// logShapeCounters logs, once per rotation, what SYN shaping has done since
// Divisor started and what the watchdog reports.
func logShapeCounters() {
	seen := shapeStats.Seen.Load()
	attrs := []any{
		"shaped", shapeStats.Rewritten.Load(),
		"passed_through", shapeStats.PassedAsIs.Load(),
		"verdict_errors", shapeStats.VerdictErrs.Load(),
	}
	// The listeners ask the kernel to fail open, so it counts no drops: a SYN
	// it queued (id_sequence) that neither reached a listener nor is still
	// waiting went out unshaped because the socket buffer was full. (A full
	// queue fails open before queueing and is not counted anywhere.)
	if stats, err := shape.ReadQueueStats(); err == nil {
		t := shape.ShapedQueueTotals(stats)
		attrs = append(attrs, "kernel_queued", t.IDSequence, "failed_open", t.IDSequence-min(t.IDSequence, seen+t.Waiting))
	}
	ws, ok, fresh := shape.WatchdogStatus(shape.StateDir, time.Now())
	switch {
	case !ok:
		slog.Warn("No SYN shaping watchdog state: without the watchdog a frozen Divisor holds Windows/macOS SYNs", "dir", shape.StateDir)
	case !fresh:
		slog.Warn("SYN shaping watchdog state is stale: is the watchdog running?", "updated_at", ws.UpdatedAt)
	}
	if ok {
		attrs = append(attrs, "watchdog_trips", ws.Trips, "watchdog_bypassed", ws.Bypassed)
	}
	slog.Info("SYN shaping counters", attrs...)
}

func runWatchdog() {
	cfg := config.Load()
	threshold, err := cfg.ShapeWatchdogThresholdOrDefault()
	if err != nil {
		log.Fatalf("%s", err)
	}
	if err := shape.NewWatchdog(threshold).Run(context.Background()); err != nil {
		log.Fatalf("SYN shaping watchdog: %s", err)
	}
}
