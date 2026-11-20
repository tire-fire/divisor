package shape

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// QueueStat is what Divisor and the watchdog read from one line of
// /proc/net/netfilter/nfnetlink_queue (a queue with a listener bound in this
// network namespace).
type QueueStat struct {
	Waiting    uint64 // packets queued, waiting for a verdict
	IDSequence uint64 // packets the kernel queued since the listener bound, including fail-opens on a full socket buffer
}

const nfqueueProc = "/proc/net/netfilter/nfnetlink_queue"

// ParseQueueStats reads the kernel's NFQUEUE table, keyed by queue number.
func ParseQueueStats(r io.Reader) (map[uint16]QueueStat, error) {
	out := map[uint16]QueueStat{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 {
			continue
		}
		num, err1 := strconv.ParseUint(f[0], 10, 16)
		waiting, err2 := strconv.ParseUint(f[2], 10, 64)
		idSeq, err3 := strconv.ParseUint(f[7], 10, 64)
		if err := errors.Join(err1, err2, err3); err != nil {
			return nil, fmt.Errorf("nfnetlink_queue line %q: %w", sc.Text(), err)
		}
		out[uint16(num)] = QueueStat{Waiting: waiting, IDSequence: idSeq}
	}
	return out, sc.Err()
}

// ReadQueueStats reads the NFQUEUE table of the current network namespace.
// A missing file means no queue has ever been bound here.
func ReadQueueStats() (map[uint16]QueueStat, error) {
	f, err := os.Open(nfqueueProc)
	if os.IsNotExist(err) {
		return map[uint16]QueueStat{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseQueueStats(f)
}

// ShapedQueueTotals sums the stats of the shaped profiles' queues.
func ShapedQueueTotals(stats map[uint16]QueueStat) QueueStat {
	var t QueueStat
	for _, p := range Shaped() {
		q := stats[p.SYN.Queue]
		t.Waiting += q.Waiting
		t.IDSequence += q.IDSequence
	}
	return t
}

// WatchdogState is what the watchdog publishes in its state file.
type WatchdogState struct {
	Trips     uint64    `json:"trips"`
	Bypassed  bool      `json:"bypassed"`
	Since     time.Time `json:"since,omitempty"` // when the current bypass began
	UpdatedAt time.Time `json:"updated_at"`
}

const (
	watchdogInterval   = 50 * time.Millisecond
	stateWriteInterval = time.Second
	// stateStaleAfter is when Divisor reports the watchdog as not running:
	// ten missed writes.
	stateStaleAfter = 10 * stateWriteInterval
)

// StateDir holds the watchdog's state file; Divisor and the watchdog mount it.
const StateDir = "/run/divisor"

func statePath(dir string) string { return filepath.Join(dir, "watchdog.json") }

// WatchdogStatus reads the watchdog's state file in dir. ok is false when
// there is none; fresh is false when the watchdog stopped writing it.
func WatchdogStatus(dir string, now time.Time) (s WatchdogState, ok, fresh bool) {
	raw, err := os.ReadFile(statePath(dir))
	if err != nil || json.Unmarshal(raw, &s) != nil {
		return s, false, false
	}
	return s, true, now.Sub(s.UpdatedAt) <= stateStaleAfter
}

// Watchdog keeps a stuck listener from holding SYNs. The kernel fails a queue
// open only when no listener is bound or the queue or its socket buffer is
// full; a listener that is bound but stopped (a frozen or hung Divisor) leaves
// SYNs waiting, and the checks that sent them time out. The watchdog runs as its own process, so it
// keeps working when Divisor is frozen. When the shaped profiles' queues have
// been non-empty at every sample for threshold, it empties the synopts chain
// so new SYNs leave unshaped; once they have been empty for threshold, it puts
// the queue rules back. The chain is the bypass state: the watchdog reads it at
// start (a restart mid-bypass still restores) and during a stall (a Divisor
// restart puts the queue rules back).
type Watchdog struct {
	threshold time.Duration
	stateDir  string

	// Kernel and nft access; tests replace them.
	readStats func() (map[uint16]QueueStat, error)
	bypass    func() error
	restore   func() error
	chain     func() (ChainState, error)
	now       func() time.Time

	state        WatchdogState
	waitingSince time.Time // first sample with packets waiting, zero when none
	clearSince   time.Time // first sample with nothing waiting while bypassed
	chainChecked time.Time // last chain read during a stall while bypassed
}

// NewWatchdog returns a watchdog working on the kernel, nft and StateDir.
func NewWatchdog(threshold time.Duration) *Watchdog {
	return &Watchdog{threshold: threshold, stateDir: StateDir, readStats: ReadQueueStats,
		bypass: Bypass, restore: Restore, chain: SynoptsState, now: time.Now}
}

// Run samples the queues until ctx ends.
func (w *Watchdog) Run(ctx context.Context) error {
	if err := os.MkdirAll(w.stateDir, 0o755); err != nil {
		return err
	}
	if err := w.reconcile(); err != nil {
		return err
	}
	slog.Info("SYN shaping watchdog started", "threshold", w.threshold, "bypassed", w.state.Bypassed, "trips", w.state.Trips)
	tick := time.NewTicker(watchdogInterval)
	defer tick.Stop()
	var lastWrite time.Time
	for {
		changed := w.step()
		if now := w.now(); changed || now.Sub(lastWrite) >= stateWriteInterval {
			w.writeState()
			lastWrite = now
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// reconcile takes the trip count from the last state file and the bypass state
// from the chain: an installed table whose synopts chain queues nothing is
// bypassed, whoever emptied it. A missing table leaves the watchdog idle; any
// other nft error stops it (its restart policy retries).
func (w *Watchdog) reconcile() error {
	if s, ok, _ := WatchdogStatus(w.stateDir, w.now()); ok {
		w.state.Trips, w.state.Since = s.Trips, s.Since
	}
	st, err := w.chain()
	if err != nil && !errors.Is(err, ErrNoTable) {
		return fmt.Errorf("reading the synopts chain: %w", err)
	}
	w.state.Bypassed = err == nil && st == ChainBypassed
	if !w.state.Bypassed {
		w.state.Since = time.Time{}
	} else if w.state.Since.IsZero() {
		w.state.Since = w.now()
	}
	return nil
}

// step takes one sample and acts on it; it reports whether the bypass state
// changed.
func (w *Watchdog) step() bool {
	now := w.now()
	stats, err := w.readStats()
	if err != nil {
		slog.Warn("SYN shaping watchdog: reading queue stats", "error", err)
		return false
	}

	if waiting := ShapedQueueTotals(stats).Waiting; waiting > 0 {
		w.clearSince = time.Time{}
		if w.waitingSince.IsZero() {
			w.waitingSince = now
		}
		if now.Sub(w.waitingSince) < w.threshold {
			return false
		}
		if w.state.Bypassed {
			// Divisor reinstalls its table, queue rules included, when it
			// restarts. While a stall lasts, look at the chain once per
			// threshold and bypass again if the rules are back.
			if now.Sub(w.chainChecked) < w.threshold {
				return false
			}
			w.chainChecked = now
			st, err := w.chain()
			if err != nil && !errors.Is(err, ErrNoTable) {
				slog.Warn("SYN shaping watchdog: reading the synopts chain during a stall", "error", err)
			}
			if err != nil || st != ChainQueueing {
				return false
			}
		}
		if err := w.bypass(); err != nil {
			slog.Error("SYN shaping watchdog: bypass failed", "error", err)
			return false
		}
		w.state.Bypassed, w.state.Since = true, now
		w.state.Trips++
		slog.Warn("SYN shaping watchdog: listener not answering, SYNs now leave unshaped",
			"waiting", waiting, "stalled_for", now.Sub(w.waitingSince), "trips", w.state.Trips)
		return true
	}

	w.waitingSince = time.Time{}
	if !w.state.Bypassed {
		return false
	}
	if w.clearSince.IsZero() {
		w.clearSince = now
	}
	if now.Sub(w.clearSince) < w.threshold {
		return false
	}
	if err := w.restore(); err != nil {
		// No shaping table any more: nothing to restore; anything else is
		// retried next sample.
		if !errors.Is(err, ErrNoTable) {
			slog.Error("SYN shaping watchdog: restore failed, retrying", "error", err)
			return false
		}
	} else {
		slog.Info("SYN shaping watchdog: listener answering again, shaping restored", "bypassed_for", now.Sub(w.state.Since))
	}
	w.state.Bypassed, w.state.Since, w.clearSince = false, time.Time{}, time.Time{}
	return true
}

func (w *Watchdog) writeState() {
	w.state.UpdatedAt = w.now()
	raw, err := json.Marshal(w.state)
	if err != nil {
		return
	}
	tmp := statePath(w.stateDir) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		slog.Warn("SYN shaping watchdog: writing state", "error", err)
		return
	}
	_ = os.Rename(tmp, statePath(w.stateDir))
}
