package shape

import (
	"strings"
	"testing"
	"time"
)

func TestParseQueueStats(t *testing.T) {
	// Format of /proc/net/netfilter/nfnetlink_queue (Linux 6.x).
	in := "    7      1     3 2   256     0     0      557  1\n" +
		"   15 3306050584     0 2   256     4     2      147  1\n"
	got, err := ParseQueueStats(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if q := got[7]; q.Waiting != 3 || q.IDSequence != 557 {
		t.Errorf("queue 7 = %+v", q)
	}
	if tot := ShapedQueueTotals(got); tot.Waiting != 3 || tot.IDSequence != 704 {
		t.Errorf("totals = %+v, want waiting 3, id_sequence 704", tot)
	}
}

// wdHarness scripts the clock, the queue table and the synopts chain so the
// watchdog runs without a kernel.
type wdHarness struct {
	now       time.Time
	waiting   uint64
	queueing  bool // synopts chain holds the queue rules
	installed bool // shaping table exists
	bypasses  int
	restores  int
}

func newWD(t *testing.T, h *wdHarness) *Watchdog {
	return &Watchdog{
		threshold: 500 * time.Millisecond,
		stateDir:  t.TempDir(),
		now:       func() time.Time { return h.now },
		readStats: func() (map[uint16]QueueStat, error) {
			return map[uint16]QueueStat{7: {Waiting: h.waiting}}, nil
		},
		bypass:  func() error { h.bypasses++; h.queueing = false; return nil },
		restore: func() error { h.restores++; h.queueing = true; return nil },
		chain: func() (ChainState, error) {
			switch {
			case !h.installed:
				return 0, ErrNoTable
			case h.queueing:
				return ChainQueueing, nil
			}
			return ChainBypassed, nil
		},
	}
}

func (h *wdHarness) run(w *Watchdog, d time.Duration) {
	for end := h.now.Add(d); h.now.Before(end); h.now = h.now.Add(watchdogInterval) {
		w.step()
	}
}

func TestWatchdogIgnoresShortBursts(t *testing.T) {
	h := &wdHarness{now: time.Unix(1000, 0), queueing: true, installed: true}
	w := newWD(t, h)
	// A round's SYN burst keeps the queue busy for well under the threshold.
	h.waiting = 40
	h.run(w, 300*time.Millisecond)
	h.waiting = 0
	h.run(w, time.Second)
	if h.bypasses != 0 || w.state.Trips != 0 {
		t.Fatalf("bypassed on a short burst: bypasses=%d trips=%d", h.bypasses, w.state.Trips)
	}
}

func TestWatchdogBypassesStalledListenerAndRestores(t *testing.T) {
	h := &wdHarness{now: time.Unix(1000, 0), queueing: true, installed: true}
	w := newWD(t, h)
	// Listener frozen: SYNs sit in the queue.
	h.waiting = 3
	h.run(w, 450*time.Millisecond)
	if h.bypasses != 0 {
		t.Fatal("bypassed before the threshold")
	}
	h.run(w, 10*time.Second)
	if h.bypasses != 1 || !w.state.Bypassed || w.state.Trips != 1 {
		t.Fatalf("want one bypass while stalled: bypasses=%d state=%+v", h.bypasses, w.state)
	}
	// Listener thaws and answers the queued SYNs.
	h.waiting = 0
	h.run(w, 450*time.Millisecond)
	if h.restores != 0 {
		t.Fatal("restored before the queue stayed clear for the threshold")
	}
	h.run(w, time.Second)
	if h.restores != 1 || w.state.Bypassed {
		t.Fatalf("want shaping restored: restores=%d state=%+v", h.restores, w.state)
	}
	// A second stall is a second trip.
	h.waiting = 1
	h.run(w, time.Second)
	if w.state.Trips != 2 {
		t.Fatalf("trips = %d, want 2", w.state.Trips)
	}
}

// A watchdog that restarts while it has shaping bypassed takes the bypass from
// the chain, not from memory, and still restores once the listener answers.
func TestWatchdogRestartDuringBypassRestores(t *testing.T) {
	h := &wdHarness{now: time.Unix(1000, 0), queueing: true, installed: true}
	first := newWD(t, h)
	h.waiting = 2
	h.run(first, time.Second)
	first.writeState()
	if h.queueing || first.state.Trips != 1 {
		t.Fatalf("first watchdog did not bypass: queueing=%v trips=%d", h.queueing, first.state.Trips)
	}

	h.waiting = 0
	second := newWD(t, h)
	second.stateDir = first.stateDir
	if err := second.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !second.state.Bypassed || second.state.Trips != 1 {
		t.Fatalf("restarted watchdog state = %+v, want bypassed with 1 trip", second.state)
	}
	h.run(second, time.Second)
	if h.restores != 1 || !h.queueing || second.state.Bypassed {
		t.Fatalf("restarted watchdog did not restore: restores=%d queueing=%v", h.restores, h.queueing)
	}
}

// A Divisor restart reinstalls the queue rules while the watchdog still has the
// bypass on record; if that Divisor stalls too, the watchdog bypasses again.
func TestWatchdogBypassesAgainAfterDivisorReinstallsRules(t *testing.T) {
	h := &wdHarness{now: time.Unix(1000, 0), queueing: true, installed: true}
	w := newWD(t, h)
	h.waiting = 2
	h.run(w, time.Second)
	if h.bypasses != 1 {
		t.Fatalf("bypasses = %d, want 1", h.bypasses)
	}
	h.queueing = true // Divisor restarted: shape.Install put the rules back
	h.run(w, 2*time.Second)
	if h.bypasses != 2 || h.queueing || w.state.Trips != 2 {
		t.Fatalf("want a second bypass: bypasses=%d queueing=%v trips=%d", h.bypasses, h.queueing, w.state.Trips)
	}
}

// With shaping off (no table) the watchdog never bypasses or restores.
func TestWatchdogIdleWithoutShapingTable(t *testing.T) {
	h := &wdHarness{now: time.Unix(1000, 0)}
	w := newWD(t, h)
	if err := w.reconcile(); err != nil {
		t.Fatal(err)
	}
	h.run(w, 2*time.Second)
	if w.state.Bypassed || h.bypasses+h.restores != 0 {
		t.Fatalf("watchdog acted without a table: %+v bypasses=%d restores=%d", w.state, h.bypasses, h.restores)
	}
}

func TestWatchdogStatusFreshness(t *testing.T) {
	h := &wdHarness{now: time.Unix(1000, 0), queueing: true, installed: true}
	w := newWD(t, h)
	h.waiting = 1
	h.run(w, time.Second)
	w.writeState()
	s, ok, fresh := WatchdogStatus(w.stateDir, h.now.Add(time.Second))
	if !ok || !fresh || s.Trips != 1 || !s.Bypassed {
		t.Fatalf("state = %+v ok=%v fresh=%v", s, ok, fresh)
	}
	if _, _, fresh := WatchdogStatus(w.stateDir, h.now.Add(time.Minute)); fresh {
		t.Fatal("a state file a minute old must read as stale")
	}
}

func TestRulesetQueuesAndClearsMarks(t *testing.T) {
	rs, err := Ruleset([]string{"10.100.0.0/16"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range synoptsRules() {
		if !strings.Contains(rs, r) {
			t.Errorf("installed ruleset lacks %q", r)
		}
		if !strings.Contains(RestoreScript(), "add rule inet divisor_shape synopts "+r) {
			t.Errorf("restore script lacks %q", r)
		}
	}
	if !strings.HasPrefix(RestoreScript(), "flush chain inet divisor_shape synopts\n") {
		t.Error("restore must replace the chain, not append to it")
	}
	// Extra hops are added to every profile's TTL.
	if !strings.Contains(rs, "ip ttl set 129") || !strings.Contains(rs, "ip ttl set 65") {
		t.Errorf("TTLs not raised by the extra hop:\n%s", rs)
	}
	// Profile marks are cleared toward any destination, both families.
	if !strings.Contains(rs, "ip dscp { 7, 11, 15 } ip dscp set cs0") || !strings.Contains(rs, "ip6 dscp { 7, 11, 15 } ip6 dscp set cs0") {
		t.Errorf("profile DSCP values not cleared for every destination:\n%s", rs)
	}
}
