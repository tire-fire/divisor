package shape

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/mdlayher/netlink"
)

// Stats counts what the listeners did, for the per-rotation log line.
type Stats struct {
	Seen        atomic.Uint64 // packets the listeners received
	Rewritten   atomic.Uint64
	PassedAsIs  atomic.Uint64 // not rewritable (see the Err* reasons): accepted unmodified
	VerdictErrs atomic.Uint64
}

// Listen binds one NFQUEUE listener per shaped profile and serves until ctx
// ends. Every packet gets an ACCEPT verdict: rewritten when RewriteSYN
// succeeds, unmodified otherwise. The kernel is asked to fail open (accept
// without queueing) when a queue or the listener's socket buffer is full.
func Listen(ctx context.Context, stats *Stats) error {
	var started []*nfqueue.Nfqueue
	for _, p := range Shaped() {
		q, err := listenProfile(ctx, p, stats)
		if err != nil {
			for _, s := range started {
				_ = s.Close()
			}
			return err
		}
		started = append(started, q)
	}
	return nil
}

func listenProfile(ctx context.Context, p Profile, stats *Stats) (*nfqueue.Nfqueue, error) {
	q, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      p.SYN.Queue,
		MaxPacketLen: 256, // a SYN is at most 60 (IPv4) + 60 (TCP) bytes
		MaxQueueLen:  65536,
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        nfqueue.NfQaCfgFlagFailOpen,
	})
	if err != nil {
		return nil, fmt.Errorf("open NFQUEUE %d (%s): %w", p.SYN.Queue, p.Name, err)
	}
	// A burst of SYNs (every check of a round at once) must fit in the
	// socket buffer, or the kernel fails those SYNs open (unmodified). The
	// size is capped by net.core.rmem_max. Don't stop on ENOBUFS when it
	// still overflows.
	if err := q.Con.SetReadBuffer(16 << 20); err != nil {
		slog.Warn("NFQUEUE socket buffer", "queue", p.SYN.Queue, "error", err)
	}
	_ = q.SetOption(netlink.NoENOBUFS, true)

	hook := func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		id := *a.PacketID
		stats.Seen.Add(1)
		var err error
		if a.Payload != nil {
			if out, rerr := RewriteSYN(*a.Payload, *p.SYN); rerr == nil {
				err = q.SetVerdictModPacket(id, nfqueue.NfAccept, out)
				if err == nil {
					stats.Rewritten.Add(1)
				}
			} else {
				err = q.SetVerdict(id, nfqueue.NfAccept)
				if err == nil {
					stats.PassedAsIs.Add(1)
				}
			}
		} else {
			err = q.SetVerdict(id, nfqueue.NfAccept)
		}
		if err != nil {
			stats.VerdictErrs.Add(1)
			slog.Warn("NFQUEUE verdict failed", "queue", p.SYN.Queue, "error", err)
		}
		return 0
	}
	errfn := func(e error) int {
		if errors.Is(e, context.Canceled) {
			return 1
		}
		slog.Warn("NFQUEUE read error", "queue", p.SYN.Queue, "error", e)
		return 0
	}
	if err := q.RegisterWithErrorFunc(ctx, hook, errfn); err != nil {
		_ = q.Close()
		return nil, fmt.Errorf("register NFQUEUE %d (%s): %w", p.SYN.Queue, p.Name, err)
	}
	slog.Info("SYN shaping listening", "profile", p.Name, "queue", p.SYN.Queue)
	return q, nil
}
