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

// Stats counts what the listeners did, for logs and the lab.
type Stats struct {
	Rewritten   atomic.Uint64
	PassedAsIs  atomic.Uint64 // not rewritable (see the Err* reasons): accepted unmodified
	VerdictErrs atomic.Uint64
}

// Listen binds one NFQUEUE listener per profile that rewrites SYNs and serves
// until ctx ends. Every packet gets an ACCEPT verdict: rewritten when
// RewriteSYN succeeds, unmodified otherwise. The kernel is asked to fail open
// (accept without queueing) when a queue is full.
func Listen(ctx context.Context, stats *Stats) error {
	var started []*nfqueue.Nfqueue
	for _, p := range Profiles {
		if p.Queue == 0 {
			continue
		}
		q, err := listenProfile(ctx, p, stats)
		if err != nil {
			for _, s := range started {
				_ = s.Close()
			}
			return err
		}
		started = append(started, q)
	}
	go func() {
		<-ctx.Done()
		for _, s := range started {
			_ = s.Close()
		}
	}()
	return nil
}

func listenProfile(ctx context.Context, p Profile, stats *Stats) (*nfqueue.Nfqueue, error) {
	q, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      p.Queue,
		MaxPacketLen: 0xffff,
		MaxQueueLen:  4096,
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        nfqueue.NfQaCfgFlagFailOpen,
	})
	if err != nil {
		return nil, fmt.Errorf("open NFQUEUE %d (%s): %w", p.Queue, p.Name, err)
	}
	// Don't stop on ENOBUFS when the socket buffer overflows: the kernel
	// fails open for what didn't fit.
	_ = q.SetOption(netlink.NoENOBUFS, true)

	hook := func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		id := *a.PacketID
		var err error
		if a.Payload != nil {
			if out, rerr := RewriteSYN(*a.Payload, p); rerr == nil {
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
			slog.Warn("NFQUEUE verdict failed", "queue", p.Queue, "error", err)
		}
		return 0
	}
	errfn := func(e error) int {
		if errors.Is(e, context.Canceled) {
			return 1
		}
		slog.Warn("NFQUEUE read error", "queue", p.Queue, "error", e)
		return 0
	}
	if err := q.RegisterWithErrorFunc(ctx, hook, errfn); err != nil {
		_ = q.Close()
		return nil, fmt.Errorf("register NFQUEUE %d (%s): %w", p.Queue, p.Name, err)
	}
	slog.Info("SYN shaping listening", "profile", p.Name, "queue", p.Queue)
	return q, nil
}
