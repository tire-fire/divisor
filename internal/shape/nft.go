package shape

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// TableName is the nftables table Divisor owns for shaping. Address rotation
// never touches it: its rules match the runner's DSCP mark and TARGET_SUBNETS,
// not the rotated SNAT addresses.
const TableName = "divisor_shape"

// Ruleset renders the shaping table for traffic to targets (CIDRs). Packets
// leave with each profile's TTL plus extraHops, for the routers between
// Divisor and the point where a real host of that OS would sit (direct mode:
// the node hop after the runner pod).
//
// Chain "profile" (postrouting, priority -200, before SNAT at 100): a packet
// to a target with a profile's DSCP gets the profile's TTL / hop limit, its
// DSCP cleared and the profile's mark. Profile DSCP values are cleared on
// every other destination too, so a mark never leaves the host. Chain
// "synopts" (priority -190): a shaped profile's SYN without ACK goes to the
// profile's NFQUEUE. With no listener bound, or a full queue or socket buffer,
// the kernel passes the SYN on unmodified (fail-open, the runner's own
// fingerprint shows); a bound but stalled listener holds SYNs until the
// watchdog empties this chain (see Watchdog).
func Ruleset(targets []string, extraHops int) (string, error) {
	var v4, v6 []string
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		ip, n, err := net.ParseCIDR(t)
		if err != nil {
			return "", fmt.Errorf("invalid target subnet %q: %w", t, err)
		}
		if ip.To4() != nil {
			v4 = append(v4, n.String())
		} else {
			v6 = append(v6, n.String())
		}
	}
	if len(v4)+len(v6) == 0 {
		return "", fmt.Errorf("no target subnets to shape")
	}

	var b bytes.Buffer
	// Declaring the table first makes the delete succeed on a fresh host,
	// so the file replaces any previous version atomically.
	fmt.Fprintf(&b, "table inet %s {}\ndelete table inet %s\ntable inet %s {\n", TableName, TableName, TableName)
	b.WriteString("\tchain profile {\n\t\ttype filter hook postrouting priority -200; policy accept;\n")
	var dscps []string
	for _, p := range Profiles {
		ttl := int(p.TTL) + extraHops
		dscps = append(dscps, fmt.Sprint(p.DSCP))
		if len(v4) > 0 {
			fmt.Fprintf(&b, "\t\tip daddr { %s } ip dscp %d meta mark set 0x%x ct mark set 0x%x ip dscp set cs0 ip ttl set %d\n", strings.Join(v4, ", "), p.DSCP, p.Mark, p.Mark, ttl)
			// Packets the runner kernel sends for the flow without the
			// socket, so without its DSCP (an RST answering a segment that
			// arrives after close): the flow's conntrack mark still says
			// which OS it claims.
			fmt.Fprintf(&b, "\t\tip daddr { %s } ct mark 0x%x ip ttl set %d\n", strings.Join(v4, ", "), p.Mark, ttl)
		}
		if len(v6) > 0 {
			fmt.Fprintf(&b, "\t\tip6 daddr { %s } ip6 dscp %d meta mark set 0x%x ct mark set 0x%x ip6 dscp set cs0 ip6 hoplimit set %d\n", strings.Join(v6, ", "), p.DSCP, p.Mark, p.Mark, ttl)
			fmt.Fprintf(&b, "\t\tip6 daddr { %s } ct mark 0x%x ip6 hoplimit set %d\n", strings.Join(v6, ", "), p.Mark, ttl)
		}
	}
	// Any destination: a check that reaches a host outside TARGET_SUBNETS, or
	// over IPv6 without an IPv6 target, must not carry the mark either.
	fmt.Fprintf(&b, "\t\tip dscp { %s } ip dscp set cs0\n", strings.Join(dscps, ", "))
	fmt.Fprintf(&b, "\t\tip6 dscp { %s } ip6 dscp set cs0\n", strings.Join(dscps, ", "))
	b.WriteString("\t}\n\tchain synopts {\n\t\ttype filter hook postrouting priority -190; policy accept;\n")
	for _, r := range synoptsRules() {
		fmt.Fprintf(&b, "\t\t%s\n", r)
	}
	b.WriteString("\t}\n}\n")
	return b.String(), nil
}

// Install loads the shaping table into the current network namespace.
func Install(targets []string, extraHops int) error {
	rs, err := Ruleset(targets, extraHops)
	if err != nil {
		return err
	}
	return nft(rs)
}

// synoptsRules hands each shaped profile's SYNs (without ACK) to its NFQUEUE.
func synoptsRules() []string {
	var rules []string
	for _, p := range Shaped() {
		rules = append(rules, fmt.Sprintf("meta mark 0x%x tcp flags & (syn | ack) == syn queue flags bypass to %d", p.Mark, p.SYN.Queue))
	}
	return rules
}

const flushSynopts = "flush chain inet " + TableName + " synopts\n"

// RestoreScript puts the queue rules back, replacing whatever the chain holds.
func RestoreScript() string {
	var b strings.Builder
	b.WriteString(flushSynopts)
	for _, r := range synoptsRules() {
		fmt.Fprintf(&b, "add rule inet %s synopts %s\n", TableName, r)
	}
	return b.String()
}

// Bypass empties the synopts chain: SYNs leave unshaped, while the profile
// chain still sets the TTL and clears the DSCP. Restore puts the queue rules
// back.
func Bypass() error  { return nft(flushSynopts) }
func Restore() error { return nft(RestoreScript()) }

// ErrNoTable means nft found no shaping table (or synopts chain) in this
// network namespace.
var ErrNoTable = errors.New("no " + TableName + " table")

// ChainState is what the synopts chain does.
type ChainState int

const (
	ChainQueueing ChainState = iota // hands shaped profiles' SYNs to the queues
	ChainBypassed                   // emptied: SYNs leave unshaped
)

// SynoptsState reads the synopts chain; ErrNoTable when there is no table.
func SynoptsState() (ChainState, error) {
	out, err := exec.Command("nft", "list", "chain", "inet", TableName, "synopts").CombinedOutput()
	if err != nil {
		return 0, nftError(err, out)
	}
	if bytes.Contains(out, []byte(" queue ")) {
		return ChainQueueing, nil
	}
	return ChainBypassed, nil
}

func nft(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nftError(err, out)
	}
	return nil
}

func nftError(err error, out []byte) error {
	if bytes.Contains(out, []byte("No such file or directory")) {
		return ErrNoTable
	}
	return fmt.Errorf("nft: %w: %s", err, bytes.TrimSpace(out))
}
