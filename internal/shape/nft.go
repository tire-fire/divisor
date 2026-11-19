package shape

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// TableName is the nftables table Divisor owns for shaping. Address rotation
// never touches it: it matches the runner's DSCP mark, not addresses.
const TableName = "divisor_shape"

// Ruleset renders the shaping table for traffic to targets (CIDRs).
//
// Chain "profile" (postrouting, priority -200, before SNAT at 100): a packet
// with a profile's DSCP gets the profile's TTL / hop limit, its DSCP cleared
// and the profile's mark. Chain "synopts" (priority -190): a profile's SYN
// without ACK goes to the profile's NFQUEUE. "bypass" passes packets on
// unmodified when no listener is bound, and the listener asks the kernel to
// fail open when its queue is full: a missing or busy Divisor shows the
// runner's own fingerprint but never drops a connection.
func Ruleset(targets []string) (string, error) {
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
	for _, p := range Profiles {
		if len(v4) > 0 {
			fmt.Fprintf(&b, "\t\tip daddr { %s } ip dscp %d meta mark set 0x%x ct mark set 0x%x ip dscp set cs0 ip ttl set %d\n", strings.Join(v4, ", "), p.DSCP, p.Mark, p.Mark, p.TTL)
			// Packets the runner kernel sends for the flow without the
			// socket, so without its DSCP (an RST answering a segment that
			// arrives after close): the flow's conntrack mark still says
			// which OS it claims.
			fmt.Fprintf(&b, "\t\tip daddr { %s } ct mark 0x%x ip ttl set %d\n", strings.Join(v4, ", "), p.Mark, p.TTL)
		}
		if len(v6) > 0 {
			fmt.Fprintf(&b, "\t\tip6 daddr { %s } ip6 dscp %d meta mark set 0x%x ct mark set 0x%x ip6 dscp set cs0 ip6 hoplimit set %d\n", strings.Join(v6, ", "), p.DSCP, p.Mark, p.Mark, p.TTL)
			fmt.Fprintf(&b, "\t\tip6 daddr { %s } ct mark 0x%x ip6 hoplimit set %d\n", strings.Join(v6, ", "), p.Mark, p.TTL)
		}
	}
	b.WriteString("\t}\n\tchain synopts {\n\t\ttype filter hook postrouting priority -190; policy accept;\n")
	for _, p := range Profiles {
		if p.Queue == 0 {
			continue
		}
		fmt.Fprintf(&b, "\t\tmeta mark 0x%x tcp flags & (syn | ack) == syn queue flags bypass to %d\n", p.Mark, p.Queue)
	}
	b.WriteString("\t}\n}\n")
	return b.String(), nil
}

// Install loads the shaping table into the current network namespace.
func Install(targets []string) error {
	rs, err := Ruleset(targets)
	if err != nil {
		return err
	}
	return nft(rs)
}

// Remove deletes the shaping table.
func Remove() error {
	return nft(fmt.Sprintf("table inet %s {}\ndelete table inet %s\n", TableName, TableName))
}

func nft(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}
