package shape

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// linuxSYNOptions is what a Linux kernel writes: mss 1460, sackOK, TS, nop, ws.
func linuxSYNOptions(ws byte) []byte {
	return []byte{2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0x12, 0x34, 0, 0, 0, 0, 1, 3, 3, ws}
}

func tcpHeader(flags byte, opts []byte) []byte {
	h := make([]byte, 20, 20+len(opts))
	binary.BigEndian.PutUint16(h[0:], 40000)
	binary.BigEndian.PutUint16(h[2:], 443)
	binary.BigEndian.PutUint32(h[4:], 0xa1b2c3d4)
	h[12] = byte((20+len(opts))/4) << 4
	h[13] = flags
	binary.BigEndian.PutUint16(h[14:], 64240)
	return append(h, opts...)
}

func ipv4Packet(tcp []byte) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
	binary.BigEndian.PutUint16(ip[4:], 0x1234)
	ip[6] = 0x40 // DF
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:], []byte{10, 192, 7, 9})
	copy(ip[16:], []byte{10, 100, 1, 10})
	binary.BigEndian.PutUint16(ip[10:], checksum(ip, 0))
	pkt := append(ip, tcp...)
	t := pkt[20:]
	var pseudo [12]byte
	copy(pseudo[:8], pkt[12:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(t)))
	binary.BigEndian.PutUint16(t[16:], checksum(t, sum(pseudo[:])))
	return pkt
}

func ipv6Packet(tcp []byte) []byte {
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(tcp)))
	ip[6] = 6
	ip[7] = 64
	ip[8], ip[9], ip[23] = 0xfd, 0x00, 1
	ip[24], ip[25], ip[39] = 0xfd, 0x00, 2
	pkt := append(ip, tcp...)
	t := pkt[40:]
	var pseudo [40]byte
	copy(pseudo[:32], pkt[8:40])
	binary.BigEndian.PutUint32(pseudo[32:], uint32(len(t)))
	pseudo[39] = 6
	binary.BigEndian.PutUint16(t[16:], checksum(t, sum(pseudo[:])))
	return pkt
}

// valid checks the IPv4 header and TCP checksums the way a receiver does.
func validV4(t *testing.T, pkt []byte) {
	t.Helper()
	ihl := int(pkt[0]&15) * 4
	if checksum(pkt[:ihl], 0) != 0 {
		t.Fatalf("bad IPv4 header checksum")
	}
	if int(binary.BigEndian.Uint16(pkt[2:])) != len(pkt) {
		t.Fatalf("IPv4 total length %d, packet %d", binary.BigEndian.Uint16(pkt[2:]), len(pkt))
	}
	var pseudo [12]byte
	copy(pseudo[:8], pkt[12:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(pkt)-ihl))
	if checksum(pkt[ihl:], sum(pseudo[:])) != 0 {
		t.Fatalf("bad TCP checksum")
	}
}

func profile(name string) Profile {
	for _, p := range Profiles {
		if p.Name == name {
			return p
		}
	}
	panic(name)
}

func TestRewriteSYNWindows(t *testing.T) {
	in := ipv4Packet(tcpHeader(0x02, linuxSYNOptions(8)))
	out, err := RewriteSYN(in, profile("windows"))
	if err != nil {
		t.Fatal(err)
	}
	validV4(t, out)
	want := []byte{2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2}
	if got := out[40:]; !bytes.Equal(got, want) {
		t.Fatalf("options %v, want Windows' %v", got, want)
	}
	if out[32]>>4 != 8 || len(out) != 52 {
		t.Fatalf("TCP header %d bytes, packet %d; want 32 and 52", int(out[32]>>4)*4, len(out))
	}
	// Everything else in the headers is the runner's.
	if !bytes.Equal(out[20:32], in[20:32]) || out[8] != in[8] || !bytes.Equal(out[12:20], in[12:20]) || out[34] != in[34] || out[35] != in[35] {
		t.Fatal("rewrite changed ports, sequence number, flags, window, TTL or addresses")
	}
}

func TestRewriteSYNWindowScaleOnlyLowered(t *testing.T) {
	for real, want := range map[byte]byte{10: 8, 9: 8, 8: 8, 7: 7, 2: 2} {
		out, err := RewriteSYN(ipv4Packet(tcpHeader(0x02, linuxSYNOptions(real))), profile("windows"))
		if err != nil {
			t.Fatal(err)
		}
		if out[47] != want {
			t.Errorf("runner scale %d announced as %d, want %d", real, out[47], want)
		}
	}
}

func TestRewriteSYNMacOSKeepsTimestamps(t *testing.T) {
	out, err := RewriteSYN(ipv4Packet(tcpHeader(0x02, linuxSYNOptions(7))), profile("macos"))
	if err != nil {
		t.Fatal(err)
	}
	validV4(t, out)
	want := []byte{2, 4, 0x05, 0xb4, 1, 3, 3, 6, 1, 1, 8, 10, 0, 0, 0x12, 0x34, 0, 0, 0, 0, 4, 2, 0, 0}
	if got := out[40:]; !bytes.Equal(got, want) {
		t.Fatalf("options %v, want macOS' %v", got, want)
	}
}

func TestRewriteSYNIPv6(t *testing.T) {
	out, err := RewriteSYN(ipv6Packet(tcpHeader(0x02, linuxSYNOptions(9))), profile("windows"))
	if err != nil {
		t.Fatal(err)
	}
	if int(binary.BigEndian.Uint16(out[4:]))+40 != len(out) || len(out) != 72 {
		t.Fatalf("IPv6 payload length %d for %d-byte packet", binary.BigEndian.Uint16(out[4:]), len(out))
	}
	var pseudo [40]byte
	copy(pseudo[:32], out[8:40])
	binary.BigEndian.PutUint32(pseudo[32:], uint32(len(out)-40))
	pseudo[39] = 6
	if checksum(out[40:], sum(pseudo[:])) != 0 {
		t.Fatal("bad TCP checksum")
	}
	if !bytes.Equal(out[60:], []byte{2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2}) {
		t.Fatalf("options %v", out[60:])
	}
}

func TestRewriteSYNLeavesOtherPacketsAlone(t *testing.T) {
	opts := linuxSYNOptions(7)
	frag := ipv4Packet(tcpHeader(0x02, opts))
	frag[6] |= 0x20 // MF
	withData := ipv4Packet(append(tcpHeader(0x02, opts), 'x'))
	binary.BigEndian.PutUint16(withData[2:], uint16(len(withData)))
	md5 := append([]byte{1, 1, 19, 18}, make([]byte, 16)...)
	cases := map[string]struct {
		pkt  []byte
		want error
	}{
		"SYN-ACK":             {ipv4Packet(tcpHeader(0x12, opts)), ErrNotTCPSYN},
		"ACK":                 {ipv4Packet(tcpHeader(0x10, nil)), ErrNotTCPSYN},
		"fragment":            {frag, ErrUnsupported},
		"SYN with data (TFO)": {withData, ErrUnsupported},
		"TCP-MD5 option":      {ipv4Packet(tcpHeader(0x02, append(append([]byte{}, opts...), md5...))), ErrOptions},
		"no window scaling":   {ipv4Packet(tcpHeader(0x02, []byte{2, 4, 5, 0xb4, 4, 2, 1, 1})), ErrOptions},
		"truncated option":    {ipv4Packet(tcpHeader(0x02, []byte{2, 4, 5, 0xb4, 1, 1, 3, 9})), ErrOptions},
	}
	for name, c := range cases {
		if _, err := RewriteSYN(c.pkt, profile("windows")); !errors.Is(err, c.want) {
			t.Errorf("%s: err %v, want %v", name, err, c.want)
		}
	}
	noTS := ipv4Packet(tcpHeader(0x02, []byte{2, 4, 5, 0xb4, 1, 1, 4, 2, 1, 3, 3, 7}))
	if _, err := RewriteSYN(noTS, profile("macos")); !errors.Is(err, ErrOptions) {
		t.Errorf("macOS layout from a SYN without timestamps: err %v, want ErrOptions (never invent TS)", err)
	}
}

func TestRulesetRejectsBadTargets(t *testing.T) {
	if _, err := Ruleset([]string{"10.100.0.0/33"}); err == nil {
		t.Error("invalid CIDR accepted")
	}
	if _, err := Ruleset([]string{" ", ""}); err == nil {
		t.Error("a table that shapes nothing accepted")
	}
}

func TestRewriteSYNMacOSWindow(t *testing.T) {
	for runner, want := range map[uint16]uint16{
		64240: 65535, // Linux's 65536-byte space rounded down to MSS 1460
		65535: 65535, // runner already sends macOS's window (SO_RCVBUF)
		62780: 62780, // more than one MSS below: a smaller real buffer, keep
		29200: 29200,
	} {
		tcp := tcpHeader(0x02, linuxSYNOptions(7))
		binary.BigEndian.PutUint16(tcp[14:], runner)
		out, err := RewriteSYN(ipv4Packet(tcp), profile("macos"))
		if err != nil {
			t.Fatal(err)
		}
		validV4(t, out)
		if got := binary.BigEndian.Uint16(out[34:]); got != want {
			t.Errorf("runner window %d left as %d, want %d", runner, got, want)
		}
	}
	// Windows 10/11 send 64240 themselves: never raised.
	out, err := RewriteSYN(ipv4Packet(tcpHeader(0x02, linuxSYNOptions(8))), profile("windows"))
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(out[34:]); got != 64240 {
		t.Errorf("Windows SYN window %d, want the runner's 64240", got)
	}
}
