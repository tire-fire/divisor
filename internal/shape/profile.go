// Package shape makes the TCP/IP fingerprint of runner traffic match the
// operating system each check claims (its User-Agent, workstation name or
// client banner), on the way out of Divisor.
//
// The runner marks every socket with a DSCP value per claimed OS
// (QUOTIENT_PROFILE_MARK=dscp in Quotient). Divisor's nftables table turns the
// mark into the profile's TTL, clears the DSCP before packets leave, and hands
// SYNs (only SYNs) of profiles with their own option layout to an NFQUEUE
// listener, which rewrites the SYN's options. Nothing after the SYN is
// rewritten, so there is no per-flow state:
//   - TCP timestamps dropped from a SYN make the client kernel run the whole
//     flow without them, because the server's SYN-ACK then carries none;
//   - the window scale is only ever lowered (min of the real and the
//     profile's), so every box after Divisor reads the same, smaller window
//     and nobody can send more than the client can take. Raising it would need
//     every later window on the flow rescaled, which is not done. The runner's
//     container must be given an 8 MiB tcp_rmem maximum (README), so its
//     per-profile window clamps (8/4/2 MiB) give the real scales 8/7/6.
package shape

// Option kinds as they appear in a SYN layout.
const (
	optEOL  byte = 0
	optNOP  byte = 1
	optMSS  byte = 2
	optWS   byte = 3
	optSACK byte = 4 // SACK permitted
	optTS   byte = 8
)

// A Profile is one claimed OS.
type Profile struct {
	Name string
	// DSCP is the mark the runner sets on the profile's sockets (RFC 2474
	// pool 2, experimental/local use). Divisor clears it before the wire.
	DSCP uint8
	// TTL is the OS's initial IPv4 TTL / IPv6 hop limit; Ruleset adds
	// SHAPE_EXTRA_HOPS.
	TTL uint8
	// Mark carries the profile from the nftables profile chain to the SYN
	// chain and, as the conntrack mark, to the flow's later packets.
	Mark uint32
	// SYN is how the profile's SYNs are rewritten; nil leaves them as the
	// runner kernel wrote them (its layout already is the OS's).
	SYN *SYNShape
}

// SYNShape is a profile's SYN rewrite.
type SYNShape struct {
	// Queue is the NFQUEUE number the profile's SYNs are handed to.
	Queue uint16
	// Layout is the SYN's option layout. A layout option the runner's SYN
	// lacks (optTS from a socket without timestamps) fails the rewrite; a
	// layout without optTS drops the runner's timestamps.
	Layout []byte
	// MaxScale is the window scale announced: min(real, MaxScale).
	MaxScale uint8
	// SYNWindow, when set, is the OS's SYN window; see synWindow.
	SYNWindow uint16
}

// Profiles are the OSes Quotient's checks claim. The layouts are what real
// hosts send: Windows 10/11 and Server (seen from team hosts in Invitational
// #2: mss,nop,ws 8,nop,nop,sackOK, no timestamps); macOS (mss,nop,ws 6,nop,
// nop,ts,sackOK,eol plus one byte of padding); Linux sends its own layout.
var Profiles = []Profile{
	{Name: "windows", DSCP: 7, TTL: 128, Mark: 0xd17, SYN: &SYNShape{Queue: 7,
		Layout: []byte{optMSS, optNOP, optWS, optNOP, optNOP, optSACK}, MaxScale: 8}},
	{Name: "linux", DSCP: 11, TTL: 64, Mark: 0xd11},
	{Name: "macos", DSCP: 15, TTL: 64, Mark: 0xd15, SYN: &SYNShape{Queue: 15,
		Layout: []byte{optMSS, optNOP, optWS, optNOP, optNOP, optTS, optSACK, optEOL}, MaxScale: 6, SYNWindow: 65535}},
}

// Shaped returns the profiles whose SYNs are rewritten.
func Shaped() []Profile {
	var out []Profile
	for _, p := range Profiles {
		if p.SYN != nil {
			out = append(out, p)
		}
	}
	return out
}
