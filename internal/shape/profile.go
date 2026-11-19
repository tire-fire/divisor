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
//     every later window on the flow rescaled, which is not done. Divisor
//     instead raises the runner network namespace's tcp_rmem maximum so the
//     runner's real scale is at least the profile's (see EnsureRcvBufMax).
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
	// TTL is the IPv4 TTL / IPv6 hop limit packets leave Divisor with: the
	// OS's initial value, as from a real host where Divisor sits.
	TTL uint8
	// Mark carries the profile from the nftables mark chain to the SYN chain.
	Mark uint32
	// Queue is the NFQUEUE number for the profile's SYNs; 0: SYNs are left as
	// the runner kernel wrote them (its layout already is the OS's).
	Queue uint16
	// Layout is the SYN's option layout. optTS entries are written only if
	// the runner's SYN had timestamps; profiles without optTS drop them.
	Layout []byte
	// MaxScale is the window scale announced: min(real, MaxScale).
	MaxScale uint8
}

// Profiles are the OSes Quotient's checks claim. The layouts are what real
// hosts send: Windows 10/11 and Server (seen from team hosts in Invitational
// #2: mss,nop,ws 8,nop,nop,sackOK, no timestamps); macOS (mss,nop,ws 6,nop,
// nop,ts,sackOK,eol plus one byte of padding); Linux sends its own layout.
var Profiles = []Profile{
	{Name: "windows", DSCP: 7, TTL: 128, Mark: 0xd17, Queue: 7,
		Layout: []byte{optMSS, optNOP, optWS, optNOP, optNOP, optSACK}, MaxScale: 8},
	{Name: "linux", DSCP: 11, TTL: 64, Mark: 0xd11},
	{Name: "macos", DSCP: 15, TTL: 64, Mark: 0xd15, Queue: 15,
		Layout: []byte{optMSS, optNOP, optWS, optNOP, optNOP, optTS, optSACK, optEOL}, MaxScale: 6},
}

// ByQueue returns the profile whose SYNs arrive on queue q.
func ByQueue(q uint16) (Profile, bool) {
	for _, p := range Profiles {
		if p.Queue == q && q != 0 {
			return p, true
		}
	}
	return Profile{}, false
}
