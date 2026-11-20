package shape

import (
	"encoding/binary"
	"errors"
)

// Reasons a packet is passed through unmodified. They are counted, not
// fatal: an unmodified SYN only means the runner's own fingerprint shows.
var (
	ErrNotTCPSYN   = errors.New("not a TCP SYN without ACK")
	ErrUnsupported = errors.New("fragment, IPv6 extension header or SYN with payload")
	ErrOptions     = errors.New("SYN options can't be rewritten safely")
)

// synOptions are the options of a runner SYN that a layout can use.
type synOptions struct {
	mss          uint16
	ws           uint8
	hasMSS       bool
	hasWS        bool
	hasSACK      bool
	hasTS        bool
	tsVal, tsEcr uint32
}

// RewriteSYN returns pkt (an IPv4 or IPv6 packet, as NFQUEUE delivers it)
// with its TCP SYN options in p's layout and the window scale lowered to
// p.MaxScale, with lengths and checksums fixed. Only SYNs without ACK are
// rewritten. An error means pkt must be passed on unmodified.
func RewriteSYN(pkt []byte, p Profile) ([]byte, error) {
	if len(pkt) < 1 {
		return nil, ErrNotTCPSYN
	}
	var ipHdrLen int
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return nil, ErrNotTCPSYN
		}
		ipHdrLen = int(pkt[0]&0x0f) * 4
		if pkt[9] != 6 || ipHdrLen < 20 || len(pkt) < ipHdrLen+20 {
			return nil, ErrNotTCPSYN
		}
		if binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 { // MF or fragment offset
			return nil, ErrUnsupported
		}
		if int(binary.BigEndian.Uint16(pkt[2:4])) != len(pkt) {
			return nil, ErrUnsupported
		}
	case 6:
		ipHdrLen = 40
		if len(pkt) < ipHdrLen+20 {
			return nil, ErrNotTCPSYN
		}
		if pkt[6] != 6 { // extension headers: leave alone
			return nil, ErrUnsupported
		}
		if int(binary.BigEndian.Uint16(pkt[4:6]))+40 != len(pkt) {
			return nil, ErrUnsupported
		}
	default:
		return nil, ErrNotTCPSYN
	}

	tcp := pkt[ipHdrLen:]
	if tcp[13]&0x12 != 0x02 { // SYN set, ACK clear
		return nil, ErrNotTCPSYN
	}
	tcpHdrLen := int(tcp[12]>>4) * 4
	if tcpHdrLen < 20 || tcpHdrLen > len(tcp) {
		return nil, ErrOptions
	}
	if len(tcp) != tcpHdrLen { // SYN with data (TCP Fast Open)
		return nil, ErrUnsupported
	}
	in, err := parseSYNOptions(tcp[20:tcpHdrLen])
	if err != nil {
		return nil, err
	}

	opts, err := buildOptions(in, p)
	if err != nil {
		return nil, err
	}

	out := make([]byte, ipHdrLen+20+len(opts))
	copy(out, pkt[:ipHdrLen])
	copy(out[ipHdrLen:], tcp[:20])
	copy(out[ipHdrLen+20:], opts)
	ntcp := out[ipHdrLen:]
	ntcp[12] = byte((20+len(opts))/4)<<4 | ntcp[12]&0x0f
	ntcp[16], ntcp[17] = 0, 0
	if in.hasMSS {
		binary.BigEndian.PutUint16(ntcp[14:16], synWindow(binary.BigEndian.Uint16(ntcp[14:16]), in.mss, p.SYNWindow))
	}

	if out[0]>>4 == 4 {
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		out[10], out[11] = 0, 0
		binary.BigEndian.PutUint16(out[10:12], checksum(out[:ipHdrLen], 0))
		var pseudo [12]byte
		copy(pseudo[0:8], out[12:20])
		pseudo[9] = 6
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(ntcp)))
		binary.BigEndian.PutUint16(ntcp[16:18], checksum(ntcp, sum(pseudo[:])))
	} else {
		binary.BigEndian.PutUint16(out[4:6], uint16(len(ntcp)))
		var pseudo [40]byte
		copy(pseudo[0:32], out[8:40])
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(ntcp)))
		pseudo[39] = 6
		binary.BigEndian.PutUint16(ntcp[16:18], checksum(ntcp, sum(pseudo[:])))
	}
	return out, nil
}

// synWindow is the window field the SYN leaves with. A SYN's window is not
// scaled, and it only bounds what the server may send before the client's
// handshake ACK, which carries the real, scaled window. Linux announces its
// receive space rounded down to a multiple of the MSS, capped at 65535; the
// runner's real space is then within one MSS above what it announced. So the
// profile's window replaces the runner's only when it is higher by less than
// one MSS (64240 -> 65535 with MSS 1460): an over-statement of under one
// segment for less than a round trip, while the server's initial congestion
// window (10 segments) is far below either value. Anything else is kept: a
// runner window already at the profile's, a smaller buffer, or a SYN from a
// non-Linux stack.
func synWindow(runner, mss, profile uint16) uint16 {
	if profile == 0 || runner >= profile || mss == 0 || uint32(runner)+uint32(mss) <= uint32(profile) {
		return runner
	}
	return profile
}

func parseSYNOptions(b []byte) (synOptions, error) {
	var o synOptions
	for i := 0; i < len(b); {
		switch b[i] {
		case optEOL:
			return o, nil
		case optNOP:
			i++
			continue
		}
		if i+1 >= len(b) || b[i+1] < 2 || i+int(b[i+1]) > len(b) {
			return o, ErrOptions
		}
		v := b[i+2 : i+int(b[i+1])]
		switch {
		case b[i] == optMSS && len(v) == 2:
			o.mss, o.hasMSS = binary.BigEndian.Uint16(v), true
		case b[i] == optWS && len(v) == 1:
			o.ws, o.hasWS = v[0], true
		case b[i] == optSACK && len(v) == 0:
			o.hasSACK = true
		case b[i] == optTS && len(v) == 8:
			o.tsVal, o.tsEcr, o.hasTS = binary.BigEndian.Uint32(v), binary.BigEndian.Uint32(v[4:]), true
		default:
			// MD5 signature, MPTCP, TFO cookie, ...: not ours to reorder.
			return o, ErrOptions
		}
		i += int(b[i+1])
	}
	return o, nil
}

// buildOptions writes p's layout from the runner's options. It never invents
// an option the runner didn't send (a scale without window scaling, SACK the
// stack didn't offer), and it only lowers the window scale.
func buildOptions(in synOptions, p Profile) ([]byte, error) {
	var out []byte
	for _, kind := range p.Layout {
		switch kind {
		case optNOP:
			out = append(out, optNOP)
		case optEOL:
			out = append(out, optEOL)
		case optMSS:
			if !in.hasMSS {
				return nil, ErrOptions
			}
			out = append(out, optMSS, 4, byte(in.mss>>8), byte(in.mss))
		case optWS:
			if !in.hasWS {
				return nil, ErrOptions
			}
			out = append(out, optWS, 3, min(in.ws, p.MaxScale))
		case optSACK:
			if !in.hasSACK {
				return nil, ErrOptions
			}
			out = append(out, optSACK, 2)
		case optTS:
			if !in.hasTS {
				return nil, ErrOptions
			}
			out = append(out, optTS, 10)
			out = binary.BigEndian.AppendUint32(out, in.tsVal)
			out = binary.BigEndian.AppendUint32(out, in.tsEcr)
		}
	}
	for len(out)%4 != 0 {
		out = append(out, optEOL)
	}
	if len(out) > 40 {
		return nil, ErrOptions
	}
	return out, nil
}

func sum(b []byte) uint32 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	return s
}

// checksum is the Internet checksum of b, starting from partial sum init.
func checksum(b []byte, init uint32) uint16 {
	s := init + sum(b)
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}
