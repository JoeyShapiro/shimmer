package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// DHCP magic cookie that precedes the options field (RFC 2131).
const dhcpMagicCookie uint32 = 0x63825363

// Minimum size of a BOOTP/DHCP message: the fixed header (236 bytes) plus the
// 4-byte magic cookie. Anything shorter cannot be a valid DHCP packet.
const dhcpMinLen = 240

// Op codes for the BOOTP "op" field.
type DHCPOp byte

const (
	BootRequest DHCPOp = 1
	BootReply   DHCPOp = 2
)

func (o DHCPOp) String() string {
	switch o {
	case BootRequest:
		return "BOOTREQUEST"
	case BootReply:
		return "BOOTREPLY"
	default:
		return fmt.Sprintf("op(%d)", byte(o))
	}
}

// DHCP option codes we care about. The full registry is large; these are the
// ones present in the captured traffic plus the common ones a server replies
// with.
type DHCPOptionCode byte

const (
	OptPad              DHCPOptionCode = 0
	OptSubnetMask       DHCPOptionCode = 1
	OptRouter           DHCPOptionCode = 3
	OptDNSServer        DHCPOptionCode = 6
	OptHostName         DHCPOptionCode = 12
	OptRequestedIP      DHCPOptionCode = 50
	OptLeaseTime        DHCPOptionCode = 51
	OptMessageType      DHCPOptionCode = 53
	OptServerID         DHCPOptionCode = 54
	OptParamRequestList DHCPOptionCode = 55
	OptMaxMessageSize   DHCPOptionCode = 57
	OptVendorClassID    DHCPOptionCode = 60
	OptClientID         DHCPOptionCode = 61
	OptEnd              DHCPOptionCode = 255
)

// DHCPMessageType is the value of option 53.
type DHCPMessageType byte

const (
	DHCPDiscover DHCPMessageType = 1
	DHCPOffer    DHCPMessageType = 2
	DHCPRequest  DHCPMessageType = 3
	DHCPDecline  DHCPMessageType = 4
	DHCPAck      DHCPMessageType = 5
	DHCPNak      DHCPMessageType = 6
	DHCPRelease  DHCPMessageType = 7
	DHCPInform   DHCPMessageType = 8
)

func (t DHCPMessageType) String() string {
	switch t {
	case DHCPDiscover:
		return "DISCOVER"
	case DHCPOffer:
		return "OFFER"
	case DHCPRequest:
		return "REQUEST"
	case DHCPDecline:
		return "DECLINE"
	case DHCPAck:
		return "ACK"
	case DHCPNak:
		return "NAK"
	case DHCPRelease:
		return "RELEASE"
	case DHCPInform:
		return "INFORM"
	default:
		return fmt.Sprintf("type(%d)", byte(t))
	}
}

// DHCPPacket is a parsed BOOTP/DHCP message. Options are stored raw in a map so
// callers can read anything, with typed helpers for the common fields.
type DHCPPacket struct {
	Op    DHCPOp
	HType byte // hardware address type; 1 == Ethernet
	HLen  byte // hardware address length; 6 for Ethernet
	Hops  byte
	XID   uint32 // transaction ID; ties a client's DISCOVER/REQUEST together
	Secs  uint16
	Flags uint16

	CIAddr net.IP // client IP (already bound)
	YIAddr net.IP // "your" IP (server -> client)
	SIAddr net.IP // next-server IP
	GIAddr net.IP // relay agent IP

	CHAddr net.HardwareAddr // client hardware (MAC) address
	SName  string           // optional server host name
	File   string           // optional boot file name

	Options map[DHCPOptionCode][]byte
	// OptionOrder preserves the on-wire ordering of option codes, which some
	// clients are sensitive to when we build replies.
	OptionOrder []DHCPOptionCode
}

// ParseDHCP decodes a raw DHCP message (the UDP payload, starting at the BOOTP
// "op" byte) into a DHCPPacket.
func ParseDHCP(buf []byte) (*DHCPPacket, error) {
	if len(buf) < dhcpMinLen {
		return nil, fmt.Errorf("dhcp: packet too short: %d bytes (need >= %d)", len(buf), dhcpMinLen)
	}

	if cookie := binary.BigEndian.Uint32(buf[236:240]); cookie != dhcpMagicCookie {
		return nil, fmt.Errorf("dhcp: bad magic cookie: %#08x", cookie)
	}

	p := &DHCPPacket{
		Op:      DHCPOp(buf[0]),
		HType:   buf[1],
		HLen:    buf[2],
		Hops:    buf[3],
		XID:     binary.BigEndian.Uint32(buf[4:8]),
		Secs:    binary.BigEndian.Uint16(buf[8:10]),
		Flags:   binary.BigEndian.Uint16(buf[10:12]),
		CIAddr:  net.IP(append([]byte(nil), buf[12:16]...)),
		YIAddr:  net.IP(append([]byte(nil), buf[16:20]...)),
		SIAddr:  net.IP(append([]byte(nil), buf[20:24]...)),
		GIAddr:  net.IP(append([]byte(nil), buf[24:28]...)),
		Options: make(map[DHCPOptionCode][]byte),
	}

	hlen := int(p.HLen)
	if hlen > 16 {
		hlen = 16 // chaddr field is only 16 bytes wide
	}
	p.CHAddr = net.HardwareAddr(append([]byte(nil), buf[28:28+hlen]...))
	p.SName = trimNul(buf[44:108])
	p.File = trimNul(buf[108:236])

	if err := p.parseOptions(buf[240:]); err != nil {
		return nil, err
	}
	return p, nil
}

// parseOptions walks the TLV-encoded options field. PAD (0) and END (255) are
// single bytes; every other option is code, length, then length bytes of data.
func (p *DHCPPacket) parseOptions(opts []byte) error {
	for i := 0; i < len(opts); {
		code := DHCPOptionCode(opts[i])
		if code == OptPad {
			i++
			continue
		}
		if code == OptEnd {
			break
		}
		if i+1 >= len(opts) {
			return fmt.Errorf("dhcp: truncated option %d (missing length)", code)
		}
		length := int(opts[i+1])
		start := i + 2
		if start+length > len(opts) {
			return fmt.Errorf("dhcp: option %d claims %d bytes but only %d remain", code, length, len(opts)-start)
		}
		val := append([]byte(nil), opts[start:start+length]...)
		if _, seen := p.Options[code]; !seen {
			p.OptionOrder = append(p.OptionOrder, code)
		}
		p.Options[code] = val
		i = start + length
	}
	return nil
}

// MessageType returns the DHCP message type (option 53) and whether it was
// present.
func (p *DHCPPacket) MessageType() (DHCPMessageType, bool) {
	v, ok := p.Options[OptMessageType]
	if !ok || len(v) < 1 {
		return 0, false
	}
	return DHCPMessageType(v[0]), true
}

// ParamRequestList returns the option codes the client wants us to include in
// our reply (option 55).
func (p *DHCPPacket) ParamRequestList() []DHCPOptionCode {
	raw := p.Options[OptParamRequestList]
	list := make([]DHCPOptionCode, len(raw))
	for i, b := range raw {
		list[i] = DHCPOptionCode(b)
	}
	return list
}

// String renders a human-readable one-block summary, handy for logging.
func (p *DHCPPacket) String() string {
	var b strings.Builder
	mt, ok := p.MessageType()
	mtStr := "unknown"
	if ok {
		mtStr = mt.String()
	}
	fmt.Fprintf(&b, "DHCP %s %s\n", p.Op, mtStr)
	fmt.Fprintf(&b, "  xid=%#08x flags=%#04x mac=%s\n", p.XID, p.Flags, p.CHAddr)
	fmt.Fprintf(&b, "  ci=%s yi=%s si=%s gi=%s\n", p.CIAddr, p.YIAddr, p.SIAddr, p.GIAddr)
	if h := trimNul(p.Options[OptHostName]); h != "" {
		fmt.Fprintf(&b, "  hostname=%q\n", h)
	}
	if v := trimNul(p.Options[OptVendorClassID]); v != "" {
		fmt.Fprintf(&b, "  vendor=%q\n", v)
	}
	if ip := optionIP(p.Options[OptRequestedIP]); ip != nil {
		fmt.Fprintf(&b, "  requested-ip=%s\n", ip)
	}
	if ip := optionIP(p.Options[OptServerID]); ip != nil {
		fmt.Fprintf(&b, "  server-id=%s\n", ip)
	}
	return b.String()
}

func optionIP(v []byte) net.IP {
	if len(v) != 4 {
		return nil
	}
	return net.IP(append([]byte(nil), v...))
}

func trimNul(b []byte) string {
	if i := indexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}
