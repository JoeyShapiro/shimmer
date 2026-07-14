package main

import (
	"fmt"
	"net"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
)

// nl80211 commands/attributes for management-frame registration and
// RX/TX, not covered by the constants in hostapd.go.
const (
	NL80211_CMD_REGISTER_FRAME = 58
	NL80211_CMD_FRAME          = 59

	NL80211_ATTR_FRAME       = 51
	NL80211_ATTR_FRAME_MATCH = 91
	NL80211_ATTR_FRAME_TYPE  = 101
)

// 802.11 frame control type/subtype byte (the first byte of the MAC header):
// type occupies bits 2-3, subtype bits 4-7. These match the values already
// used in buildBeaconHead (0x80 = beacon) and buildBeaconResponse (0x50 =
// probe response).
const (
	ieee80211FCAssocReq   = 0x00
	ieee80211FCReassocReq = 0x20
	ieee80211FCAuth       = 0xb0
	ieee80211FCDeauth     = 0xc0
	ieee80211FCDisassoc   = 0xa0
)

// mgmtSubtypeName returns a human-readable label for a frame control byte's
// type/subtype bits, for logging.
func mgmtSubtypeName(fc byte) string {
	switch fc & 0xf0 {
	case 0x00:
		return "assoc-req"
	case 0x10:
		return "assoc-resp"
	case 0x20:
		return "reassoc-req"
	case 0x30:
		return "reassoc-resp"
	case 0x40:
		return "probe-req"
	case 0x50:
		return "probe-resp"
	case 0x80:
		return "beacon"
	case 0xa0:
		return "disassoc"
	case 0xb0:
		return "auth"
	case 0xc0:
		return "deauth"
	case 0xd0:
		return "action"
	default:
		return fmt.Sprintf("mgmt(%#02x)", fc&0xf0)
	}
}

// mlmeGroupID finds the "mlme" multicast group id in a resolved nl80211
// family. The kernel delivers authentication/association/deauth frame
// events on this group.
func mlmeGroupID(family genetlink.Family) (uint32, error) {
	for _, g := range family.Groups {
		if g.Name == "mlme" {
			return g.ID, nil
		}
	}
	return 0, fmt.Errorf(`nl80211 family has no "mlme" multicast group`)
}

// registerFrameType tells the kernel to deliver every management frame
// matching fc's type/subtype on this interface to conn as an
// NL80211_CMD_FRAME notification. It doesn't ack, so there's nothing to
// receive after sending it.
func registerFrameType(conn *genetlink.Conn, familyID uint16, ifindex int, fc byte) error {
	b, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: NL80211_ATTR_IFINDEX, Data: nlenc.Uint32Bytes(uint32(ifindex))},
		{Type: NL80211_ATTR_FRAME_TYPE, Data: nlenc.Uint16Bytes(uint16(fc))},
		{Type: NL80211_ATTR_FRAME_MATCH, Data: []byte{}},
	})
	if err != nil {
		return fmt.Errorf("marshal REGISTER_FRAME attributes: %w", err)
	}

	_, err = conn.Send(genetlink.Message{
		Header: genetlink.Header{Command: NL80211_CMD_REGISTER_FRAME},
		Data:   b,
	}, familyID, netlink.Request)
	if err != nil {
		return fmt.Errorf("send REGISTER_FRAME(%s): %w", mgmtSubtypeName(fc), err)
	}
	return nil
}

// openMgmtListener opens a dedicated nl80211 genetlink socket for receiving
// management frames on ifindex: it registers interest in the frame types
// needed to complete a client's connection (auth, (re)assoc request, deauth,
// disassoc) and joins the "mlme" multicast group.
//
// This is a separate connection from the one HostAPD uses for one-shot AP
// setup commands, so asynchronous multicast notifications never get
// interleaved with a synchronous request/reply on the same socket.
func openMgmtListener(ifindex int) (*genetlink.Conn, error) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("dial genetlink: %w", err)
	}

	family, err := conn.GetFamily("nl80211")
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("get nl80211 family: %w", err)
	}

	for _, fc := range []byte{ieee80211FCAuth, ieee80211FCAssocReq, ieee80211FCReassocReq, ieee80211FCDeauth, ieee80211FCDisassoc} {
		if err := registerFrameType(conn, family.ID, ifindex, fc); err != nil {
			conn.Close()
			return nil, err
		}
	}

	groupID, err := mlmeGroupID(family)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.JoinGroup(groupID); err != nil {
		conn.Close()
		return nil, fmt.Errorf("join mlme multicast group: %w", err)
	}

	return conn, nil
}

// listenMgmtFrames blocks, logging every management frame the kernel
// delivers on conn. This is step one of handling client connections: before
// building actual authentication/association replies, confirm the client's
// frames are reaching us at all.
func listenMgmtFrames(conn *genetlink.Conn) {
	for {
		msgs, _, err := conn.Receive()
		if err != nil {
			fmt.Printf("mgmt: receive error: %v\n", err)
			return
		}

		for _, msg := range msgs {
			if msg.Header.Command != NL80211_CMD_FRAME {
				continue
			}

			attrs, err := netlink.UnmarshalAttributes(msg.Data)
			if err != nil {
				fmt.Printf("mgmt: unmarshal attributes: %v\n", err)
				continue
			}

			var frame []byte
			for _, a := range attrs {
				if a.Type == NL80211_ATTR_FRAME {
					frame = a.Data
				}
			}
			if len(frame) < 24 {
				continue // shorter than a full 802.11 MAC header
			}

			fc := frame[0]
			src := net.HardwareAddr(append([]byte(nil), frame[10:16]...))
			fmt.Printf("mgmt: %s from %s\n", mgmtSubtypeName(fc), src)
		}
	}
}
