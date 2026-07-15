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

// mgmtResponder replies to client management frames. It holds its own
// genetlink connection, separate from the one used to listen for incoming
// frames: that connection is joined to the "mlme" multicast group and is
// only ever read from a single goroutine, so a synchronous request/reply
// issued on it (send a command, then read back its ack) could easily read
// an unrelated broadcast frame notification instead of its own ack. Keeping
// a dedicated connection for outbound commands (used only for
// request/reply, never joined to any multicast group) avoids that.
type mgmtResponder struct {
	conn     *genetlink.Conn
	familyID uint16
	ifindex  int
	apMAC    net.HardwareAddr
}

// newMgmtResponder dials a fresh genetlink connection for transmitting
// frames and station commands back to clients on ifindex.
func newMgmtResponder(ifindex int, apMAC net.HardwareAddr) (*mgmtResponder, error) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("dial genetlink: %w", err)
	}

	family, err := conn.GetFamily("nl80211")
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("get nl80211 family: %w", err)
	}

	return &mgmtResponder{conn: conn, familyID: family.ID, ifindex: ifindex, apMAC: apMAC}, nil
}

func (r *mgmtResponder) Close() error {
	return r.conn.Close()
}

// sendFrame transmits a raw 802.11 frame on the AP's operating channel and
// waits for the kernel to ack accepting it for transmission.
func (r *mgmtResponder) sendFrame(frame []byte) error {
	b, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: NL80211_ATTR_IFINDEX, Data: nlenc.Uint32Bytes(uint32(r.ifindex))},
		{Type: NL80211_ATTR_WIPHY_FREQ, Data: nlenc.Uint32Bytes(apFreqMHz)},
		{Type: NL80211_ATTR_FRAME, Data: frame},
	})
	if err != nil {
		return fmt.Errorf("marshal FRAME attributes: %w", err)
	}

	_, err = r.conn.Send(genetlink.Message{
		Header: genetlink.Header{Command: NL80211_CMD_FRAME},
		Data:   b,
	}, r.familyID, netlink.Request|netlink.Acknowledge)
	if err != nil {
		return fmt.Errorf("send FRAME: %w", err)
	}

	if _, _, err := r.conn.Receive(); err != nil {
		return fmt.Errorf("receive FRAME ack: %w", err)
	}
	return nil
}

// handleAuth replies to an open-system authentication request from client
// with a success response, the second half of the (single round-trip) open
// system auth handshake.
func (r *mgmtResponder) handleAuth(client net.HardwareAddr) {
	resp := buildAuthResponse(r.apMAC, client)
	if err := r.sendFrame(resp); err != nil {
		fmt.Printf("mgmt: failed to send auth response to %s: %v\n", client, err)
		return
	}
	fmt.Printf("mgmt: sent auth response to %s\n", client)
}

// buildAuthResponse builds an open-system authentication frame (algorithm 0,
// transaction sequence 2, status success) addressed from apMAC to client.
// Mirrors the MAC header layout in buildBeaconHead/buildBeaconResponse.
func buildAuthResponse(apMAC, client net.HardwareAddr) []byte {
	b := []byte{}

	// MAC header
	b = append(b, 0xb0, 0x00) // frame control: type=management, subtype=auth
	b = append(b, 0x00, 0x00) // duration
	b = append(b, client...)  // dst
	b = append(b, apMAC...)   // src
	b = append(b, apMAC...)   // bssid

	b = append(b, 0x00, 0x00) // sequence

	// auth fixed fields
	b = append(b, 0x00, 0x00) // algorithm 0 = open system
	b = append(b, 0x02, 0x00) // transaction sequence number 2 (response)
	b = append(b, 0x00, 0x00) // status code 0 = successful

	return b
}

// listenMgmtFrames blocks, dispatching every management frame the kernel
// delivers on conn to resp.
func listenMgmtFrames(conn *genetlink.Conn, resp *mgmtResponder) {
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

			if fc == ieee80211FCAuth {
				resp.handleAuth(src)
			}
		}
	}
}
