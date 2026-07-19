package main

import (
	"encoding/binary"
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
	NL80211_CMD_NEW_STATION    = 19

	NL80211_ATTR_FRAME               = 51
	NL80211_ATTR_FRAME_MATCH         = 91
	NL80211_ATTR_FRAME_TYPE          = 101
	NL80211_ATTR_STA_AID             = 16
	NL80211_ATTR_STA_FLAGS2          = 67
	NL80211_ATTR_STA_LISTEN_INTERVAL = 18
	NL80211_ATTR_STA_SUPPORTED_RATES = 19
)

// Bit positions within struct nl80211_sta_flag_update's mask/set fields (enum
// nl80211_sta_flags). Setting all three at once on NEW_STATION is only
// correct for an open (no-security) network: there's no 802.1X/4-way
// handshake to wait for before authorizing the station.
const (
	nl80211StaFlagAuthorized    = 1 << 1
	nl80211StaFlagAuthenticated = 1 << 5
	nl80211StaFlagAssociated    = 1 << 7
)

// staAID is the association ID we hand every client. Fine for now since
// there's only ever one station tracked at a time.
const staAID = 1

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
	htCaps   htCapabilities
}

// newMgmtResponder dials a fresh genetlink connection for transmitting
// frames and station commands back to clients on ifindex. htCaps is the
// wiphy's real HT capability (from HostAPD's startup query), used to mirror
// HT Capabilities/Operation IEs in association responses so a session
// doesn't silently fall back to legacy rates.
func newMgmtResponder(ifindex int, apMAC net.HardwareAddr, htCaps htCapabilities) (*mgmtResponder, error) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("dial genetlink: %w", err)
	}

	family, err := conn.GetFamily("nl80211")
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("get nl80211 family: %w", err)
	}

	return &mgmtResponder{conn: conn, familyID: family.ID, ifindex: ifindex, apMAC: apMAC, htCaps: htCaps}, nil
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

// handleAssocReq registers the client with the driver via NEW_STATION, then
// replies with a successful association response. The station must be
// registered first: the instant the client sees a successful association
// response it may start sending data frames (ARP, DHCP), and mac80211's
// default behavior on receiving a data frame from a station it doesn't know
// about is to immediately deauth it ("class 3 frame from non-associated
// station"). Sending the response first leaves exactly that race.
func (r *mgmtResponder) handleAssocReq(client net.HardwareAddr, frame []byte) {
	listenInterval := assocRequestListenInterval(frame)
	clientHTCap, hasHTCap := assocRequestHTCapability(frame)
	if err := r.newStation(client, staAID, listenInterval, clientHTCap, hasHTCap); err != nil {
		fmt.Printf("mgmt: failed to add station %s: %v\n", client, err)
		return
	}
	fmt.Printf("mgmt: added station %s (aid=%d)\n", client, staAID)

	resp := buildAssocResponse(r.apMAC, client, staAID, r.htCaps)
	if err := r.sendFrame(resp); err != nil {
		fmt.Printf("mgmt: failed to send assoc response to %s: %v\n", client, err)
		return
	}
	fmt.Printf("mgmt: sent assoc response to %s\n", client)
}

// newStation registers client with the driver as authenticated, associated,
// and (since this is an open network) authorized, so it starts accepting
// and forwarding the station's data frames. When the client advertised its
// own HT Capabilities in the association request, that's passed through too
// (NL80211_ATTR_HT_CAPABILITY) so the driver's rate control knows it can use
// HT/MCS rates to this specific station instead of defaulting to legacy.
func (r *mgmtResponder) newStation(client net.HardwareAddr, aid, listenInterval uint16, htCap []byte, hasHTCap bool) error {
	mask := uint32(nl80211StaFlagAuthenticated | nl80211StaFlagAssociated | nl80211StaFlagAuthorized)
	staFlags := make([]byte, 8)
	nlenc.PutUint32(staFlags[0:4], mask) // mask: which flags this update touches
	nlenc.PutUint32(staFlags[4:8], mask) // set: turn all of them on

	attrs := []netlink.Attribute{
		{Type: NL80211_ATTR_IFINDEX, Data: nlenc.Uint32Bytes(uint32(r.ifindex))},
		{Type: NL80211_ATTR_MAC, Data: client},
		{Type: NL80211_ATTR_STA_AID, Data: nlenc.Uint16Bytes(aid)},
		{Type: NL80211_ATTR_STA_LISTEN_INTERVAL, Data: nlenc.Uint16Bytes(listenInterval)},
		{Type: NL80211_ATTR_STA_SUPPORTED_RATES, Data: apSupportedRates},
		{Type: NL80211_ATTR_STA_FLAGS2, Data: staFlags},
	}
	if hasHTCap {
		attrs = append(attrs, netlink.Attribute{Type: NL80211_ATTR_HT_CAPABILITY, Data: htCap})
	}

	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return fmt.Errorf("marshal NEW_STATION attributes: %w", err)
	}

	_, err = r.conn.Send(genetlink.Message{
		Header: genetlink.Header{Command: NL80211_CMD_NEW_STATION},
		Data:   b,
	}, r.familyID, netlink.Request|netlink.Acknowledge)
	if err != nil {
		return fmt.Errorf("send NEW_STATION: %w", err)
	}

	if _, _, err := r.conn.Receive(); err != nil {
		return fmt.Errorf("receive NEW_STATION ack: %w", err)
	}
	return nil
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

// assocRequestListenInterval reads the Listen Interval fixed field out of an
// association request frame (Capability Info at [24:26], Listen Interval at
// [26:28], right after the 24-byte MAC header), falling back to 1 if the
// frame is too short to contain it.
func assocRequestListenInterval(frame []byte) uint16 {
	if len(frame) < 28 {
		return 1
	}
	return binary.LittleEndian.Uint16(frame[26:28])
}

// buildAssocResponse builds a successful association response addressed
// from apMAC to client, echoing the same capability info, supported rates,
// and (when present) HT Capabilities/Operation advertised in our beacons.
// Including HT here matters: the association response is the definitive
// per-session capability confirmation, and a client that doesn't see HT
// confirmed here can fall back to legacy rates for the whole session even
// if the beacon separately advertised HT support.
func buildAssocResponse(apMAC, client net.HardwareAddr, aid uint16, htCaps htCapabilities) []byte {
	b := []byte{}

	// MAC header
	b = append(b, 0x10, 0x00) // frame control: type=management, subtype=assoc-resp
	b = append(b, 0x00, 0x00) // duration
	b = append(b, client...)  // dst
	b = append(b, apMAC...)   // src
	b = append(b, apMAC...)   // bssid

	b = append(b, 0x00, 0x00) // sequence

	// assoc-resp fixed fields
	b = append(b, apCapabilityInfo...) // capability, same as our beacons
	b = append(b, 0x00, 0x00)          // status code 0 = successful
	aidField := make([]byte, 2)
	binary.LittleEndian.PutUint16(aidField, 0xc000|aid) // top 2 bits reserved-as-1 per spec
	b = append(b, aidField...)

	// supported rates IE
	b = append(b, 0x01, byte(len(apSupportedRates)))
	b = append(b, apSupportedRates...)

	if htCaps.found {
		b = append(b, buildHTCapabilitiesIE(htCaps)...)
		b = append(b, buildHTOperationIE(apChannel)...)
	}

	return b
}

// assocRequestHTCapability extracts the body of the client's own HT
// Capabilities element (ID 45, 26-byte body) from its association request,
// if present. IEs start at offset 28 (24-byte MAC header + 2-byte
// Capability Info + 2-byte Listen Interval fixed fields).
func assocRequestHTCapability(frame []byte) ([]byte, bool) {
	for i := 28; i+2 <= len(frame); {
		id, length := frame[i], int(frame[i+1])
		i += 2
		if i+length > len(frame) {
			return nil, false
		}
		if id == 0x2d && length == 26 {
			return append([]byte(nil), frame[i:i+length]...), true
		}
		i += length
	}
	return nil, false
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

			switch fc {
			case ieee80211FCAuth:
				resp.handleAuth(src)
			case ieee80211FCAssocReq:
				resp.handleAssocReq(src, frame)
			}
		}
	}
}
