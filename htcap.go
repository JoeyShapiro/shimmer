package main

import (
	"encoding/binary"
	"fmt"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
)

const (
	NL80211_CMD_GET_WIPHY = 1
	NL80211_ATTR_WIPHY    = 1

	NL80211_ATTR_WIPHY_BANDS        = 22
	NL80211_ATTR_HT_CAPABILITY      = 31
	NL80211_ATTR_WIPHY_CHANNEL_TYPE = 39

	NL80211_BAND_ATTR_HT_MCS_SET       = 3
	NL80211_BAND_ATTR_HT_CAPA          = 4
	NL80211_BAND_ATTR_HT_AMPDU_FACTOR  = 5
	NL80211_BAND_ATTR_HT_AMPDU_DENSITY = 6

	// nl80211_channel_type: whether/how the operating channel uses HT.
	NL80211_CHAN_NO_HT = 0
	NL80211_CHAN_HT20  = 1
)

// htCapabilities holds the HT (802.11n) capability fields a wiphy reports
// for one band, in the same encoding the HT Capabilities information
// element uses on the wire (802.11-2016 9.4.2.56).
type htCapabilities struct {
	found        bool
	capInfo      uint16   // HT Capability Info
	ampduFactor  uint8    // Maximum A-MPDU Length Exponent
	ampduDensity uint8    // Minimum MPDU Start Spacing
	mcsSet       [16]byte // Supported MCS Set
}

// String renders the capability info for logging.
func (c htCapabilities) String() string {
	if !c.found {
		return "no HT capabilities reported (802.11n not supported on this band)"
	}
	return fmt.Sprintf(
		"HT capability info: %#04x, A-MPDU max length exponent: %d, A-MPDU min start spacing: %d, MCS set: %x",
		c.capInfo, c.ampduFactor, c.ampduDensity, c.mcsSet,
	)
}

// queryWiphyHTCapabilities asks the kernel what HT (802.11n) capabilities
// wiphyIndex actually supports, straight from the driver. We don't get to
// assert this ourselves — building an HT Capabilities IE with values the
// hardware doesn't back would just break negotiation with real clients.
func queryWiphyHTCapabilities(conn *genetlink.Conn, familyID uint16, wiphyIndex uint32) (htCapabilities, error) {
	b, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: NL80211_ATTR_WIPHY, Data: nlenc.Uint32Bytes(wiphyIndex)},
	})
	if err != nil {
		return htCapabilities{}, fmt.Errorf("marshal GET_WIPHY attributes: %w", err)
	}

	_, err = conn.Send(genetlink.Message{
		Header: genetlink.Header{Command: NL80211_CMD_GET_WIPHY},
		Data:   b,
	}, familyID, netlink.Request)
	if err != nil {
		return htCapabilities{}, fmt.Errorf("send GET_WIPHY: %w", err)
	}

	replies, _, err := conn.Receive()
	if err != nil {
		return htCapabilities{}, fmt.Errorf("receive GET_WIPHY reply: %w", err)
	}

	for _, reply := range replies {
		attrs, err := netlink.UnmarshalAttributes(reply.Data)
		if err != nil {
			return htCapabilities{}, fmt.Errorf("unmarshal wiphy attributes: %w", err)
		}
		for _, attr := range attrs {
			if attr.Type != NL80211_ATTR_WIPHY_BANDS {
				continue
			}
			if cap, ok := parseHTFromBands(attr.Data); ok {
				return cap, nil
			}
		}
	}

	return htCapabilities{}, nil
}

// htCap40MHz and htCapSGI40MHz are bits in the HT Capability Info field
// (802.11-2016 9.4.2.56.2) covering 40MHz channel width support and short
// guard interval at 40MHz. buildHTCapabilitiesIE masks these off: we only
// configure a single HT20 channel right now, so claiming 40MHz-related
// capabilities would misrepresent what we're actually operating.
const (
	htCap40MHz    = 1 << 1
	htCapSGI40MHz = 1 << 6
)

// buildHTCapabilitiesIE builds the HT Capabilities information element
// (802.11-2016 9.4.2.56) from cap — the wiphy's real, queried capabilities,
// restricted to HT20 operation.
func buildHTCapabilitiesIE(cap htCapabilities) []byte {
	capInfo := cap.capInfo &^ (htCap40MHz | htCapSGI40MHz)

	b := []byte{0x2d, 26} // element ID 45 (HT Capabilities), body length 26
	b = append(b, byte(capInfo), byte(capInfo>>8))
	b = append(b, (cap.ampduFactor&0x3)|((cap.ampduDensity&0x7)<<2))
	b = append(b, cap.mcsSet[:]...)
	b = append(b, 0x00, 0x00)             // HT Extended Capabilities: none
	b = append(b, 0x00, 0x00, 0x00, 0x00) // Transmit Beamforming Capabilities: none
	b = append(b, 0x00)                   // ASEL Capabilities: none
	return b
}

// buildHTOperationIE builds the HT Operation information element
// (802.11-2016 9.4.2.57) for a single HT20 channel with no legacy
// protection requirements and MCS0 as the only mandatory ("basic") rate.
func buildHTOperationIE(channel uint8) []byte {
	b := []byte{0x3d, 22}     // element ID 61 (HT Operation), body length 22
	b = append(b, channel)    // primary channel
	b = append(b, 0x00)       // HT info subset 1: no secondary channel, 20MHz only
	b = append(b, 0x00, 0x00) // HT info subset 2: no protection
	b = append(b, 0x00, 0x00) // HT info subset 3
	basicMCS := make([]byte, 16)
	basicMCS[0] = 0x01 // MCS0 mandatory
	b = append(b, basicMCS...)
	return b
}

// parseHTFromBands walks the nested per-band attributes looking for the
// first band that reports HT capabilities — on this AP, that's the 2.4GHz
// band, the only one it operates on.
func parseHTFromBands(data []byte) (htCapabilities, bool) {
	bands, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return htCapabilities{}, false
	}

	for _, band := range bands {
		bandAttrs, err := netlink.UnmarshalAttributes(band.Data)
		if err != nil {
			continue
		}

		var cap htCapabilities
		for _, ba := range bandAttrs {
			switch ba.Type {
			case NL80211_BAND_ATTR_HT_CAPA:
				if len(ba.Data) >= 2 {
					// This is a copy of the on-the-wire HT Capabilities IE
					// field, which 802.11 specifies little-endian —
					// distinct from netlink's own host-native integer
					// attributes, so decode it explicitly rather than via
					// nlenc.
					cap.capInfo = binary.LittleEndian.Uint16(ba.Data)
					cap.found = true
				}
			case NL80211_BAND_ATTR_HT_AMPDU_FACTOR:
				if len(ba.Data) >= 1 {
					cap.ampduFactor = ba.Data[0]
				}
			case NL80211_BAND_ATTR_HT_AMPDU_DENSITY:
				if len(ba.Data) >= 1 {
					cap.ampduDensity = ba.Data[0]
				}
			case NL80211_BAND_ATTR_HT_MCS_SET:
				if len(ba.Data) >= 16 {
					copy(cap.mcsSet[:], ba.Data[:16])
				}
			}
		}
		if cap.found {
			return cap, true
		}
	}

	return htCapabilities{}, false
}
