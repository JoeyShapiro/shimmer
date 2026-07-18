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

	NL80211_ATTR_WIPHY_BANDS = 22

	NL80211_BAND_ATTR_HT_MCS_SET       = 3
	NL80211_BAND_ATTR_HT_CAPA          = 4
	NL80211_BAND_ATTR_HT_AMPDU_FACTOR  = 5
	NL80211_BAND_ATTR_HT_AMPDU_DENSITY = 6
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
