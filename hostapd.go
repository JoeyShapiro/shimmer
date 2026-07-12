package main

import (
	"fmt"
	"log"
	"net"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	linkup "github.com/vishvananda/netlink"
)

const (
	NL80211_CMD_GET_INTERFACE = 5
	NL80211_CMD_SET_INTERFACE = 6
	NL80211_IFTYPE_AP         = 3

	NL80211_ATTR_IFINDEX = 3
	NL80211_ATTR_IFNAME  = 4
	NL80211_ATTR_IFTYPE  = 5
	NL80211_ATTR_MAC     = 6

	NL80211_CMD_START_AP         = 15
	NL80211_ATTR_BEACON_INTERVAL = 12
	NL80211_ATTR_DTIM_PERIOD     = 13
	NL80211_ATTR_BEACON_HEAD     = 14
	NL80211_ATTR_BEACON_TAIL     = 15
	NL80211_ATTR_WIPHY_FREQ      = 38
	NL80211_ATTR_SSID            = 52
	NL80211_ATTR_AUTH_TYPE       = 53
	NL80211_ATTR_HIDDEN_SSID     = 126
	NL80211_ATTR_PROBE_RESP      = 145

	NL80211_AUTHTYPE_OPEN_SYSTEM   = 0
	NL80211_HIDDEN_SSID_NOT_IN_USE = 0
)

var wiphyIndex uint32

// printInterfaceAttrs pretty-prints the nl80211 attributes we care about
// for a single interface reply.
func printInterfaceAttrs(attrs []netlink.Attribute) {
	for _, attr := range attrs {
		switch attr.Type {
		case 1: // NL80211_ATTR_WIPHY
			wiphyIndex = nlenc.Uint32(attr.Data)
			fmt.Println("wiphy index:", wiphyIndex)
		case NL80211_ATTR_IFNAME:
			fmt.Println("name:", string(attr.Data))
		case NL80211_ATTR_IFTYPE:
			if len(attr.Data) < 4 {
				fmt.Println("mode: <malformed attribute>")
				continue
			}
			fmt.Println("mode:", nlenc.Uint32(attr.Data))
		case NL80211_ATTR_MAC:
			if len(attr.Data) < 6 {
				fmt.Println("mac: <malformed attribute>")
				continue
			}
			fmt.Printf("mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
				attr.Data[0], attr.Data[1], attr.Data[2],
				attr.Data[3], attr.Data[4], attr.Data[5])
		case NL80211_ATTR_WIPHY_FREQ:
			if len(attr.Data) < 4 {
				fmt.Println("freq: <malformed attribute>")
				continue
			}
			fmt.Println("freq:", nlenc.Uint32(attr.Data), "MHz")
		}
	}
}

// queryInterface issues a GET_INTERFACE dump for ifindex and prints the
// resulting attributes.
func queryInterface(conn *genetlink.Conn, familyID uint16, ifindex int) error {
	b, err := netlink.MarshalAttributes([]netlink.Attribute{
		{
			Type: NL80211_ATTR_IFINDEX,
			Data: nlenc.Uint32Bytes(uint32(ifindex)),
		},
	})
	if err != nil {
		return fmt.Errorf("marshal GET_INTERFACE attributes: %w", err)
	}

	_, err = conn.Send(genetlink.Message{
		Header: genetlink.Header{
			Command: NL80211_CMD_GET_INTERFACE,
		},
		Data: b,
	}, familyID, netlink.Request|netlink.Dump)
	if err != nil {
		return fmt.Errorf("send GET_INTERFACE: %w", err)
	}

	replies, _, err := conn.Receive()
	if err != nil {
		return fmt.Errorf("receive GET_INTERFACE reply: %w", err)
	}

	for _, reply := range replies {
		attrs, err := netlink.UnmarshalAttributes(reply.Data)
		if err != nil {
			return fmt.Errorf("unmarshal interface attributes: %w", err)
		}
		printInterfaceAttrs(attrs)
	}

	return nil
}

// setInterfaceType issues a SET_INTERFACE call switching ifindex to iftype.
func setInterfaceType(conn *genetlink.Conn, familyID uint16, ifindex int, iftype uint32) error {
	b, err := netlink.MarshalAttributes([]netlink.Attribute{
		{
			Type: NL80211_ATTR_IFINDEX,
			Data: nlenc.Uint32Bytes(uint32(ifindex)),
		},
		{
			Type: NL80211_ATTR_IFTYPE,
			Data: nlenc.Uint32Bytes(iftype),
		},
	})
	if err != nil {
		return fmt.Errorf("marshal SET_INTERFACE attributes: %w", err)
	}

	_, err = conn.Send(genetlink.Message{
		Header: genetlink.Header{
			Command: NL80211_CMD_SET_INTERFACE,
		},
		Data: b,
	}, familyID, netlink.Request|netlink.Acknowledge)
	if err != nil {
		return fmt.Errorf("send SET_INTERFACE: %w", err)
	}

	if _, _, err := conn.Receive(); err != nil {
		return fmt.Errorf("receive SET_INTERFACE reply: %w", err)
	}

	return nil
}

func HostAPD(name string) error {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("dial genetlink: %w", err)
	}
	defer conn.Close()

	family, err := conn.GetFamily("nl80211")
	if err != nil {
		return fmt.Errorf("get nl80211 family: %w", err)
	}
	fmt.Println("Resolved nl80211 family ID:", family.ID)

	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("lookup interface %q: %w", name, err)
	}

	if err := queryInterface(conn, family.ID, iface.Index); err != nil {
		return err
	}

	// turn into AP mode
	link, err := linkup.LinkByName(name)
	if err != nil {
		return fmt.Errorf("lookup link %q: %w", name, err)
	}

	if err := linkup.LinkSetDown(link); err != nil {
		return fmt.Errorf("set link down: %w", err)
	}

	if err := setInterfaceType(conn, family.ID, iface.Index, NL80211_IFTYPE_AP); err != nil {
		return err
	}

	if err := linkup.LinkSetUp(link); err != nil {
		return fmt.Errorf("set link up: %w", err)
	}

	// verify
	if err := queryInterface(conn, family.ID, iface.Index); err != nil {
		return err
	}

	beaconHead := buildBeaconHead(iface.HardwareAddr, "shmitm", 1)
	beaconTail := []byte{}
	probeResp := buildBeaconResponse(iface.HardwareAddr, "shmitm", 1)

	fmt.Printf("beacon head: %x\n", beaconHead)

	b, _ := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: NL80211_ATTR_IFINDEX, Data: nlenc.Uint32Bytes(uint32(iface.Index))},
		{Type: NL80211_ATTR_SSID, Data: []byte("shmitm")},
		{Type: NL80211_ATTR_WIPHY_FREQ, Data: nlenc.Uint32Bytes(2412)}, // channel 6
		{Type: NL80211_ATTR_BEACON_INTERVAL, Data: nlenc.Uint32Bytes(100)},
		{Type: NL80211_ATTR_DTIM_PERIOD, Data: nlenc.Uint32Bytes(2)},
		{Type: NL80211_ATTR_BEACON_HEAD, Data: beaconHead},
		{Type: NL80211_ATTR_BEACON_TAIL, Data: beaconTail},
		{Type: NL80211_ATTR_AUTH_TYPE, Data: nlenc.Uint32Bytes(NL80211_AUTHTYPE_OPEN_SYSTEM)},
		{Type: NL80211_ATTR_HIDDEN_SSID, Data: nlenc.Uint32Bytes(NL80211_HIDDEN_SSID_NOT_IN_USE)},
		{Type: NL80211_ATTR_PROBE_RESP, Data: probeResp},
		{Type: 1, Data: nlenc.Uint32Bytes(uint32(wiphyIndex))}, // NL80211_ATTR_WIPHY
	})

	_, err = conn.Send(genetlink.Message{
		Header: genetlink.Header{
			Command: NL80211_CMD_START_AP,
		},
		Data: b,
	}, family.ID, netlink.Request|netlink.Acknowledge)
	if err != nil {
		log.Fatal("send:", err)
	}

	_, _, err = conn.Receive()
	if err != nil {
		log.Fatal("receive:", err)
	}

	fmt.Println("AP started")

	return nil
}

func buildBeaconHead(mac net.HardwareAddr, ssid string, channel uint8) []byte {
	b := []byte{}

	// MAC header
	b = append(b, 0x80, 0x00)                         // frame control: type=management, subtype=beacon
	b = append(b, 0x00, 0x00)                         // duration
	b = append(b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff) // dst broadcast
	b = append(b, mac...)                             // src
	b = append(b, mac...)                             // bssid

	b = append(b, 0x00, 0x00) // sequence

	// fixed fields
	b = append(b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // timestamp
	b = append(b, 0x64, 0x00)                                     // beacon interval 100
	b = append(b, 0x21, 0x04)                                     // capability

	// SSID IE
	b = append(b, 0x00)
	b = append(b, byte(len(ssid)))
	b = append(b, []byte(ssid)...)

	// supported rates IE
	b = append(b, 0x01, 0x08)
	b = append(b, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24)

	// DS parameter set IE (channel)
	b = append(b, 0x03, 0x01, channel)

	return b
}

func buildBeaconResponse(mac net.HardwareAddr, ssid string, channel uint8) []byte {
	b := []byte{}

	// MAC header
	b = append(b, 0x50, 0x00)                         // frame control: type=management, subtype=probe-respond
	b = append(b, 0x00, 0x00)                         // duration
	b = append(b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff) // dst broadcast
	b = append(b, mac...)                             // src
	b = append(b, mac...)                             // bssid

	b = append(b, 0x00, 0x00) // sequence

	// fixed fields
	b = append(b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // timestamp
	b = append(b, 0x64, 0x00)                                     // beacon interval 100
	b = append(b, 0x21, 0x04)                                     // capability

	// SSID IE
	b = append(b, 0x00)
	b = append(b, byte(len(ssid)))
	b = append(b, []byte(ssid)...)

	// supported rates IE
	b = append(b, 0x01, 0x08)
	b = append(b, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24)

	// DS parameter set IE (channel)
	b = append(b, 0x03, 0x01, channel)

	return b
}
