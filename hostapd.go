package main

import (
	"fmt"
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
	NL80211_ATTR_FREQ    = 98
)

// printInterfaceAttrs pretty-prints the nl80211 attributes we care about
// for a single interface reply.
func printInterfaceAttrs(attrs []netlink.Attribute) {
	for _, attr := range attrs {
		switch attr.Type {
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
		case NL80211_ATTR_FREQ:
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

	return nil
}
