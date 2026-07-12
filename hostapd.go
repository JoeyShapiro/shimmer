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
	NL80211_ATTR_IFINDEX      = 3
)

func StartAPD(name string) (int, error) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return -1, err
	}
	defer conn.Close()

	family, err := conn.GetFamily("nl80211")
	if err != nil {
		return -1, err
	}

	iface, _ := net.InterfaceByName(name)
	ifindex := iface.Index

	b, _ := netlink.MarshalAttributes([]netlink.Attribute{
		{
			Type: NL80211_ATTR_IFINDEX,
			Data: nlenc.Uint32Bytes(uint32(ifindex)),
		},
	})

	_, err = conn.Send(genetlink.Message{
		Header: genetlink.Header{
			Command: NL80211_CMD_GET_INTERFACE,
		},
		Data: b,
	}, family.ID, netlink.Request|netlink.Dump)

	replies, _, err := conn.Receive()

	for _, reply := range replies {
		attrs, _ := netlink.UnmarshalAttributes(reply.Data)
		for _, attr := range attrs {
			switch attr.Type {
			case 4: // IFNAME
				fmt.Println("name:", string(attr.Data))
			case 5: // IFTYPE
				fmt.Println("mode:", nlenc.Uint32(attr.Data))
			case 6: // MAC
				fmt.Printf("mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
					attr.Data[0], attr.Data[1], attr.Data[2],
					attr.Data[3], attr.Data[4], attr.Data[5])
			case 98: // FREQ
				fmt.Println("freq:", nlenc.Uint32(attr.Data), "MHz")
			}
		}
	}

	// turn into AP mode
	link, err := linkup.LinkByName(name)
	if err != nil {
		return -1, err
	}

	linkup.LinkSetDown(link)

	const (
		NL80211_CMD_SET_INTERFACE = 6
		NL80211_IFTYPE_AP         = 3
	)

	b, _ = netlink.MarshalAttributes([]netlink.Attribute{
		{
			Type: NL80211_ATTR_IFINDEX,
			Data: nlenc.Uint32Bytes(uint32(ifindex)),
		},
		{
			Type: 5, // IFTYPE
			Data: nlenc.Uint32Bytes(NL80211_IFTYPE_AP),
		},
	})

	_, err = conn.Send(genetlink.Message{
		Header: genetlink.Header{
			Command: NL80211_CMD_SET_INTERFACE,
		},
		Data: b,
	}, family.ID, netlink.Request|netlink.Acknowledge)

	_, _, err = conn.Receive()

	if err != nil {
		return -1, err
	}

	linkup.LinkSetUp(link)

	//verify
	b, _ = netlink.MarshalAttributes([]netlink.Attribute{
		{
			Type: NL80211_ATTR_IFINDEX,
			Data: nlenc.Uint32Bytes(uint32(ifindex)),
		},
	})

	_, err = conn.Send(genetlink.Message{
		Header: genetlink.Header{
			Command: NL80211_CMD_GET_INTERFACE,
		},
		Data: b,
	}, family.ID, netlink.Request|netlink.Dump)
	if err != nil {
		return -1, err
	}

	replies, _, err = conn.Receive()
	if err != nil {
		return -1, err
	}

	for _, reply := range replies {
		attrs, _ := netlink.UnmarshalAttributes(reply.Data)
		for _, attr := range attrs {
			switch attr.Type {
			case 4: // IFNAME
				fmt.Println("name:", string(attr.Data))
			case 5: // IFTYPE
				fmt.Println("mode:", nlenc.Uint32(attr.Data))
			case 6: // MAC
				fmt.Printf("mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
					attr.Data[0], attr.Data[1], attr.Data[2],
					attr.Data[3], attr.Data[4], attr.Data[5])
			case 98: // FREQ
				fmt.Println("freq:", nlenc.Uint32(attr.Data), "MHz")
			}
		}
	}

	return int(family.ID), nil
}
