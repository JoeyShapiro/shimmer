package main

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

const (
	dhcpServerIP  = "10.0.0.1"
	dhcpPoolStart = "10.0.0.100"
	dhcpSubnet    = "255.255.255.0"
	dhcpLeaseSecs = 3600

	apIfaceName  = "wlp0s20f0u13"
	wanIfaceName = "eno1" // the interface with actual internet access
)

func runMitm() error {
	iface, htCaps, err := HostAPD(apIfaceName)
	if err != nil {
		return fmt.Errorf("failed to resolve nl80211 family: %w", err)
	}
	fmt.Println("Successfully set interface to AP mode")

	if err := setupNAT(apIfaceName, wanIfaceName); err != nil {
		return fmt.Errorf("failed to set up NAT/forwarding: %w", err)
	}
	fmt.Println("Forwarding and NATing to", wanIfaceName)

	mgmtConn, err := openMgmtListener(iface.Index)
	if err != nil {
		return fmt.Errorf("failed to set up management-frame listener: %w", err)
	}
	defer mgmtConn.Close()

	mgmtResp, err := newMgmtResponder(iface.Index, iface.HardwareAddr, htCaps)
	if err != nil {
		return fmt.Errorf("failed to set up management-frame responder: %w", err)
	}
	defer mgmtResp.Close()

	go listenMgmtFrames(mgmtConn, mgmtResp)
	fmt.Println("Listening for 802.11 management frames...")

	dnsConn, err := openDNSListener(iface)
	if err != nil {
		return fmt.Errorf("failed to set up DNS forwarder: %w", err)
	}
	defer dnsConn.Close()

	go forwardDNSQueries(dnsConn)
	fmt.Println("Forwarding DNS queries to", dnsUpstream)

	conn, err := net.ListenPacket("udp4", "0.0.0.0:67")
	if err != nil {
		return fmt.Errorf("failed to listen on UDP port 67: %w", err)
	}
	defer conn.Close()

	// This box is multi-homed (the AP interface plus whatever else, e.g.
	// wired ethernet). Without SO_BINDTODEVICE, a reply to 255.255.255.255
	// is ambiguous: the kernel's routing code picks *an* interface to send
	// it out of, which need not be the one the client is actually on. Pin
	// the socket to the AP interface so both directions are unambiguous.
	rawConn, _ := conn.(*net.UDPConn).SyscallConn()
	// TODO why use unix
	rawConn.Control(func(fd uintptr) {
		unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
		unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface.Name)
	})
	fmt.Println("Listening for DHCP packets on UDP port 67...")

	serverIP := net.ParseIP(dhcpServerIP).To4()
	subnetMask := net.ParseIP(dhcpSubnet).To4()
	leaseTime := make([]byte, 4)
	binary.BigEndian.PutUint32(leaseTime, dhcpLeaseSecs)
	broadcast := &net.UDPAddr{IP: net.IPv4bcast, Port: 68}

	leases := map[string]net.IP{}
	nextIP := net.ParseIP(dhcpPoolStart).To4()

	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			fmt.Printf("read error: %v\n", err)
			continue
		}

		pkt, err := ParseDHCP(buf[:n])
		if err != nil {
			fmt.Printf("Received %d bytes from %s: not DHCP: %v\n", n, addr, err)
			continue
		}
		fmt.Printf("Received %d bytes from %s\n%s", n, addr, pkt)

		msgType, ok := pkt.MessageType()
		if !ok {
			continue
		}

		mac := pkt.CHAddr.String()
		var reply *DHCPPacket

		switch msgType {
		case DHCPDiscover:
			ip, seen := leases[mac]
			if !seen {
				ip = append(net.IP(nil), nextIP...)
				leases[mac] = ip
				incIP(nextIP)
			}
			reply = NewReply(pkt, DHCPOffer, ip)

		case DHCPRequest:
			ip, seen := leases[mac]
			if !seen {
				continue // never offered this client anything; ignore
			}
			reply = NewReply(pkt, DHCPAck, ip)

		default:
			continue
		}

		reply.SIAddr = serverIP
		reply.SetOption(OptServerID, serverIP)
		reply.SetOption(OptSubnetMask, subnetMask)
		reply.SetOption(OptRouter, serverIP)
		reply.SetOption(OptDNSServer, serverIP)
		reply.SetOption(OptLeaseTime, leaseTime)

		if _, err := conn.WriteTo(reply.Marshal(), broadcast); err != nil {
			fmt.Printf("send error: %v\n", err)
		}
	}
}

// incIP increments a 4-byte IPv4 address in place (with carry), used to hand
// out sequential addresses from the pool.
func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
