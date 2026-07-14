package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

const (
	dhcpServerIP  = "10.0.0.1"
	dhcpPoolStart = "10.0.0.100"
	dhcpSubnet    = "255.255.255.0"
	dhcpLeaseSecs = 3600
)

func runMitm() error {
	iface, err := HostAPD("wlp0s20f0u13")
	if err != nil {
		return fmt.Errorf("failed to resolve nl80211 family: %w", err)
	}
	fmt.Println("Successfully set interface to AP mode")

	mgmtConn, err := openMgmtListener(iface.Index)
	if err != nil {
		return fmt.Errorf("failed to set up management-frame listener: %w", err)
	}
	defer mgmtConn.Close()
	go listenMgmtFrames(mgmtConn)
	fmt.Println("Listening for 802.11 management frames...")

	conn, err := net.ListenPacket("udp4", "0.0.0.0:67")
	if err != nil {
		return fmt.Errorf("failed to listen on UDP port 67: %w", err)
	}
	defer conn.Close()

	rawConn, _ := conn.(*net.UDPConn).SyscallConn()
	rawConn.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
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
