package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// dnsUpstream is the real resolver we forward client queries to. DHCP hands
// out dhcpServerIP as the DNS server (option 6), so without this forwarder
// nothing would answer on port 53 at all: raw IP connectivity would work
// fine via NAT, but hostname resolution would silently fail.
const (
	dnsUpstream = "1.1.1.1:53"
	dnsTimeout  = 5 * time.Second
)

// openDNSListener opens a UDP socket on port 53, pinned to iface for the
// same reason as the DHCP socket in mitm.go: this box is multi-homed, and
// without SO_BINDTODEVICE a reply could go out the wrong interface.
func openDNSListener(iface *net.Interface) (net.PacketConn, error) {
	conn, err := net.ListenPacket("udp4", "0.0.0.0:53")
	if err != nil {
		return nil, fmt.Errorf("failed to listen on UDP port 53: %w", err)
	}

	rawConn, _ := conn.(*net.UDPConn).SyscallConn()
	rawConn.Control(func(fd uintptr) {
		unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface.Name)
	})

	return conn, nil
}

// forwardDNSQueries blocks, relaying every query received on conn to
// dnsUpstream in its own goroutine.
func forwardDNSQueries(conn net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, clientAddr, err := conn.ReadFrom(buf)
		if err != nil {
			fmt.Printf("dns: read error: %v\n", err)
			return
		}
		query := append([]byte(nil), buf[:n]...)
		fmt.Printf("dns: query from %s: %s\n", clientAddr, dnsQuestionName(query))
		go relayDNSQuery(conn, clientAddr, query)
	}
}

// dnsQuestionName best-effort extracts the domain name from a DNS message's
// question section (the 12-byte header is followed by a sequence of
// length-prefixed labels ending in a zero byte), purely for logging. Returns
// "" on anything too short or malformed rather than treating that as fatal.
func dnsQuestionName(query []byte) string {
	var labels []string
	for i := 12; i < len(query); {
		length := int(query[i])
		if length == 0 {
			return strings.Join(labels, ".")
		}
		i++
		if i+length > len(query) {
			return ""
		}
		labels = append(labels, string(query[i:i+length]))
		i += length
	}
	return ""
}

// relayDNSQuery forwards a single query to dnsUpstream and writes back
// whatever comes back to clientAddr, unmodified. DNS matches requests to
// replies with a transaction ID in the first two bytes of the message, so
// there's no need to parse anything here.
func relayDNSQuery(conn net.PacketConn, clientAddr net.Addr, query []byte) {
	upstream, err := net.DialTimeout("udp4", dnsUpstream, dnsTimeout)
	if err != nil {
		fmt.Printf("dns: dial upstream: %v\n", err)
		return
	}
	defer upstream.Close()

	if _, err := upstream.Write(query); err != nil {
		fmt.Printf("dns: write upstream: %v\n", err)
		return
	}

	upstream.SetReadDeadline(time.Now().Add(dnsTimeout))
	resp := make([]byte, 1500)
	n, err := upstream.Read(resp)
	if err != nil {
		fmt.Printf("dns: read upstream: %v\n", err)
		return
	}

	if _, err := conn.WriteTo(resp[:n], clientAddr); err != nil {
		fmt.Printf("dns: reply to client: %v\n", err)
		return
	}
	fmt.Printf("dns: replied to %s (%d bytes)\n", clientAddr, n)
}
