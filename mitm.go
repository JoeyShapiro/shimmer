package main

import (
	"fmt"
	"net"
	"syscall"
)

func runMitm() error {
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
	}

	return nil
}
