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
		n, addr, _ := conn.ReadFrom(buf)
		fmt.Printf("Received %d bytes from %s\n", n, addr.String())
		fmt.Printf("Packet data: %x\n", buf[:n])
	}

	return nil
}
