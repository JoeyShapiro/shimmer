package main

import (
	"fmt"
	"io"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// externalProxy controls whether shmitm runs its own listener on
// mitmProxyPort, or leaves that port free for a separately-run tool (e.g. a
// real mitmproxy instance) to bind instead.
const externalProxy = false

// soOriginalDst is Linux's getsockopt option (at the SOL_IP level) for
// recovering a redirected connection's pre-NAT destination.
const soOriginalDst = 80

// openProxyListener listens on mitmProxyPort for the TCP connections
// setupNAT's prerouting rule redirects there.
func openProxyListener() (net.Listener, error) {
	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", mitmProxyPort))
	if err != nil {
		return nil, fmt.Errorf("failed to listen on TCP port %d: %w", mitmProxyPort, err)
	}
	return ln, nil
}

// serveProxy accepts redirected connections and, for now, just forwards
// each one on to its original destination unmodified — proving the
// redirect+accept+relay pipeline end to end before any actual interception
// logic gets added on top.
func serveProxy(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Printf("proxy: accept error: %v\n", err)
			return
		}
		go handleProxyConn(conn)
	}
}

// handleProxyConn recovers where conn was really headed and relays bytes
// bidirectionally between the client and that real destination.
func handleProxyConn(conn net.Conn) {
	defer conn.Close()

	dst, err := originalDst(conn)
	if err != nil {
		fmt.Printf("proxy: failed to get original destination for %s: %v\n", conn.RemoteAddr(), err)
		return
	}
	fmt.Printf("proxy: %s -> %s\n", conn.RemoteAddr(), dst)

	upstream, err := net.Dial("tcp", dst.String())
	if err != nil {
		fmt.Printf("proxy: failed to dial %s: %v\n", dst, err)
		return
	}
	defer upstream.Close()

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, conn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, upstream)
		done <- struct{}{}
	}()
	<-done
}

// originalDst recovers the pre-redirect destination address/port of a
// connection that arrived via setupNAT's prerouting redirect rule, using
// Linux's SO_ORIGINAL_DST getsockopt — the kernel remembers the address the
// client actually addressed, from before the DNAT rewrite.
func originalDst(conn net.Conn) (*net.TCPAddr, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("not a TCP connection: %T", conn)
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var addr unix.RawSockaddrInet4
	var sockErr error
	if err := rawConn.Control(func(fd uintptr) {
		size := uint32(unsafe.Sizeof(addr))
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, uintptr(unix.SOL_IP), uintptr(soOriginalDst),
			uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 {
			sockErr = errno
		}
	}); err != nil {
		return nil, err
	}
	if sockErr != nil {
		return nil, sockErr
	}

	// addr.Port holds the raw network-byte-order (big-endian) port bytes,
	// read as a host-native uint16 — byte-swap to recover the real value.
	port := (addr.Port >> 8) | (addr.Port << 8)
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	return &net.TCPAddr{IP: ip, Port: int(port)}, nil
}
