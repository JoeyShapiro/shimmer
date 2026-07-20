package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
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

// proxyServer terminates redirected connections. HTTP requests get parsed
// and logged before being forwarded; HTTPS connections get a real TLS
// handshake — using ca to mint a leaf certificate matching whatever
// hostname the client requests via SNI — so the decrypted HTTP traffic can
// be read the same way HTTP already is.
type proxyServer struct {
	ca *certAuthority
}

// openProxyListener listens on mitmProxyPort for the TCP connections
// setupNAT's prerouting rule redirects there.
func openProxyListener() (net.Listener, error) {
	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", mitmProxyPort))
	if err != nil {
		return nil, fmt.Errorf("failed to listen on TCP port %d: %w", mitmProxyPort, err)
	}
	return ln, nil
}

// serve accepts redirected connections and dispatches each to its own
// handler goroutine.
func (p *proxyServer) serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Printf("proxy: accept error: %v\n", err)
			return
		}
		go p.handleConn(conn)
	}
}

// handleConn recovers where conn was really headed and either terminates it
// as HTTPS (see handleHTTPS) or, for plain HTTP, parses and logs the
// request's full URL before forwarding it on unmodified. Anything else
// (shouldn't happen given setupNAT only redirects ports 80/443 here) just
// gets relayed as raw bytes.
func (p *proxyServer) handleConn(conn net.Conn) {
	defer conn.Close()

	dst, err := originalDst(conn)
	if err != nil {
		fmt.Printf("proxy: failed to get original destination for %s: %v\n", conn.RemoteAddr(), err)
		return
	}

	if dst.Port == 443 {
		p.handleHTTPS(conn, dst)
		return
	}

	upstream, err := net.Dial("tcp", dst.String())
	if err != nil {
		fmt.Printf("proxy: failed to dial %s: %v\n", dst, err)
		return
	}
	defer upstream.Close()

	clientReader := bufio.NewReader(conn)

	if dst.Port == 80 {
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			fmt.Printf("proxy: failed to parse HTTP request from %s: %v\n", conn.RemoteAddr(), err)
			return
		}
		fmt.Printf("proxy: %s http://%s%s\n", conn.RemoteAddr(), req.Host, req.URL.RequestURI())
		if err := req.Write(upstream); err != nil {
			fmt.Printf("proxy: failed to forward request to %s: %v\n", dst, err)
			return
		}
	} else {
		fmt.Printf("proxy: %s -> %s\n", conn.RemoteAddr(), dst)
	}

	relay(conn, clientReader, upstream)
}

// handleHTTPS terminates the client's TLS connection using a leaf
// certificate minted for whatever hostname it requests via SNI, then opens
// a second, separate TLS connection of our own to the real destination —
// splitting what the client believes is one encrypted conversation into
// two, with the decrypted HTTP sitting in our process in between.
func (p *proxyServer) handleHTTPS(conn net.Conn, dst *net.TCPAddr) {
	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return p.ca.certFor(hello.ServerName)
		},
		// No HTTP/2: it's binary-framed and multiplexed, not worth the
		// parsing complexity yet. This forces the client to fall back to
		// HTTP/1.1 with us even if it would've preferred h2 with the real
		// site.
		NextProtos: []string{"http/1.1"},
	}

	clientConn := tls.Server(conn, tlsConfig)
	if err := clientConn.Handshake(); err != nil {
		fmt.Printf("proxy: TLS handshake with %s failed: %v\n", conn.RemoteAddr(), err)
		return
	}

	serverName := clientConn.ConnectionState().ServerName
	if serverName == "" {
		// No SNI. Rare for a modern client, but fall back to the raw IP we
		// recovered from SO_ORIGINAL_DST so we can still dial upstream.
		serverName = dst.IP.String()
	}

	upstream, err := tls.Dial("tcp", dst.String(), &tls.Config{ServerName: serverName})
	if err != nil {
		fmt.Printf("proxy: failed to dial %s (%s): %v\n", dst, serverName, err)
		return
	}
	defer upstream.Close()

	clientReader := bufio.NewReader(clientConn)

	req, err := http.ReadRequest(clientReader)
	if err != nil {
		fmt.Printf("proxy: failed to parse HTTPS request from %s: %v\n", conn.RemoteAddr(), err)
		return
	}
	fmt.Printf("proxy: %s https://%s%s\n", conn.RemoteAddr(), req.Host, req.URL.RequestURI())
	if err := req.Write(upstream); err != nil {
		fmt.Printf("proxy: failed to forward request to %s: %v\n", dst, err)
		return
	}

	relay(clientConn, clientReader, upstream)
}

// relay copies bytes bidirectionally between a client (writes go to
// clientWriter, reads come from clientReader — which may already have
// buffered/consumed an initial request) and upstream, until either side
// closes.
func relay(clientWriter io.Writer, clientReader io.Reader, upstream io.ReadWriter) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, clientReader)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientWriter, upstream)
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
