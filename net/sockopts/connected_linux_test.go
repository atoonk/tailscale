// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package sockopts

import (
	"net"
	"syscall"
	"testing"
	"time"
)

// TestConnectedSocketSharesPort checks the kernel behaviour magicsock's
// connected UDP sockets rely on: a socket connected to a peer, bound with
// SO_REUSEPORT to the port of an unconnected socket, receives that peer's
// datagrams, while the unconnected socket still receives everyone else's.
// (Linux 5.4 and later prefer the connected socket; older kernels spread a
// reuseport group's datagrams by hash.)
func TestConnectedSocketSharesPort(t *testing.T) {
	reusePort := func(network, address string, c syscall.RawConn) error {
		return SetReusePort(c)
	}
	lc := net.ListenConfig{Control: reusePort}
	shared, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	port := shared.LocalAddr().(*net.UDPAddr).Port

	newPeer := func() *net.UDPConn {
		p, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { p.Close() })
		return p
	}
	peerA, peerB := newPeer(), newPeer()

	d := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, Control: reusePort}
	connected, err := d.DialContext(t.Context(), "udp4", peerA.LocalAddr().String())
	if err != nil {
		t.Fatalf("connected dial on shared port: %v", err)
	}
	defer connected.Close()

	expect := func(what string, c net.PacketConn, want string) {
		t.Helper()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 64)
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if got := string(buf[:n]); got != want {
			t.Fatalf("%s: got %q, want %q", what, got, want)
		}
	}
	expectNothing := func(what string, c net.PacketConn) {
		t.Helper()
		c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 64)
		if n, from, err := c.ReadFrom(buf); err == nil {
			t.Fatalf("%s: unexpectedly read %q from %v", what, buf[:n], from)
		}
	}

	to := shared.LocalAddr()
	if _, err := peerA.WriteTo([]byte("from A"), to); err != nil {
		t.Fatal(err)
	}
	expect("connected socket reading peer A", connected.(net.PacketConn), "from A")
	expectNothing("shared socket after peer A", shared)

	if _, err := peerB.WriteTo([]byte("from B"), to); err != nil {
		t.Fatal(err)
	}
	expect("shared socket reading peer B", shared, "from B")

	if _, err := connected.Write([]byte("to A")); err != nil {
		t.Fatal(err)
	}
	peerA.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, from, err := peerA.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "to A" || from.(*net.UDPAddr).Port != port {
		t.Fatalf("peer A got %q from %v, want %q from port %d", buf[:n], from, "to A", port)
	}
}
