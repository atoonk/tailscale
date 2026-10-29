// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package batching

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/net/packet"
)

// TestConnectedConn checks a [Conn] over a connected socket: writes to the
// connected address arrive at the peer, in order, and writes to any other
// address are refused.
func TestConnectedConn(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peerAddr := peer.LocalAddr().(*net.UDPAddr).AddrPort()

	uc, err := net.DialUDP("udp4", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	c, ok := TryUpgradeToConn(uc, "udp4", "", nil).(Conn)
	if !ok {
		t.Skip("TryUpgradeToConn did not return a Conn on this kernel")
	}

	const n = 10
	buffs := make([][]byte, n)
	for i := range buffs {
		buffs[i] = make([]byte, packet.GeneveFixedHeaderLength+100)
		buffs[i][packet.GeneveFixedHeaderLength] = byte(i)
	}
	if err := c.WriteBatchTo(buffs, peerAddr, packet.GeneveHeader{}, packet.GeneveFixedHeaderLength); err != nil {
		t.Fatalf("WriteBatchTo(connected addr): %v", err)
	}
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	for i := range n {
		got, _, err := peer.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("peer read %d: %v", i, err)
		}
		if got != 100 || buf[0] != byte(i) {
			t.Fatalf("peer read %d: got %d bytes, first %d; want 100 bytes, first %d", i, got, buf[0], i)
		}
	}

	other := netip.MustParseAddrPort("127.0.0.1:1")
	if err := c.WriteBatchTo(buffs[:1], other, packet.GeneveHeader{}, packet.GeneveFixedHeaderLength); !errors.Is(err, ErrNotConnectedTo) {
		t.Errorf("WriteBatchTo(other addr) = %v, want ErrNotConnectedTo", err)
	}
	if _, err := c.WriteToUDPAddrPort(buffs[0][packet.GeneveFixedHeaderLength:], other); !errors.Is(err, ErrNotConnectedTo) {
		t.Errorf("WriteToUDPAddrPort(other addr) = %v, want ErrNotConnectedTo", err)
	}
	if _, err := c.WriteToUDPAddrPort(buffs[0][packet.GeneveFixedHeaderLength:], peerAddr); err != nil {
		t.Errorf("WriteToUDPAddrPort(connected addr): %v", err)
	}
	if _, _, err := peer.ReadFromUDPAddrPort(buf); err != nil {
		t.Errorf("peer read after WriteToUDPAddrPort: %v", err)
	}
}
