// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package magicsock

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/net/batching"
	"tailscale.com/net/netmon"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/mak"
	"tailscale.com/util/usermetric"
)

// newRealSocketTestConn is newTestConn on real UDP sockets, which connected
// UDP sockets need.
func newRealSocketTestConn(t testing.TB) *Conn {
	t.Helper()

	bus := eventbustest.NewBus(t)
	t.Cleanup(bus.Close)

	netMon, err := netmon.New(bus, logger.WithPrefix(t.Logf, "... netmon: "))
	if err != nil {
		t.Fatalf("netmon.New: %v", err)
	}
	t.Cleanup(func() { netMon.Close() })

	c, err := NewConn(Options{
		NetMon:            netMon,
		EventBus:          bus,
		HealthTracker:     health.NewTracker(bus),
		Metrics:           new(usermetric.Registry),
		DisablePortMapper: true,
		Logf:              t.Logf,
		Port:              0,
		EndpointsFunc:     func(eps []tailcfg.Endpoint) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// connectedUDPFixture is a Conn with the knob on, one peer on 127.0.0.1 with
// a trusted direct path and an active session, and the bind open with the
// test standing in for wireguard-go's receive goroutines.
type connectedUDPFixture struct {
	c          *Conn
	ep         *endpoint
	peer       *net.UDPConn
	peerAddr   netip.AddrPort
	sharedAddr netip.AddrPort
	rx         chan connectedUDPRx
	wait       func() // for the receive funcs to exit
}

// connectedUDPRx is one packet a receive func reported to the test's stand-in
// for wireguard-go.
type connectedUDPRx struct {
	fn int // index of the receive func
	ep conn.Endpoint
}

// The order connBind.Open returns receive funcs in: IPv4, IPv6, the
// connected UDP slots, DERP.
const (
	fnIPv4      = 0
	fnFirstSlot = 2
)

func (f *connectedUDPFixture) isSlotFn(i int) bool {
	return i >= fnFirstSlot && i < fnFirstSlot+f.c.connectedUDP.maxSockets
}

func newConnectedUDPFixture(t *testing.T) *connectedUDPFixture {
	t.Helper()
	envknob.SetenvForTest(t, "TS_ENABLE_CONNECTED_UDP", "true")

	c := newRealSocketTestConn(t)
	if !c.connectedUDPEnabled() {
		t.Fatal("connected UDP not enabled")
	}

	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	peerAddr := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	nodeKey, _ := addTestEndpoint(t, c, peer)

	c.mu.Lock()
	ep, ok := c.peerMap.endpointForNodeKey(nodeKey)
	c.mu.Unlock()
	if !ok {
		t.Fatal("no endpoint for test peer")
	}
	// Give the endpoint a trusted direct path and an active session, as disco
	// would have.
	ep.mu.Lock()
	ep.setBestAddrLocked(addrQuality{epAddr: epAddr{ap: peerAddr}})
	ep.trustBestAddrUntil = mono.Now().Add(time.Hour)
	ep.lastSendExt = mono.Now()
	ep.mu.Unlock()

	fns, _, err := c.Bind().Open(0)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(fns), fnFirstSlot+c.connectedUDP.maxSockets+1; got != want {
		t.Fatalf("Open returned %d receive funcs, want %d", got, want)
	}
	f := &connectedUDPFixture{
		c:          c,
		ep:         ep,
		peer:       peer,
		peerAddr:   peerAddr,
		sharedAddr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), c.pconn4.Port()),
		rx:         make(chan connectedUDPRx, 1024),
	}
	f.wait = runReceiveFuncs(fns, f.rx)
	return f
}

// runReceiveFuncs plays wireguard-go: one goroutine per receive func, each
// reporting what it gets on ch, until the func returns an error. The returned
// func waits for them all to exit.
func runReceiveFuncs(fns []conn.ReceiveFunc, ch chan<- connectedUDPRx) (wait func()) {
	var wg sync.WaitGroup
	for i, fn := range fns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slab := make([]byte, 2*batching.ReadSlabMultiple)
			packets := make([]conn.ReceivedPacket, conn.IdealBatchSize)
			for {
				n, err := fn(slab, packets)
				if err != nil {
					return
				}
				for _, p := range packets[:n] {
					if p.Size > 0 {
						ch <- connectedUDPRx{fn: i, ep: p.Endpoint}
					}
				}
			}
		}()
	}
	return wg.Wait
}

// sendFromPeer sends a WireGuard-looking packet from the peer to the shared
// port and returns which receive func reported it.
func (f *connectedUDPFixture) sendFromPeer(t *testing.T) connectedUDPRx {
	t.Helper()
	wgPacket := make([]byte, 64)
	wgPacket[0] = 4 // a transport message, as far as magicsock can tell
	if _, err := f.peer.WriteToUDPAddrPort(wgPacket, f.sharedAddr); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-f.rx:
		if r.ep != f.ep {
			t.Fatalf("packet reported for endpoint %v, want %v", r.ep, f.ep)
		}
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the peer's packet")
	}
	panic("unreachable")
}

// promote runs the heartbeat's promotion for the fixture's peer with enough
// traffic recorded, and waits for the connected socket.
func (f *connectedUDPFixture) promote(t *testing.T) *connectedUDPConn {
	t.Helper()
	f.ep.noteConnectedUDPTx(int(connectedUDPPromoteBytes))
	f.ep.mu.Lock()
	f.ep.updateConnectedUDPLocked(mono.Now())
	f.ep.mu.Unlock()
	var cu *connectedUDPConn
	if err := tstest.WaitFor(5*time.Second, func() error {
		f.ep.mu.Lock()
		defer f.ep.mu.Unlock()
		if cu = f.ep.connectedSocket; cu == nil {
			return errors.New("no connected socket yet")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return cu
}

// connectedSocket returns the fixture peer's connected socket, or nil.
func (f *connectedUDPFixture) connectedSocket() *connectedUDPConn {
	f.ep.mu.Lock()
	defer f.ep.mu.Unlock()
	return f.ep.connectedSocket
}

// send sends one 100-byte WireGuard batch to the peer through the endpoint.
func (f *connectedUDPFixture) send(t *testing.T) {
	t.Helper()
	buffs := [][]byte{make([]byte, packet.GeneveFixedHeaderLength+100)}
	if err := f.ep.send(buffs, packet.GeneveFixedHeaderLength); err != nil {
		t.Fatalf("send: %v", err)
	}
}

// expectAtPeer reads one datagram at the peer and checks its payload size and
// that it came from the shared port.
func (f *connectedUDPFixture) expectAtPeer(t *testing.T, size int) {
	t.Helper()
	f.peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	n, from, err := f.peer.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != size || from != f.sharedAddr {
		t.Fatalf("peer got %d bytes from %v, want %d from %v", n, from, size, f.sharedAddr)
	}
}

// waitSlotsFree waits for every receive slot to be back on the free list.
func (f *connectedUDPFixture) waitSlotsFree(t *testing.T) {
	t.Helper()
	if err := tstest.WaitFor(5*time.Second, func() error {
		if n, want := f.c.freeConnectedUDPSlots(), f.c.connectedUDP.maxSockets; n != want {
			return fmt.Errorf("%d free receive slots, want %d", n, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// waitExit waits for every receive func to have returned, as wireguard-go
// does on bind close.
func (f *connectedUDPFixture) waitExit(t *testing.T, what string) {
	t.Helper()
	mustReturn(t, "receive funcs after "+what, f.wait)
}

func (c *Conn) freeConnectedUDPSlots() int {
	c.connectedUDP.mu.Lock()
	defer c.connectedUDP.mu.Unlock()
	return len(c.connectedUDP.free)
}

// mustReturn fails the test if fn has not returned after 5 s, which is how a
// deadlock or a leaked receive func shows up.
func mustReturn(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return", what)
	}
}

// TestConnectedUDP walks a peer through the life of a connected UDP socket:
// its packets arrive on the shared socket's receive func, it gets promoted
// once it has been sent enough, its packets then arrive on a connected
// socket's receive func, sends to it leave from the shared port, and a path
// change closes the socket and frees its receive slot.
func TestConnectedUDP(t *testing.T) {
	f := newConnectedUDPFixture(t)
	c, ep := f.c, f.ep

	if r := f.sendFromPeer(t); r.fn != fnIPv4 {
		t.Fatalf("before promotion, packet arrived on receive func %d, want %d (IPv4)", r.fn, fnIPv4)
	}

	// Not enough traffic: no promotion.
	ep.noteConnectedUDPTx(int(connectedUDPPromoteBytes - 1))
	ep.mu.Lock()
	ep.updateConnectedUDPLocked(mono.Now())
	dialing := ep.connectedUDPDialing
	ep.mu.Unlock()
	if dialing {
		t.Fatal("promoted below the traffic threshold")
	}

	// Enough traffic over one heartbeat: promotion.
	cu := f.promote(t)
	if cu.remote != f.peerAddr || cu.localPort != c.pconn4.Port() {
		t.Fatalf("connected socket %v -> %v, want local port %d -> %v", cu.localPort, cu.remote, c.pconn4.Port(), f.peerAddr)
	}
	if got, want := c.freeConnectedUDPSlots(), c.connectedUDP.maxSockets-1; got != want {
		t.Fatalf("%d free receive slots, want %d", got, want)
	}

	// The kernel now delivers the peer's packets to the connected socket,
	// which one of the reserved receive funcs reads.
	if r := f.sendFromPeer(t); !f.isSlotFn(r.fn) {
		t.Fatalf("after promotion, packet arrived on receive func %d, want a connected socket slot", r.fn)
	}

	// Sends go through the connected socket and still leave from the shared
	// port, so the peer sees no change.
	f.send(t)
	f.expectAtPeer(t, 100)

	// A path change closes the connected socket and frees its slot.
	ep.mu.Lock()
	ep.setBestAddrLocked(addrQuality{})
	stillConnected := ep.connectedSocket
	ep.mu.Unlock()
	if stillConnected != nil {
		t.Fatal("connected socket survived a path change")
	}
	if !cu.closed.Load() {
		t.Fatal("connected socket not closed after a path change")
	}
	f.waitSlotsFree(t)

	// Closing the bind ends every receive func, slots included.
	if err := c.Bind().Close(); err != nil {
		t.Fatal(err)
	}
	f.waitExit(t, "bind close")
}

// TestConnectedUDPPathChangedWhileDialing checks that a promotion whose peer
// moved to another path while the dial was in flight gives the socket up
// without deadlocking on the endpoint's lock, and frees its slot.
func TestConnectedUDPPathChangedWhileDialing(t *testing.T) {
	f := newConnectedUDPFixture(t)
	ep := f.ep

	other := netip.MustParseAddrPort("127.0.0.1:9")
	ep.mu.Lock()
	ep.connectedUDPDialing = true
	// The heartbeat decided to promote f.peerAddr, but the path is now other.
	ep.setBestAddrLocked(addrQuality{epAddr: epAddr{ap: other}})
	ep.mu.Unlock()
	before := metricNumConnectedUDPSockets.Value()
	mustReturn(t, "promoteConnectedUDP", func() { ep.promoteConnectedUDP(f.peerAddr) })

	ep.mu.Lock()
	installed, dialing := ep.connectedSocket, ep.connectedUDPDialing
	ep.mu.Unlock()
	if installed != nil || dialing {
		t.Fatalf("connected socket installed = %v, dialing = %v; want nil, false", installed, dialing)
	}
	f.waitSlotsFree(t)
	if n := metricNumConnectedUDPSockets.Value(); n != before {
		t.Fatalf("connected sockets gauge = %d, want %d", n, before)
	}
}

// TestConnectedUDPRebindWhileDialing checks that a socket closed by a rebind
// between its dial and its installation is not installed, so the peer is not
// left on a dead socket, and that it is promoted again afterwards.
func TestConnectedUDPRebindWhileDialing(t *testing.T) {
	f := newConnectedUDPFixture(t)
	c, ep := f.c, f.ep

	ep.mu.Lock()
	ep.connectedUDPDialing = true
	ep.mu.Unlock()
	cu, err := c.dialConnectedUDP(ep, f.peerAddr)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.rebind(keepCurrentPort); err != nil {
		t.Fatal(err)
	}
	if !cu.closed.Load() {
		t.Fatal("rebind did not close the dialed socket")
	}
	mustReturn(t, "installConnectedUDP", func() { ep.installConnectedUDP(f.peerAddr, cu, nil) })
	if f.connectedSocket() != nil {
		t.Fatal("a closed socket was installed")
	}

	// The rebind kept the port, so the peer is still reachable over the
	// shared socket and gets promoted again.
	if c.pconn4.Port() != f.sharedAddr.Port() {
		t.Skipf("rebind moved the shared socket from port %d to %d", f.sharedAddr.Port(), c.pconn4.Port())
	}
	f.send(t)
	f.expectAtPeer(t, 100)
	f.waitSlotsFree(t)
	f.promote(t)
}

// TestConnectedUDPBindCloseWhileDialing checks that a dial that completes
// around a bind close neither installs a socket on the closed bind nor leaks
// its receive slot, so that every receive func exits and wireguard-go's bind
// close does not hang.
func TestConnectedUDPBindCloseWhileDialing(t *testing.T) {
	t.Run("registered-before-close", func(t *testing.T) {
		f := newConnectedUDPFixture(t)
		c, ep := f.c, f.ep
		ep.mu.Lock()
		ep.connectedUDPDialing = true
		ep.mu.Unlock()
		cu, err := c.dialConnectedUDP(ep, f.peerAddr)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Bind().Close(); err != nil {
			t.Fatal(err)
		}
		mustReturn(t, "installConnectedUDP", func() { ep.installConnectedUDP(f.peerAddr, cu, nil) })
		if f.connectedSocket() != nil {
			t.Fatal("a socket was installed on a closed bind")
		}
		f.waitExit(t, "bind close")
	})
	t.Run("slot-taken-dial-fails", func(t *testing.T) {
		f := newConnectedUDPFixture(t)
		c := f.c
		slot, err := c.takeConnectedUDPSlot() // a dial in flight
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Bind().Close(); err != nil {
			t.Fatal(err)
		}
		// With the shared socket closed there is no port to dial from.
		if _, err := c.dialConnectedUDPSocket(f.peerAddr); err == nil {
			t.Fatal("dial succeeded after bind close")
		}
		c.giveBackConnectedUDPSlot(slot) // what dialConnectedUDP does on that error
		f.waitExit(t, "bind close with a dial in flight")
	})
}

// TestConnectedUDPSendErrorFallsBack checks that a connected socket that
// fails under its peer is dropped on the next send, with the batch sent over
// the shared socket, and that the peer is promoted again afterwards.
func TestConnectedUDPSendErrorFallsBack(t *testing.T) {
	f := newConnectedUDPFixture(t)

	cu := f.promote(t)
	// The socket dies underneath magicsock, which does not know yet.
	cu.pconn.Close()

	f.send(t)
	f.expectAtPeer(t, 100)
	if f.connectedSocket() != nil {
		t.Fatal("dead connected socket still installed after a send error")
	}
	f.waitSlotsFree(t)
	if cu2 := f.promote(t); cu2 == cu {
		t.Fatal("re-promotion reused the dead socket")
	}
}

// TestConnectedUDPICMPErrorIgnored checks that an ICMP error about the peer,
// which the kernel reports once on the connected socket, neither closes the
// socket nor loses the batch: the peer's port is closed, so the first send
// draws a port unreachable, and the following sends still go out.
func TestConnectedUDPICMPErrorIgnored(t *testing.T) {
	f := newConnectedUDPFixture(t)
	c, ep := f.c, f.ep

	cu := f.promote(t)
	f.peer.Close()
	f.send(t) // reaches a closed port: ICMP port unreachable comes back
	if err := tstest.WaitFor(2*time.Second, func() error {
		// Give the ICMP time to arrive; the next send reports it.
		f.send(t)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.send(t)
	if f.connectedSocket() != cu || cu.closed.Load() {
		t.Fatal("an ICMP port unreachable closed the connected socket")
	}
	if got, want := c.freeConnectedUDPSlots(), c.connectedUDP.maxSockets-1; got != want {
		t.Fatalf("%d free receive slots, want %d", got, want)
	}

	// The peer comes back on the same port; traffic flows on the same socket.
	peer, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(f.peerAddr))
	if err != nil {
		t.Skipf("peer port %v not free again: %v", f.peerAddr, err)
	}
	defer peer.Close()
	f.peer = peer
	ep.mu.Lock()
	ep.lastSendExt = mono.Now()
	ep.mu.Unlock()
	f.send(t)
	f.expectAtPeer(t, 100)
}

// TestConnectedUDPCap checks that a busy peer beyond the cap is refused,
// counted, and left on the shared socket.
func TestConnectedUDPCap(t *testing.T) {
	f := newConnectedUDPFixture(t)
	c, ep := f.c, f.ep

	var taken []*connectedUDPSlot
	for range c.connectedUDP.maxSockets {
		slot, err := c.takeConnectedUDPSlot()
		if err != nil {
			t.Fatalf("ran out of slots early: %v", err)
		}
		taken = append(taken, slot)
	}
	before := metricConnectedUDPNoSlot.Value()
	if _, err := c.dialConnectedUDP(ep, f.peerAddr); !errors.Is(err, errConnectedUDPNoSlot) {
		t.Fatalf("dial with all slots taken = %v, want errConnectedUDPNoSlot", err)
	}
	if got := metricConnectedUDPNoSlot.Value(); got != before+1 {
		t.Fatalf("no-slot counter = %d, want %d", got, before+1)
	}
	f.send(t)
	f.expectAtPeer(t, 100)
	for _, slot := range taken {
		c.giveBackConnectedUDPSlot(slot)
	}
	f.promote(t)
}

// TestConnectedUDPStress races promotion against path changes, socket
// closes and sends for a while, then checks that every socket is closed,
// every slot is free and the bind closes cleanly.
func TestConnectedUDPStress(t *testing.T) {
	f := newConnectedUDPFixture(t)
	c, ep := f.c, f.ep
	before := metricNumConnectedUDPSockets.Value()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	run := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					fn()
				}
			}
		}()
	}
	run(func() {
		ep.noteConnectedUDPTx(int(connectedUDPPromoteBytes))
		ep.mu.Lock()
		ep.updateConnectedUDPLocked(mono.Now())
		ep.mu.Unlock()
	})
	run(func() {
		ep.mu.Lock()
		ep.setBestAddrLocked(addrQuality{})
		ep.setBestAddrLocked(addrQuality{epAddr: epAddr{ap: f.peerAddr}})
		ep.trustBestAddrUntil = mono.Now().Add(time.Hour)
		ep.mu.Unlock()
	})
	run(func() { c.closeConnectedUDPSockets("stress") })
	run(func() {
		buffs := [][]byte{make([]byte, packet.GeneveFixedHeaderLength+100)}
		ep.send(buffs, packet.GeneveFixedHeaderLength)
	})
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	if err := tstest.WaitFor(5*time.Second, func() error {
		ep.mu.Lock()
		dialing := ep.connectedUDPDialing
		ep.mu.Unlock()
		if dialing {
			return errors.New("dial still in flight")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ep.mu.Lock()
	ep.setBestAddrLocked(addrQuality{})
	ep.mu.Unlock()
	f.waitSlotsFree(t)
	if n := metricNumConnectedUDPSockets.Value(); n != before {
		t.Fatalf("connected sockets gauge = %d, want %d", n, before)
	}
	if err := c.Bind().Close(); err != nil {
		t.Fatal(err)
	}
	f.waitExit(t, "bind close")
}

func TestIsICMPErr(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want bool
	}{
		{&net.OpError{Op: "read", Err: syscall.ECONNREFUSED}, true},
		{&net.OpError{Op: "write", Err: &net.OpError{Err: syscall.EHOSTUNREACH}}, true},
		{syscall.EPROTO, true},
		{syscall.EMSGSIZE, true},
		{syscall.ENETUNREACH, true},
		{net.ErrClosed, false},
		{syscall.EBADF, false},
		{errors.New("x"), false},
		{nil, false},
	} {
		if got := isICMPErr(tt.err); got != tt.want {
			t.Errorf("isICMPErr(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

// TestConnectedUDPNoInboundWatchdog checks that a connected socket over which
// nothing has arrived from the peer for connectedUDPNoInboundAfter, while the
// session stays active, is closed in favour of the shared socket.
func TestConnectedUDPNoInboundWatchdog(t *testing.T) {
	f := newConnectedUDPFixture(t)
	ep := f.ep

	cu := f.promote(t)
	now := mono.Now()
	before := metricConnectedUDPNoInbound.Value()

	// Fresh socket, peer quiet: too early to judge.
	ep.lastRecvUDPAny.StoreAtomic(now.Add(-2 * connectedUDPNoInboundAfter))
	ep.mu.Lock()
	ep.checkConnectedUDPInboundLocked(now)
	ep.mu.Unlock()
	if f.connectedSocket() != cu {
		t.Fatal("watchdog closed a socket younger than its threshold")
	}

	// Old socket, peer heard from recently: fine.
	cu.openedAt = now.Add(-2 * connectedUDPNoInboundAfter)
	ep.lastRecvUDPAny.StoreAtomic(now.Add(-heartbeatInterval))
	ep.mu.Lock()
	ep.checkConnectedUDPInboundLocked(now)
	ep.mu.Unlock()
	if f.connectedSocket() != cu {
		t.Fatal("watchdog closed a socket whose peer was heard from recently")
	}

	// Old socket, nothing from the peer: closed, counted.
	ep.lastRecvUDPAny.StoreAtomic(now.Add(-connectedUDPNoInboundAfter))
	ep.mu.Lock()
	ep.checkConnectedUDPInboundLocked(now)
	ep.mu.Unlock()
	if f.connectedSocket() != nil || !cu.closed.Load() {
		t.Fatal("watchdog did not close a socket with no inbound")
	}
	if got := metricConnectedUDPNoInbound.Value(); got != before+1 {
		t.Fatalf("no-inbound counter = %d, want %d", got, before+1)
	}
	f.waitSlotsFree(t)
	f.send(t)
	f.expectAtPeer(t, 100)
}

// failingRawConn is a syscall.RawConn whose Control always fails, standing in
// for a kernel that refuses setsockopt.
type failingRawConn struct{}

func (failingRawConn) Control(func(fd uintptr)) error    { return errors.New("setsockopt refused") }
func (failingRawConn) Read(func(fd uintptr) bool) error  { return errors.New("unused") }
func (failingRawConn) Write(func(fd uintptr) bool) error { return errors.New("unused") }

// TestConnectedUDPReusePortRefused checks that a kernel refusing SO_REUSEPORT
// on the shared socket costs the feature, not the bind: the Control hook
// succeeds, the inner hook still runs, and promotion is off for good.
func TestConnectedUDPReusePortRefused(t *testing.T) {
	f := newConnectedUDPFixture(t)
	c, ep := f.c, f.ep

	innerCalled := false
	lc := c.sharedSocketListenConfig(&net.ListenConfig{Control: func(network, address string, rc syscall.RawConn) error {
		innerCalled = true
		return nil
	}})
	if err := lc.Control("udp4", ":0", failingRawConn{}); err != nil {
		t.Fatalf("shared socket Control returned %v, want nil (bind must succeed without SO_REUSEPORT)", err)
	}
	if !innerCalled {
		t.Fatal("inner Control hook (netns options) was skipped")
	}
	if !c.connectedUDPUnsupported() {
		t.Fatal("feature not disabled after SO_REUSEPORT was refused")
	}
	ep.noteConnectedUDPTx(int(connectedUDPPromoteBytes))
	ep.mu.Lock()
	ep.updateConnectedUDPLocked(mono.Now())
	dialing := ep.connectedUDPDialing
	ep.mu.Unlock()
	if dialing {
		t.Fatal("promotion attempted with the feature disabled")
	}

	// The connected socket's own dial, by contrast, must fail on the error.
	dl := withReusePort(&net.ListenConfig{}, func(err error) error { return err })
	if err := dl.Control("udp4", ":0", failingRawConn{}); err == nil {
		t.Fatal("connected socket Control ignored a SO_REUSEPORT failure")
	}
}

// TestConnectedUDPMaxSockets checks how TS_CONNECTED_UDP_MAX_SOCKETS turns
// into the cap, and that Open reserves one receive slot per allowed socket.
func TestConnectedUDPMaxSockets(t *testing.T) {
	for _, tt := range []struct{ knob, want int }{
		{0, connectedUDPDefaultMaxSockets},
		{3, 3},
		{-1, 1},
		{100000, connectedUDPMaxSocketsLimit},
	} {
		if got := connectedUDPSocketCap(tt.knob); got != tt.want {
			t.Errorf("connectedUDPSocketCap(%d) = %d, want %d", tt.knob, got, tt.want)
		}
	}

	envknob.SetenvForTest(t, "TS_ENABLE_CONNECTED_UDP", "true")
	c := newRealSocketTestConn(t)
	if got := c.connectedUDP.maxSockets; got != connectedUDPDefaultMaxSockets {
		t.Fatalf("default cap %d, want %d", got, connectedUDPDefaultMaxSockets)
	}
	c.connectedUDP.maxSockets = 3 // as TS_CONNECTED_UDP_MAX_SOCKETS=3 would
	fns, _, err := c.Bind().Open(0)
	if err != nil {
		t.Fatal(err)
	}
	wait := runReceiveFuncs(fns, make(chan connectedUDPRx, 1024))
	if got, want := len(fns), fnFirstSlot+3+1; got != want {
		t.Errorf("Open returned %d receive funcs with a cap of 3, want %d", got, want)
	}
	if err := c.Bind().Close(); err != nil {
		t.Fatal(err)
	}
	mustReturn(t, "receive funcs after bind close", wait)
}

// TestConnectedUDPDemote checks that a peer gives its connected socket up
// once it has been sent little for connectedUDPDemoteAfter, that one busy
// interval restarts that wait, and that a demoted peer is promoted again
// when it gets busy.
func TestConnectedUDPDemote(t *testing.T) {
	f := newConnectedUDPFixture(t)
	ep := f.ep
	cu := f.promote(t)
	before := metricConnectedUDPDemoted.Value()

	// heartbeat runs the heartbeat's update at now, with txBytes sent over
	// the interval that just ended.
	heartbeat := func(now mono.Time, txBytes int) {
		ep.noteConnectedUDPTx(txBytes)
		ep.mu.Lock()
		ep.updateConnectedUDPLocked(now)
		ep.mu.Unlock()
	}
	t0 := mono.Now()

	// Quiet from t0, then busy just before the minute is up: kept.
	heartbeat(t0, int(connectedUDPDemoteBytes-1))
	heartbeat(t0.Add(connectedUDPDemoteAfter-time.Second), 0)
	heartbeat(t0.Add(connectedUDPDemoteAfter), int(connectedUDPDemoteBytes))
	heartbeat(t0.Add(connectedUDPDemoteAfter+heartbeatInterval), 0)
	if f.connectedSocket() != cu {
		t.Fatal("connected socket closed although a busy interval restarted the wait")
	}

	// Quiet again from t1: kept until the minute is up, then closed.
	t1 := t0.Add(connectedUDPDemoteAfter + heartbeatInterval)
	heartbeat(t1.Add(connectedUDPDemoteAfter-time.Millisecond), 0)
	if f.connectedSocket() != cu {
		t.Fatal("connected socket closed before connectedUDPDemoteAfter")
	}
	heartbeat(t1.Add(connectedUDPDemoteAfter), 0)
	if f.connectedSocket() != nil || !cu.closed.Load() {
		t.Fatal("connected socket not closed after connectedUDPDemoteAfter of quiet")
	}
	if got := metricConnectedUDPDemoted.Value(); got != before+1 {
		t.Fatalf("demoted counter = %d, want %d", got, before+1)
	}
	f.waitSlotsFree(t)
	f.send(t)
	f.expectAtPeer(t, 100)
	if r := f.sendFromPeer(t); r.fn != fnIPv4 {
		t.Fatalf("after demotion, packet arrived on receive func %d, want %d (IPv4)", r.fn, fnIPv4)
	}

	// Busy again: promoted again, with a fresh wait.
	cu2 := f.promote(t)
	ep.mu.Lock()
	quiet := ep.connectedUDPQuietSince
	ep.mu.Unlock()
	if cu2 == cu || !quiet.IsZero() {
		t.Fatalf("re-promotion: same socket %v, quiet since %v; want a new socket and no quiet time", cu2 == cu, quiet)
	}
}

// TestConnectedUDPCountsConnectedTx checks that what is sent over the
// connected socket counts towards keeping it.
func TestConnectedUDPCountsConnectedTx(t *testing.T) {
	f := newConnectedUDPFixture(t)
	f.promote(t)
	f.ep.connectedUDPTxBytes.Store(0)
	f.send(t)
	f.expectAtPeer(t, 100)
	if got := f.ep.connectedUDPTxBytes.Load(); got != 100 {
		t.Fatalf("bytes counted after a send over the connected socket = %d, want 100", got)
	}
}

// TestConnectedUDPFallback checks the fallback for more busy peers than
// slots: a busy peer that finds every slot in use closes every connected
// socket and stops promotions, which resume once no more peers than slots
// have qualified for connectedUDPFallbackHold.
func TestConnectedUDPFallback(t *testing.T) {
	f := newConnectedUDPFixture(t)
	c, ep := f.c, f.ep
	s := &c.connectedUDP

	// Another peer holds the last free slot; the test holds the rest.
	other := &endpoint{c: c}
	otherPeer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { otherPeer.Close() })
	var taken []*connectedUDPSlot
	for range s.maxSockets - 1 {
		slot, err := c.takeConnectedUDPSlot()
		if err != nil {
			t.Fatal(err)
		}
		taken = append(taken, slot)
	}
	otherCU, err := c.dialConnectedUDP(other, otherPeer.LocalAddr().(*net.UDPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	other.mu.Lock()
	other.connectedSocket = otherCU
	other.mu.Unlock()

	heartbeat := func(now mono.Time, txBytes int64) {
		ep.noteConnectedUDPTx(int(txBytes))
		ep.mu.Lock()
		ep.updateConnectedUDPLocked(now)
		ep.mu.Unlock()
	}
	inFallback := func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.fallback
	}

	// Below the promotion rate: nothing happens.
	t0 := mono.Now()
	heartbeat(t0, connectedUDPPromoteBytes-1)
	if inFallback() {
		t.Fatal("fallback for a peer below connectedUDPPromoteRate")
	}

	// Busy without a slot: fallback, the other peer's socket closes.
	before := metricConnectedUDPFallback.Value()
	heartbeat(t0, connectedUDPPromoteBytes)
	if !inFallback() {
		t.Fatal("no fallback for a busy peer with every slot in use")
	}
	if got := metricConnectedUDPFallback.Value(); got != before+1 {
		t.Fatalf("fallback counter = %d, want %d", got, before+1)
	}
	if err := tstest.WaitFor(5*time.Second, func() error {
		if !otherCU.closed.Load() {
			return errors.New("other peer's connected socket still open")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, slot := range taken {
		c.giveBackConnectedUDPSlot(slot)
	}

	// No promotion while it lasts, even with free slots.
	heartbeat(t0.Add(heartbeatInterval), connectedUDPPromoteBytes)
	ep.mu.Lock()
	dialing, cu := ep.connectedUDPDialing, ep.connectedSocket
	ep.mu.Unlock()
	if dialing || cu != nil {
		t.Fatal("peer promoted during the fallback")
	}

	// More qualifying peers than slots keep it on past the hold.
	t1 := t0.Add(connectedUDPFallbackHold)
	s.mu.Lock()
	for range s.maxSockets + 1 {
		mak.Set(&s.qualified, &endpoint{}, t1)
	}
	s.mu.Unlock()
	heartbeat(t1, 0)
	if !inFallback() {
		t.Fatal("fallback ended with more qualifying peers than slots")
	}

	// Those go quiet: it ends connectedUDPFallbackHold after they were last
	// seen, and the peer is promoted again.
	heartbeat(t1.Add(connectedUDPFallbackHold-time.Second), connectedUDPPromoteBytes)
	if !inFallback() {
		t.Fatal("fallback ended before connectedUDPFallbackHold")
	}
	heartbeat(t1.Add(connectedUDPFallbackHold), 0)
	if inFallback() {
		t.Fatal("fallback still on connectedUDPFallbackHold after the contention")
	}
	f.promote(t)
}

// TestConnectedUDPFallbackEndsAfterIdle checks that a fallback whose busy
// peers all went idle ends at the next heartbeat, not a hold later.
func TestConnectedUDPFallbackEndsAfterIdle(t *testing.T) {
	f := newConnectedUDPFixture(t)
	s := &f.c.connectedUDP
	t0 := mono.Now()
	s.mu.Lock()
	s.fallback = true
	s.contendedAt = t0.Add(-time.Hour)
	s.mu.Unlock()
	f.promote(t)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fallback {
		t.Fatal("fallback still on after an hour without contention")
	}
}
