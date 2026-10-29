// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/net/batching"
	"tailscale.com/net/neterror"
	"tailscale.com/net/netns"
	"tailscale.com/net/packet"
	"tailscale.com/net/sockopts"
	"tailscale.com/net/sockstats"
	"tailscale.com/syncs"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/nettype"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
)

// This file implements per-peer connected UDP sockets, an opt-in
// (TS_ENABLE_CONNECTED_UDP, Linux only) optimization for busy peers on a
// direct path.
//
// magicsock sends every peer's packets from one unconnected socket per
// address family. On Linux the kernel picks a NIC transmit queue per datagram
// in netdev_pick_tx: the queue remembered on the socket if there is one, else
// the one XPS maps the sending CPU to, else a hash of the 5-tuple. It only
// remembers a queue on a socket with a cached route, which only a connected
// socket has. So from an unconnected socket the queue follows whichever CPU
// the sending goroutine runs on, one peer's traffic is spread over every
// transmit queue, the NIC drains those queues independently, and packets of a
// single flow reach the wire out of order. TCP inside the tunnel treats that
// as loss and slows down; on a 12-queue 10G NIC one stream got about half of
// line rate.
//
// A socket connected to the peer, bound to the same local port with
// SO_REUSEPORT, keeps that peer's packets on one queue, in order. Nothing
// changes on the wire: same local port, same peer address and port.
//
// The kernel delivers the peer's incoming packets to the connected socket as
// the most specific match (since Linux 5.4; older kernels spread a reuseport
// group's datagrams by hash, and both sockets handle them the same way), so
// each connected socket needs its own receive loop. wireguard-go runs one
// goroutine per receive func and fixes the set when the bind opens, so Open
// hands it one extra receive func per allowed connected socket (32 unless
// TS_CONNECTED_UDP_MAX_SOCKETS says otherwise), each a slot that blocks until
// a connected socket is assigned to it and waits again when that socket is
// closed. A busy peer that finds every slot taken stays on the shared socket.
//
// A socket is opened for a peer once it has been sent 10 Mbit/s from us over
// a heartbeat interval, and closed when it has been sent less than 2.5 Mbit/s
// for a minute, so that a peer that was busy once does not keep a slot from
// one that is busy now. If a busy peer finds every slot taken, all connected
// sockets are closed until the contention is over: either every busy peer
// has a connected socket or none has, so that the peers without one never
// compete with the peers with one. See connectedUDPPromoteRate. A socket is
// also closed when the peer's path
// changes (which is also how peer removal, a bad endpoint and a PMTUD change
// arrive here), its session goes idle, magicsock rebinds, the bind closes, or
// the socket itself fails. Only direct paths qualify: a peer relay path carries a Geneve
// header and shares the relay's 5-tuple with other peers, and DERP is TCP.
//
// Unlike the shared socket, a connected socket is told about ICMP errors for
// its peer (ECONNREFUSED and the like, once, on the next read or write), and
// anyone who knows the 4-tuple can send such an ICMP message. Those errors are
// ignored, which is what not hearing about them on the shared socket amounts
// to.
//
// With the knob set, the shared sockets carry SO_REUSEPORT, which lets another
// process of the same UID bind the same port and take a share of the inbound
// datagrams. That is the UID that can read the state file.

const (
	// connectedUDPDefaultMaxSockets caps the connected sockets per Conn,
	// unless TS_CONNECTED_UDP_MAX_SOCKETS says otherwise. The cap is also the
	// number of receive funcs reserved for them at Open time, each a parked
	// wireguard-go goroutine holding a 128 KiB receive buffer (about 25 KiB
	// of it resident until a socket has used the slot). wireguard-go fixes
	// the set of receive funcs at Open, so the cap is read once and cannot
	// change at runtime.
	connectedUDPDefaultMaxSockets = 32

	// connectedUDPMaxSocketsLimit bounds TS_CONNECTED_UDP_MAX_SOCKETS.
	connectedUDPMaxSocketsLimit = 256

	// connectedUDPPromoteRate is how fast, in bits per second over one
	// heartbeatInterval on a direct path, a peer must be sent to before it
	// gets a connected socket.
	//
	// It is low on purpose. One TCP flow at fixed rates through the shared
	// socket on a 12-queue 10G NIC (ixgbe, default XPS) saw 10 to 30
	// reordering events per 1000 segments at every rate from 10 Mbit/s up,
	// but TCP absorbed them: every rate up to 4 Gbit/s was reached exactly,
	// with no retransmits up to 2 Gbit/s and a handful at 3 and 4. Above that
	// the flow stopped at about 4.3 Gbit/s, against 8.97 for a connected
	// socket. So a lone small flow gains nothing from a connected socket, but
	// it loses nothing either, and a slot is cheap. What matters is that busy
	// peers are treated alike: on a full link, a flow on the shared socket
	// that competes with connected flows gets only tens to a hundred or so
	// Mbit/s (45 to 160 in testing), which would keep it below any high
	// threshold for good.
	connectedUDPPromoteRate = 10_000_000

	// connectedUDPDemoteRate and connectedUDPDemoteAfter decide when a peer
	// gives its connected socket up: when it has been sent less than
	// connectedUDPDemoteRate in every heartbeatInterval for at least
	// connectedUDPDemoteAfter. The gap to connectedUDPPromoteRate keeps a
	// peer near the threshold from switching back and forth, and the minute
	// rides out pauses in a bulk transfer.
	connectedUDPDemoteRate  = 2_500_000
	connectedUDPDemoteAfter = 60 * time.Second

	// connectedUDPFallbackHold is how long no more peers than there are
	// slots must qualify for promotion before the Conn leaves the fallback.
	connectedUDPFallbackHold = 60 * time.Second

	// The rates as bytes per heartbeatInterval, which is what is counted.
	connectedUDPPromoteBytes = connectedUDPPromoteRate / 8 * int64(heartbeatInterval/time.Second)
	connectedUDPDemoteBytes  = connectedUDPDemoteRate / 8 * int64(heartbeatInterval/time.Second)

	// connectedUDPNoInboundAfter is how long a connected socket may go
	// without a packet from its peer, while the session is active, before it
	// is closed in favour of the shared socket. The heartbeat pings the peer
	// every heartbeatInterval and the pong arrives on the connected socket,
	// so a healthy one hears from the peer at least that often. This is a
	// safety net for a receive slot that stopped reading, which would
	// otherwise black-hole the peer's inbound for as long as the socket
	// exists; it is not expected to fire.
	connectedUDPNoInboundAfter = 3 * heartbeatInterval
)

var (
	metricNumConnectedUDPSockets = clientmetric.NewGauge("magicsock_num_connected_udp_sockets")
	metricConnectedUDPOpened     = clientmetric.NewCounter("magicsock_connected_udp_opened")
	metricConnectedUDPClosed     = clientmetric.NewCounter("magicsock_connected_udp_closed")
	metricConnectedUDPDialError  = clientmetric.NewCounter("magicsock_connected_udp_dial_error")
	metricConnectedUDPNoSlot     = clientmetric.NewCounter("magicsock_connected_udp_no_slot")
	metricConnectedUDPNoInbound  = clientmetric.NewCounter("magicsock_connected_udp_no_inbound")
	metricConnectedUDPDemoted    = clientmetric.NewCounter("magicsock_connected_udp_demoted")
	metricConnectedUDPFallback   = clientmetric.NewCounter("magicsock_connected_udp_fallback")
)

var (
	errConnectedUDPNoSlot      = errors.New("all connected UDP receive slots in use")
	errConnectedUDPPortChanged = errors.New("shared socket's port changed during dial")
	errConnectedUDPUnsupported = errors.New("connected UDP sockets disabled")
	errConnectedUDPFallback    = errors.New("connected UDP sockets off while more peers are busy than there are slots")
)

// connectedUDPConn is a UDP socket connected to one peer's direct address,
// sharing the local port of the unconnected socket of the same family.
type connectedUDPConn struct {
	pconn     batching.Conn
	remote    netip.AddrPort
	network   string // "udp4" or "udp6"
	localPort uint16 // the shared socket's port at dial time
	openedAt  mono.Time
	closed    atomic.Bool
}

// close closes the socket once. The receive slot reading from it notices the
// error and frees itself.
func (cu *connectedUDPConn) close() {
	if cu.closed.CompareAndSwap(false, true) {
		cu.pconn.Close()
		metricNumConnectedUDPSockets.Add(-1)
		metricConnectedUDPClosed.Add(1)
	}
}

// connectedUDPSlot is one of the receive funcs reserved for connected
// sockets. It is either in connectedUDPState.free, or held by exactly one
// dialer, which either hands it a socket on ch or closes ch. Its receive func
// returns net.ErrClosed, so that its wireguard-go goroutine exits, when ch is
// closed or when the bind is found closed after its socket went away.
type connectedUDPSlot struct {
	ch  chan *connectedUDPConn // buffered 1
	gen uint64                 // the connBind open this slot belongs to
}

// connectedUDPState is a Conn's bookkeeping for connected sockets.
type connectedUDPState struct {
	// enabled is whether this Conn opens connected sockets at all, and
	// maxSockets how many at once. They are set once in NewConn and read
	// without mu.
	enabled    bool
	maxSockets int

	// mu guards the following fields. Lock ordering: Conn.mu, then
	// endpoint.mu, then this mu, then RebindingUDPConn.mu.
	mu syncs.Mutex

	// open is whether the bind is open. gen counts opens: wireguard-go waits
	// for every receive func to return before it opens the bind again, so
	// gen only matters if a slot's receive func outlives its bind, but it
	// keeps a stale slot out of a later bind's free list in that case.
	open        bool
	gen         uint64
	free        []*connectedUDPSlot
	active      map[*connectedUDPConn]*endpoint
	unsupported bool // the platform cannot do this; see disableConnectedUDP
	noSlotNoted bool // the cap has been logged for the current episode

	// fallback is whether every peer is on the shared socket because a busy
	// peer found every slot in use. qualified holds when each peer last
	// qualified for promotion during the fallback, and contendedAt when more
	// peers than there are slots last did. See connectedUDPAdmit.
	fallback    bool
	qualified   map[*endpoint]mono.Time
	contendedAt mono.Time
}

// initConnectedUDP decides, once, whether this Conn opens connected sockets.
// It is called from NewConn before the shared sockets are bound.
func (c *Conn) initConnectedUDP() {
	s := &c.connectedUDP
	s.enabled = connectedUDPSupported && hasUDPTransport && enableConnectedUDP() &&
		c.testOnlyPacketListener == nil && !debugAlwaysDERP()
	if !s.enabled {
		return
	}
	n := connectedUDPMaxSockets()
	s.maxSockets = connectedUDPSocketCap(n)
	if n != 0 && s.maxSockets != n {
		c.logf("magicsock: TS_CONNECTED_UDP_MAX_SOCKETS=%d out of range [1, %d]; using %d", n, connectedUDPMaxSocketsLimit, s.maxSockets)
	}
}

// connectedUDPSocketCap returns the cap on connected sockets for a
// TS_CONNECTED_UDP_MAX_SOCKETS of n, where 0 means unset.
func connectedUDPSocketCap(n int) int {
	if n == 0 {
		return connectedUDPDefaultMaxSockets
	}
	return min(max(n, 1), connectedUDPMaxSocketsLimit)
}

// connectedUDPEnabled reports whether this Conn opens connected sockets for
// busy peers.
func (c *Conn) connectedUDPEnabled() bool { return c.connectedUDP.enabled }

// withReusePort returns lc with SO_REUSEPORT added to its Control hook, so
// that connected sockets can later bind to the same port. A failure to set
// the option is handled by onErr: an error fails the bind, nil continues
// without the option.
func withReusePort(lc *net.ListenConfig, onErr func(error) error) *net.ListenConfig {
	inner := lc.Control
	out := *lc
	out.Control = func(network, address string, rc syscall.RawConn) error {
		if err := sockopts.SetReusePort(rc); err != nil {
			if err := onErr(err); err != nil {
				return err
			}
		}
		if inner != nil {
			return inner(network, address, rc)
		}
		return nil
	}
	return &out
}

// sharedSocketListenConfig returns the ListenConfig for a shared socket when
// connected sockets are enabled: SO_REUSEPORT set so that they can share its
// port. If the kernel refuses the option, the shared socket is bound without
// it, as it would be with the knob off, and the feature is disabled: the
// knob must never cost UDP connectivity.
func (c *Conn) sharedSocketListenConfig(lc *net.ListenConfig) *net.ListenConfig {
	return withReusePort(lc, func(err error) error {
		c.disableConnectedUDP(fmt.Sprintf("SO_REUSEPORT: %v", err))
		return nil
	})
}

// disableConnectedUDP turns promotion off for good for this Conn, and says
// why once. Existing connected sockets are left to close through the usual
// paths.
func (c *Conn) disableConnectedUDP(why string) {
	s := &c.connectedUDP
	s.mu.Lock()
	already := s.unsupported
	s.unsupported = true
	s.mu.Unlock()
	if !already {
		c.logf("magicsock: %v: %s", errConnectedUDPUnsupported, why)
	}
}

// openConnectedUDP reserves the receive slots for connected sockets and
// returns their receive funcs, for connBind.Open to hand to wireguard-go.
func (c *Conn) openConnectedUDP() []conn.ReceiveFunc {
	if !c.connectedUDPEnabled() {
		return nil
	}
	s := &c.connectedUDP
	s.mu.Lock()
	defer s.mu.Unlock()
	s.open = true
	s.gen++
	s.free = s.free[:0]
	fns := make([]conn.ReceiveFunc, 0, s.maxSockets)
	for range s.maxSockets {
		slot := &connectedUDPSlot{ch: make(chan *connectedUDPConn, 1), gen: s.gen}
		s.free = append(s.free, slot)
		fns = append(fns, c.mkConnectedUDPReceiveFunc(slot))
	}
	return fns
}

// closeConnectedUDPSockets closes every connected socket. The receive slots
// stay reserved; peers are promoted again as they stay busy.
func (c *Conn) closeConnectedUDPSockets(why string) {
	s := &c.connectedUDP
	s.mu.Lock()
	active := s.active
	s.active = nil
	s.mu.Unlock()
	for cu, de := range active {
		de.dropConnectedUDP(cu, why)
	}
}

// closeConnectedUDPBind closes every connected socket and releases the
// receive slots so that their wireguard-go goroutines exit. The next Open
// reserves new slots.
func (c *Conn) closeConnectedUDPBind(why string) {
	// Mark the bind closed in the same critical section that takes the
	// sockets and slots, so that a dial completing now is refused rather
	// than registered into a bind that is going away.
	s := &c.connectedUDP
	s.mu.Lock()
	active := s.active
	s.active = nil
	var slots []*connectedUDPSlot
	if s.open {
		s.open = false
		slots = s.free
		s.free = nil
	}
	s.mu.Unlock()
	for cu, de := range active {
		de.dropConnectedUDP(cu, why)
	}
	// A slot held by a dialer at this moment is closed by that dialer.
	for _, slot := range slots {
		close(slot.ch)
	}
}

// takeConnectedUDPSlot removes and returns a free receive slot. It returns
// net.ErrClosed if the bind is closed and errConnectedUDPNoSlot if every slot
// is in use.
func (c *Conn) takeConnectedUDPSlot() (*connectedUDPSlot, error) {
	s := &c.connectedUDP
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open {
		return nil, net.ErrClosed
	}
	if len(s.free) == 0 {
		return nil, errConnectedUDPNoSlot
	}
	slot := s.free[len(s.free)-1]
	s.free = s.free[:len(s.free)-1]
	return slot, nil
}

// releaseConnectedUDPSlot returns slot to the free list. It reports false if
// the bind that slot belongs to has closed, in which case the slot's receive
// func must return.
func (c *Conn) releaseConnectedUDPSlot(slot *connectedUDPSlot) bool {
	s := &c.connectedUDP
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open || slot.gen != s.gen {
		return false
	}
	s.free = append(s.free, slot)
	s.noSlotNoted = false // the next time the cap is hit is a new episode
	return true
}

// giveBackConnectedUDPSlot is a dialer returning a slot it never handed a
// socket to: back to the free list, or, if the bind closed meanwhile and
// nothing else will, closed so that its receive func returns.
func (c *Conn) giveBackConnectedUDPSlot(slot *connectedUDPSlot) {
	if !c.releaseConnectedUDPSlot(slot) {
		close(slot.ch)
	}
}

// unregisterConnectedUDP forgets cu and returns the endpoint it belonged to,
// or nil if it was already forgotten.
func (c *Conn) unregisterConnectedUDP(cu *connectedUDPConn) *endpoint {
	s := &c.connectedUDP
	s.mu.Lock()
	defer s.mu.Unlock()
	de, ok := s.active[cu]
	if ok {
		delete(s.active, cu)
	}
	return de
}

// connectedUDPRegistered reports whether cu is still registered to de, that
// is, no close or rebind has dropped it since it was dialed.
func (c *Conn) connectedUDPRegistered(cu *connectedUDPConn, de *endpoint) bool {
	s := &c.connectedUDP
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active[cu] == de
}

// sharedPort returns the local port of the shared socket for network, or 0
// if none is bound.
func (c *Conn) sharedPort(network string) uint16 {
	if network == "udp6" {
		return c.pconn6.Port()
	}
	return c.pconn4.Port()
}

// dialConnectedUDP opens a socket connected to remote on the local port of
// the unconnected socket of the same family, registers it to de, and assigns
// it to a receive slot. It returns errConnectedUDPNoSlot when the cap is
// reached, net.ErrClosed when the bind closed meanwhile, and
// errConnectedUDPPortChanged when a rebind moved the shared socket meanwhile.
func (c *Conn) dialConnectedUDP(de *endpoint, remote netip.AddrPort) (*connectedUDPConn, error) {
	slot, err := c.takeConnectedUDPSlot()
	if err != nil {
		if errors.Is(err, errConnectedUDPNoSlot) {
			c.noteConnectedUDPNoSlot(de, remote)
		}
		return nil, err
	}
	cu, err := c.dialConnectedUDPSocket(remote)
	if err != nil {
		c.giveBackConnectedUDPSlot(slot)
		return nil, err
	}
	s := &c.connectedUDP
	s.mu.Lock()
	switch {
	case !s.open || slot.gen != s.gen:
		err = net.ErrClosed
	case s.fallback:
		err = errConnectedUDPFallback
	case cu.localPort != c.sharedPort(cu.network):
		// This socket is on the old port and must not be used.
		err = errConnectedUDPPortChanged
	}
	if err != nil {
		s.mu.Unlock()
		cu.close()
		c.giveBackConnectedUDPSlot(slot)
		return nil, err
	}
	mak.Set(&s.active, cu, de)
	s.mu.Unlock()
	slot.ch <- cu
	return cu, nil
}

// noteConnectedUDPNoSlot counts a peer that qualified for a connected socket
// while all slots were in use, and says so once per episode.
func (c *Conn) noteConnectedUDPNoSlot(de *endpoint, remote netip.AddrPort) {
	metricConnectedUDPNoSlot.Add(1)
	s := &c.connectedUDP
	s.mu.Lock()
	noted := s.noSlotNoted
	s.noSlotNoted = true
	s.mu.Unlock()
	if !noted {
		c.logf("magicsock: all %d connected UDP sockets in use; %v (%v) stays on the shared socket", s.maxSockets, de.publicKey.ShortString(), remote)
	}
}

// dialConnectedUDPSocket opens and connects the socket for remote and gives
// it the shared socket's options.
func (c *Conn) dialConnectedUDPSocket(remote netip.AddrPort) (*connectedUDPConn, error) {
	network, label := "udp4", sockstats.LabelMagicsockConnUDP4
	if remote.Addr().Is6() {
		network, label = "udp6", sockstats.LabelMagicsockConnUDP6
	}
	port := c.sharedPort(network)
	if port == 0 {
		return nil, fmt.Errorf("no %v socket bound", network)
	}
	ctx := sockstats.WithSockStats(context.Background(), label, c.logf)
	d := &net.Dialer{LocalAddr: &net.UDPAddr{Port: int(port)}}
	// The same socket options as the shared socket (netns bypass mark, bind
	// to interface), plus SO_REUSEPORT to share its port.
	d.Control = withReusePort(netns.Listener(c.logf, c.netMon), func(err error) error { return err }).Control
	nc, err := d.DialContext(ctx, network, remote.String())
	if err != nil {
		return nil, err
	}
	pconn, ok := nc.(nettype.PacketConn)
	if !ok {
		nc.Close()
		return nil, fmt.Errorf("unexpected %T from %v dial", nc, network)
	}
	trySetUDPSocketOptions(pconn, c.logf)
	if c.peerMTUEnabled.Load() {
		// A later PMTUD change resets every endpoint, which closes this
		// socket, so the setting at dial time is the one that counts.
		if err := setDontFragmentOn(pconn, network, true); err != nil {
			c.logf("magicsock: connected UDP socket to %v: set DF: %v", remote, err)
		}
	}
	bc, ok := batching.TryUpgradeToConn(pconn, network, "magicsock_connected_udp_rxq_overflows", c.controlKnobs).(batching.Conn)
	if !ok {
		// Only on kernels too old for sendmmsg. Not worth a non-batching
		// path: give up on the feature for this Conn.
		pconn.Close()
		c.disableConnectedUDP("batched i/o unavailable")
		return nil, errConnectedUDPUnsupported
	}
	metricNumConnectedUDPSockets.Add(1)
	metricConnectedUDPOpened.Add(1)
	return &connectedUDPConn{pconn: bc, remote: remote, network: network, localPort: port, openedAt: mono.Now()}, nil
}

// connectedUDPUnsupported reports whether the feature was disabled for this
// Conn by disableConnectedUDP.
func (c *Conn) connectedUDPUnsupported() bool {
	s := &c.connectedUDP
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unsupported
}

// mkConnectedUDPReceiveFunc returns the receive func for slot. It blocks
// until a connected socket is assigned to the slot, reads from it until the
// socket is closed, and then waits for the next one. Received packets go
// through the same processing as those from the shared sockets.
//
// Unlike the shared sockets' receive funcs, these register no
// health.ReceiveFuncStats: a slot is parked by design and would look stuck.
func (c *Conn) mkConnectedUDPReceiveFunc(slot *connectedUDPSlot) conn.ReceiveFunc {
	var epCache epAddrEndpointCache
	var batchingPackets []batching.ReceivedPacket
	var cur *connectedUDPConn

	return func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
		if len(batchingPackets) != len(packets) {
			batchingPackets = make([]batching.ReceivedPacket, len(packets))
		}
		for {
			if cur == nil {
				cu, ok := <-slot.ch
				if !ok {
					return 0, net.ErrClosed
				}
				cur = cu
			}
			numMsgs, err := cur.pconn.ReadBatch(slab, batchingPackets)
			if err != nil {
				if neterror.PacketWasTruncated(err) || isICMPErr(err) {
					// An ICMP error is reported once and the socket is fine;
					// the shared socket never hears of them at all.
					continue
				}
				if !cur.closed.Load() {
					c.dropConnectedUDPConn(cur, fmt.Sprintf("read error: %v", err))
				}
				cur = nil
				if !c.releaseConnectedUDPSlot(slot) {
					return 0, net.ErrClosed
				}
				continue
			}
			m := c.inboundMetricsFor(cur.network == "udp6")
			if c.processReceivedBatch(slab, batchingPackets[:numMsgs], packets, &epCache, m) {
				return numMsgs, nil
			}
		}
	}
}

// dropConnectedUDPConn closes cu and detaches it from its endpoint, if it is
// still attached. It is for callers that have a socket but no endpoint, such
// as the receive func.
func (c *Conn) dropConnectedUDPConn(cu *connectedUDPConn, why string) {
	if de := c.unregisterConnectedUDP(cu); de != nil {
		de.dropConnectedUDP(cu, why)
		return
	}
	cu.close()
}

// sendUDPBatchConnected sends buffs to de over its connected socket cu. On an
// ICMP error for the peer, which the shared socket would not have heard of,
// the batch goes over the shared socket and cu is kept. On any other error cu
// is closed and the batch goes over the shared socket, so no batch is lost to
// the switch.
func (c *Conn) sendUDPBatchConnected(de *endpoint, cu *connectedUDPConn, addr epAddr, buffs [][]byte, offset int) (sent bool, err error) {
	err = c.writeWireGuardBatch(cu.pconn, buffs, addr, offset)
	if errGSO, isGSO := errors.AsType[neterror.ErrUDPGSODisabled](err); isGSO {
		c.logf("magicsock: %s", errGSO.Error())
		err = errGSO.RetryErr
	}
	if err == nil {
		return true, nil
	}
	if !isICMPErr(err) {
		de.dropConnectedUDP(cu, fmt.Sprintf("send error: %v", err))
	}
	return c.sendUDPBatch(addr, buffs, offset)
}

// writeWireGuardBatch is RebindingUDPConn.WriteWireGuardBatchTo for a socket
// that is not rebound.
func (c *Conn) writeWireGuardBatch(b batching.Conn, buffs [][]byte, addr epAddr, offset int) error {
	if offset != packet.GeneveFixedHeaderLength {
		return fmt.Errorf("writeWireGuardBatch: [unexpected] offset (%d) != Geneve header length (%d)", offset, packet.GeneveFixedHeaderLength)
	}
	gh := packet.GeneveHeader{
		Protocol: packet.GeneveProtocolWireGuard,
		VNI:      addr.vni,
	}
	return b.WriteBatchTo(buffs, addr.ap, gh, offset)
}

// connectedSocketForLocked returns de's connected socket if it is the one to
// use for sending to addr: a direct path to the address the socket is
// connected to. A peer relay path (VNI set) shares the relay's 5-tuple with
// other peers and never uses it.
//
// de.mu must be held.
func (de *endpoint) connectedSocketForLocked(addr epAddr) *connectedUDPConn {
	cu := de.connectedSocket
	if cu == nil || addr.vni.IsSet() || cu.remote != addr.ap {
		return nil
	}
	return cu
}

// noteConnectedUDPTx records bytes sent to de on a direct path, over either
// socket, which is what decides at the next heartbeat whether de gets a
// connected socket or gives its connected socket up.
func (de *endpoint) noteConnectedUDPTx(n int) {
	if de.c.connectedUDPEnabled() {
		de.connectedUDPTxBytes.Add(int64(n))
	}
}

// checkConnectedUDPInboundLocked closes de's connected socket if nothing has
// arrived from the peer for connectedUDPNoInboundAfter while the session was
// active, so that a receive slot that stopped reading costs the peer a few
// seconds and not its connectivity. See connectedUDPNoInboundAfter.
//
// de.mu must be held.
func (de *endpoint) checkConnectedUDPInboundLocked(now mono.Time) {
	cu := de.connectedSocket
	if cu == nil || now.Sub(cu.openedAt) < connectedUDPNoInboundAfter {
		return
	}
	if idle := now.Sub(de.lastRecvUDPAny.LoadAtomic()); idle >= connectedUDPNoInboundAfter {
		metricConnectedUDPNoInbound.Add(1)
		de.dropConnectedUDPLocked(fmt.Sprintf("nothing received for %v", idle.Round(time.Second)))
	}
}

// updateConnectedUDPLocked runs every heartbeat. It opens a connected socket
// for de if de has been sent enough over the last heartbeat interval and is
// on a trusted direct path, and closes de's connected socket once de has been
// sent little for a while; see connectedUDPDemoteBytes. The byte count is
// reset every heartbeat, whether or not it is looked at. The dial runs in its
// own goroutine, since de.mu is held.
//
// An endpoint with heartbeats disabled never gets a connected socket.
//
// de.mu must be held.
func (de *endpoint) updateConnectedUDPLocked(now mono.Time) {
	if !de.c.connectedUDPEnabled() {
		return
	}
	txBytes := de.connectedUDPTxBytes.Swap(0)
	if de.connectedSocket != nil {
		de.maybeDemoteConnectedUDPLocked(now, txBytes)
		return
	}
	if de.connectedUDPDialing || txBytes < connectedUDPPromoteBytes {
		de.c.connectedUDPFallbackTick(now)
		return
	}
	addr := de.bestAddr.epAddr
	if !addr.isDirect() || now.After(de.trustBestAddrUntil) || de.c.connectedUDPUnsupported() {
		return
	}
	if !de.c.connectedUDPAdmit(de, now) {
		return
	}
	de.connectedUDPDialing = true
	go de.promoteConnectedUDP(addr.ap)
}

// connectedUDPAdmit is called every heartbeat for a peer without a connected
// socket that qualifies for one on a trusted direct path. It reports whether
// the peer may be promoted now. If every slot is in use, the peer would lose
// out to the peers with one on a full link, so the Conn falls back: every
// connected socket is closed and no peer is promoted until
// connectedUDPFallbackTick says the contention is over.
func (c *Conn) connectedUDPAdmit(de *endpoint, now mono.Time) bool {
	s := &c.connectedUDP
	s.mu.Lock()
	if s.fallback {
		mak.Set(&s.qualified, de, now)
		s.mu.Unlock()
		// This heartbeat may be the one that ends the fallback.
		return c.connectedUDPFallbackTick(now)
	}
	if len(s.free) > 0 || !s.open {
		s.mu.Unlock()
		return true
	}
	s.fallback = true
	s.contendedAt = now
	clear(s.qualified)
	s.mu.Unlock()
	metricConnectedUDPFallback.Add(1)
	c.logf("magicsock: all %d connected UDP sockets in use and %v is busy without one; all peers back on the shared socket until no more than %d are busy for %v",
		s.maxSockets, de.publicKey.ShortString(), s.maxSockets, connectedUDPFallbackHold)
	// The caller holds de.mu, and closing takes the other peers' mu.
	go c.closeConnectedUDPSockets("too many busy peers")
	return false
}

// connectedUDPFallbackTick ends the fallback once no more peers than there
// are slots have qualified for promotion for connectedUDPFallbackHold, and
// reports whether it ended it. It runs from the heartbeat of every peer
// without a connected socket.
func (c *Conn) connectedUDPFallbackTick(now mono.Time) (ended bool) {
	s := &c.connectedUDP
	s.mu.Lock()
	if !s.fallback {
		s.mu.Unlock()
		return false
	}
	busy := 0
	for de, t := range s.qualified {
		if now.Sub(t) > 2*heartbeatInterval {
			delete(s.qualified, de)
			continue
		}
		busy++
	}
	switch {
	case busy > s.maxSockets:
		s.contendedAt = now
	case now.Sub(s.contendedAt) >= connectedUDPFallbackHold:
		s.fallback = false
		clear(s.qualified)
		ended = true
	}
	s.mu.Unlock()
	if ended {
		c.logf("magicsock: no more than %d peers busy for %v; connected UDP sockets back on", s.maxSockets, connectedUDPFallbackHold)
	}
	return ended
}

// maybeDemoteConnectedUDPLocked closes de's connected socket if de has been
// sent less than connectedUDPDemoteBytes in every heartbeat interval since at
// least connectedUDPDemoteAfter ago. txBytes is what it was sent over the
// interval that just ended. The first quiet interval is noticed at its end,
// so a socket goes after a little more than connectedUDPDemoteAfter of
// quiet, never less.
//
// de.mu must be held.
func (de *endpoint) maybeDemoteConnectedUDPLocked(now mono.Time, txBytes int64) {
	switch {
	case txBytes >= connectedUDPDemoteBytes:
		de.connectedUDPQuietSince = 0
	case de.connectedUDPQuietSince.IsZero():
		de.connectedUDPQuietSince = now
	case now.Sub(de.connectedUDPQuietSince) >= connectedUDPDemoteAfter:
		metricConnectedUDPDemoted.Add(1)
		de.dropConnectedUDPLocked(fmt.Sprintf("sent less than %.1f Mbit/s for %v", float64(connectedUDPDemoteRate)/1e6, connectedUDPDemoteAfter))
	}
}

// promoteConnectedUDP dials a connected socket to remote and installs it on
// de.
func (de *endpoint) promoteConnectedUDP(remote netip.AddrPort) {
	cu, err := de.c.dialConnectedUDP(de, remote)
	de.installConnectedUDP(remote, cu, err)
}

// installConnectedUDP finishes a promotion: it makes cu, the result of the
// dial to remote, de's connected socket, unless the dial failed, or de's path
// changed, or a rebind or bind close already closed cu, since the dial began.
func (de *endpoint) installConnectedUDP(remote netip.AddrPort, cu *connectedUDPConn, err error) {
	de.mu.Lock()
	defer de.mu.Unlock()
	de.connectedUDPDialing = false
	if err != nil {
		switch {
		case errors.Is(err, errConnectedUDPNoSlot), errors.Is(err, net.ErrClosed),
			errors.Is(err, errConnectedUDPPortChanged), errors.Is(err, errConnectedUDPUnsupported),
			errors.Is(err, errConnectedUDPFallback):
			// Expected; counted or logged where they happen.
		default:
			metricConnectedUDPDialError.Add(1)
			de.c.logf("magicsock: connected UDP socket to %v for %v: %v", remote, de.publicKey.ShortString(), err)
		}
		return
	}
	// cu is not installed yet, so a rejected cu is unregistered and closed
	// right here; dropConnectedUDP would take de.mu, which is held.
	var why string
	switch {
	case !de.c.connectedUDPRegistered(cu, de):
		why = "closed while dialing" // by a rebind or bind close
	case de.connectedSocket != nil || de.expired || de.bestAddr.epAddr != (epAddr{ap: remote}):
		why = "path changed while dialing"
		de.c.unregisterConnectedUDP(cu)
	}
	if why != "" {
		cu.close()
		de.c.logf("[v1] magicsock: connected UDP socket to %v for %v closed: %s", remote, de.publicKey.ShortString(), why)
		return
	}
	de.connectedSocket = cu
	de.c.logf("magicsock: connected UDP socket to %v for %v opened", remote, de.publicKey.ShortString())
}

// dropConnectedUDP closes cu and detaches it from de, if it is still
// attached. It takes de.mu.
func (de *endpoint) dropConnectedUDP(cu *connectedUDPConn, why string) {
	de.mu.Lock()
	if de.connectedSocket == cu {
		de.dropConnectedUDPLocked(why)
		de.mu.Unlock()
		return
	}
	de.mu.Unlock()
	// Dialed for de but never installed, or already replaced.
	de.c.unregisterConnectedUDP(cu)
	cu.close()
}

// dropConnectedUDPLocked closes de's connected socket, if it has one.
//
// de.mu must be held.
func (de *endpoint) dropConnectedUDPLocked(why string) {
	cu := de.connectedSocket
	if cu == nil {
		return
	}
	de.connectedSocket = nil
	de.connectedUDPQuietSince = 0
	de.c.unregisterConnectedUDP(cu)
	cu.close()
	de.c.logf("magicsock: connected UDP socket to %v for %v closed: %s", cu.remote, de.publicKey.ShortString(), why)
}
