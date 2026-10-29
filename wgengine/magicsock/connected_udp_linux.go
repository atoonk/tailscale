// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package magicsock

import (
	"errors"
	"syscall"

	"tailscale.com/envknob"
	"tailscale.com/types/nettype"
)

// connectedUDPSupported is whether this platform opens connected UDP sockets
// for busy peers. See connected_udp.go.
const connectedUDPSupported = true

// enableConnectedUDP is the opt-in for connected UDP sockets.
var enableConnectedUDP = envknob.RegisterBool("TS_ENABLE_CONNECTED_UDP")

// connectedUDPMaxSockets, if set, overrides connectedUDPDefaultMaxSockets.
var connectedUDPMaxSockets = envknob.RegisterInt("TS_CONNECTED_UDP_MAX_SOCKETS")

// isICMPErr reports whether err is a socket error the kernel raised from an
// ICMP message about the peer of a connected UDP socket. The errnos are those
// of icmp_err_convert and icmpv6_err_convert plus the ones __udp4_lib_err and
// __udp6_lib_err pick for parameter problems and expired TTLs. Such an error
// is reported on one read or write and then cleared; it says nothing about
// the socket.
func isICMPErr(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ENOPROTOOPT,
		syscall.ECONNREFUSED, syscall.EMSGSIZE, syscall.EOPNOTSUPP,
		syscall.EHOSTDOWN, syscall.ENONET, syscall.EPROTO, syscall.EACCES:
		return true
	}
	return false
}

// setDontFragmentOn sets the DF bit on a socket other than the Conn's shared
// ones, which setDontFragment covers.
func setDontFragmentOn(pconn nettype.PacketConn, network string, enable bool) error {
	optArg := syscall.IP_PMTUDISC_DO
	if !enable {
		optArg = syscall.IP_PMTUDISC_DONT
	}
	sc, ok := pconn.(syscall.Conn)
	if !ok {
		return errUnsupportedConnType
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), getIPProto(network), getDontFragOpt(network), optArg)
	}); err != nil {
		return err
	}
	return serr
}
