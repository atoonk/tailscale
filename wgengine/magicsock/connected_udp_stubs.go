// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || android

package magicsock

import "tailscale.com/types/nettype"

// Connected UDP sockets are only opened on Linux; these keep the shared code
// compiling elsewhere. See connected_udp.go.

const connectedUDPSupported = false

func enableConnectedUDP() bool { return false }

func connectedUDPMaxSockets() int { return 0 }

func isICMPErr(err error) bool { return false }

func setDontFragmentOn(pconn nettype.PacketConn, network string, enable bool) error {
	return errUnsupportedConnType
}
