// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"bytes"
	"testing"

	"tailscale.com/types/logger"
)

func TestConnectorTokenSecretInit(t *testing.T) {
	c := newConn25(logger.Discard)

	secret := c.connector.tokenSecret
	if got := len(secret); got != tokenSecretLen {
		t.Fatalf("token secret length = %d, want %d", got, tokenSecretLen)
	}

	if bytes.Equal(secret, make([]byte, tokenSecretLen)) {
		t.Fatal("token secret is all zero bytes, expected random bytes")
	}
}

func TestConnectorTokenSecretRandomAcrossInstances(t *testing.T) {
	a := newConn25(logger.Discard)
	b := newConn25(logger.Discard)

	if bytes.Equal(a.connector.tokenSecret, b.connector.tokenSecret) {
		t.Fatal("two connectors minted identical token secrets, expected distinct random secrets")
	}
}

func TestConnectorResetRotatesTokenSecret(t *testing.T) {
	c := newConn25(logger.Discard)

	before := bytes.Clone(c.connector.tokenSecret)
	c.connector.reset()
	after := c.connector.tokenSecret

	if len(after) != tokenSecretLen {
		t.Fatalf("token secret length after reset = %d, want %d", len(after), tokenSecretLen)
	}
	if bytes.Equal(before, after) {
		t.Fatal("token secret unchanged after reset, expected rotation")
	}
}
