// Package nowhere implements the NW3 Vector client, including TLS and QUIC
// carriers, TCP and UDP flows, and the Morph Prelude extension in Nowhere 3.3.0.
//
// Wire contract: https://github.com/NodePassProject/Nowhere-Protocol/blob/main/PROTOCOL.md
// Prelude: https://github.com/NodePassProject/Nowhere/blob/v3.3.0/docs/prelude.md
// The caller supplies transport dialing and certificate trust. This package has
// no dependency on mihomo's configuration, routing, or adapter packages.
package nowhere
