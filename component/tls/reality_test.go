package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/ntp"
	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func TestRealityClientHello(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		name := "hybrid"
		if !enabled {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
			require.NoError(t, err)
			shortID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
			config := &RealityConfig{PublicKey: serverKey.PublicKey(), ShortID: shortID, SupportX25519MLKEM768: enabled}
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, peer.SetDeadline(time.Now().Add(5*time.Second)))
			fingerprint, ok := GetFingerprint("chrome")
			require.True(t, ok)
			before := ntp.Now().Unix()
			done := make(chan error, 1)
			go func() {
				conn, err := GetRealityConn(ctx, client, fingerprint, "example.org", config)
				if conn != nil {
					_ = conn.Close()
				}
				done <- err
			}()

			// Capture the actual TLS records, including a fragmented ClientHello.
			var raw []byte
			for len(raw) < 4 || len(raw) < 4+(int(raw[1])<<16)+(int(raw[2])<<8)+int(raw[3]) {
				var header [5]byte
				_, err := io.ReadFull(peer, header[:])
				require.NoError(t, err)
				require.Equal(t, byte(22), header[0], "expected a handshake record")
				body := make([]byte, int(binary.BigEndian.Uint16(header[3:])))
				_, err = io.ReadFull(peer, body)
				require.NoError(t, err)
				raw = append(raw, body...)
			}
			require.NoError(t, peer.Close())
			select {
			case err := <-done:
				require.Error(t, err, "the capture peer deliberately closes without replying")
			case <-ctx.Done():
				t.Fatal("client did not stop after the peer closed")
			}
			hello := utls.UnmarshalClientHello(raw)
			require.NotNil(t, hello)
			require.Equal(t, "example.org", hello.ServerName)
			require.Len(t, hello.SessionId, 32)
			hybridIndex, x25519Index := -1, -1
			var authPublicKey []byte
			for i, share := range hello.KeyShares {
				switch share.Group {
				case utls.X25519MLKEM768:
					hybridIndex = i
					require.Len(t, share.Data, 1184+32)
					if authPublicKey == nil {
						authPublicKey = share.Data[1184:]
					}
				case utls.X25519:
					x25519Index = i
					authPublicKey = share.Data
				}
			}
			if enabled {
				require.GreaterOrEqual(t, hybridIndex, 0)
				if x25519Index >= 0 {
					require.Less(t, hybridIndex, x25519Index, "new REALITY servers require this order")
				}
			} else {
				require.Equal(t, -1, hybridIndex)
				require.NotContains(t, hello.SupportedCurves, utls.X25519MLKEM768)
			}

			// Verify the encrypted authentication fields as a REALITY server does.
			peerKey, err := ecdh.X25519().NewPublicKey(authPublicKey)
			require.NoError(t, err)
			shared, err := serverKey.ECDH(peerKey)
			require.NoError(t, err)
			authKey := make([]byte, 32)
			_, err = io.ReadFull(hkdf.New(sha256.New, shared, hello.Random[:20], []byte("REALITY")), authKey)
			require.NoError(t, err)
			block, err := aes.NewCipher(authKey)
			require.NoError(t, err)
			aead, err := cipher.NewGCM(block)
			require.NoError(t, err)
			aad := bytes.Clone(raw)
			clear(aad[39:71]) // ClientHello session ID is zeroed in the authenticated data.
			plain, err := aead.Open(nil, hello.Random[20:], hello.SessionId, aad)
			require.NoError(t, err)
			require.Len(t, plain, 16)
			require.Equal(t, []byte{26, 10, 29, 0}, plain[:4])
			require.Equal(t, shortID[:], plain[8:])
			stamp := int64(binary.BigEndian.Uint32(plain[4:8]))
			require.GreaterOrEqual(t, stamp, before)
			require.LessOrEqual(t, stamp, ntp.Now().Unix())
		})
	}
}
