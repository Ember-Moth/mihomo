package outbound

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	obfs "github.com/metacubex/mihomo/transport/simple-obfs"
	legacy "github.com/metacubex/mihomo/transport/snell"
	"github.com/stretchr/testify/require"
)

func TestSnellLegacyV4Server(t *testing.T) {
	for _, mode := range []string{"", "http", "tls"} {
		t.Run("obfs="+mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()
			payload := bytes.Repeat([]byte("legacy-v4"), 3000)
			result := make(chan error, 1)
			go func() {
				result <- serveLegacySnell(listener, mode, payload)
			}()
			address := listener.Addr().(*net.TCPAddr)
			proxy, err := NewSnell(SnellOption{
				Name: "snell", Server: address.IP.String(), Port: address.Port,
				Psk: "test-snell-password", Version: 4, ObfsOpts: map[string]any{"mode": mode},
			})
			require.NoError(t, err)
			defer proxy.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "example.org", DstPort: 443})
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			_, err = conn.Write(payload)
			require.NoError(t, err)
			response := make([]byte, len(payload))
			_, err = io.ReadFull(conn, response)
			require.NoError(t, err)
			require.Equal(t, payload, response)
			require.NoError(t, <-result)
		})
	}
}

// Retain an independent v4 codec on the other side of the migration boundary.
func serveLegacySnell(listener net.Listener, mode string, payload []byte) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	switch mode {
	case "http":
		conn = obfs.NewHTTPObfsServer(conn)
	case "tls":
		conn = obfs.NewTLSObfsServer(conn)
	}
	stream := legacy.ServerStreamConn(conn, []byte("test-snell-password"), legacy.Version4)
	var prefix [4]byte
	if _, err := io.ReadFull(stream, prefix[:]); err != nil {
		return err
	}
	if prefix[0] != legacy.Version || prefix[1] != legacy.CommandConnectV2 || prefix[2] != 0 {
		return fmt.Errorf("unexpected request header: %x", prefix)
	}
	address := make([]byte, int(prefix[3])+2)
	if _, err := io.ReadFull(stream, address); err != nil {
		return err
	}
	if string(address[:len(address)-2]) != "example.org" || binary.BigEndian.Uint16(address[len(address)-2:]) != 443 {
		return fmt.Errorf("unexpected destination: %x", address)
	}
	data := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, data); err != nil {
		return err
	}
	if !bytes.Equal(data, payload) {
		return fmt.Errorf("request payload changed")
	}
	_, err = stream.Write(append([]byte{legacy.CommandTunnel}, data...))
	return err
}
