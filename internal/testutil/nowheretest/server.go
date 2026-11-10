// Package nowheretest provides an opt-in Rust reference server for protocol tests.
package nowheretest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/pkg/nowhere"
	"github.com/metacubex/tls"
)

const SharedKey = "0123456789abcdef0123456789abcdef"

func StartPortal(t *testing.T, morph bool) (string, string, *tls.Config) {
	t.Helper()
	binary := os.Getenv("NOWHERE_TEST_BINARY")
	if binary == "" {
		t.Skip("set NOWHERE_TEST_BINARY to Nowhere v3.3.0")
	}
	version, err := exec.Command(binary, "--version").CombinedOutput()
	if err != nil || !bytes.Contains(version, []byte("v3.3.0")) {
		t.Fatalf("Nowhere version: %s %v", version, err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	query := url.Values{"tls": {"2"}, "crt": {certPath}, "key": {keyPath}, "morph": {"0"}}
	if morph {
		query.Set("morph", "1")
	}
	logPath := filepath.Join(dir, "portal.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "portal://"+SharedKey+"@"+address+"?"+query.Encode())
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Portal did not exit")
		}
		log.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logPath)
			t.Log(string(b))
		}
	})
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("Portal did not start")
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	digest := sha256.Sum256(der)
	return address, hex.EncodeToString(digest[:]), &tls.Config{ServerName: "localhost", RootCAs: roots}
}

func EchoTargets(t *testing.T) (nowhere.Target, nowhere.Target) {
	return EchoTargetsIP(t, "127.0.0.1")
}

func EchoTargetsIP(t *testing.T, host string) (nowhere.Target, nowhere.Target) {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close(); packet.Close() })
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = c.SetDeadline(time.Now().Add(10 * time.Second)); _, _ = io.Copy(c, c) }()
		}
	}()
	go func() {
		b := make([]byte, 65535)
		for {
			n, addr, err := packet.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = packet.WriteTo(b[:n], addr)
		}
	}()
	parse := func(addr net.Addr) nowhere.Target {
		h, p, _ := net.SplitHostPort(addr.String())
		port, _ := strconv.Atoi(p)
		return nowhere.Target{Host: h, Port: uint16(port)}
	}
	return parse(listener.Addr()), parse(packet.LocalAddr())
}
