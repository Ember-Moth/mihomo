package nowhere

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"
	"time"
)

func TestNW3Vectors(t *testing.T) {
	key := vectorKey("0123456789abcdef0123456789abcdef")
	if hex.EncodeToString(key[:]) != "1b5bddc7018f44cece1942211f94e5302c86827fda2e29bb4676ab667e5c95fb" {
		t.Fatal("vector KDF")
	}
	exporter := make([]byte, 32)
	for i := range exporter {
		exporter[i] = byte(i)
	}
	for i, expected := range []string{"1a26d8eb72ead8a223b54fd1f04f8e32", "7cbb323bd019bb51370c92a50a36a08f"} {
		frame := authFrame(key, byte(i+1), exporter)
		if hex.EncodeToString(frame[:]) != expected {
			t.Fatal("auth vector", i)
		}
	}
	request, err := flowRequest(false, Target{"127.0.0.1", 443})
	if err != nil || hex.EncodeToString(request) != "00017f00000101bb" {
		t.Fatal(request, err)
	}
	request, err = flowRequest(false, Target{"2001:db8::1", 443})
	if err != nil || hex.EncodeToString(request) != "000420010db800000000000000000000000101bb" {
		t.Fatal("IPv6 target", request, err)
	}
	request, err = flowRequest(true, Target{"example.org", 53})
	if err != nil || hex.EncodeToString(request) != "01030b6578616d706c652e6f72670035" {
		t.Fatal("domain target", request, err)
	}
	data, _ := EncodeUDPData(2, []byte("abc"))
	if hex.EncodeToString(data) != "00000002616263" {
		t.Fatal(data)
	}
	closeFrame, _ := EncodeUDPClose(2)
	if hex.EncodeToString(closeFrame[:]) != "80000002" {
		t.Fatal(closeFrame)
	}
	for _, raw := range []uint64{2, 3, 4294967292} {
		if _, err := udpFlowID(raw); err == nil {
			t.Fatal("invalid stream accepted", raw)
		}
	}
	if id, err := udpFlowID(4294967288); err != nil || id != maxFlowID {
		t.Fatal(id, err)
	}
	for _, host := range []string{"", "example.com.", "-bad.test", "a..b", "bad\x00.test", "fe80::1%en0"} {
		if _, err := flowRequest(false, Target{host, 443}); err == nil {
			t.Fatal("invalid target", host)
		}
	}
	request, err = flowRequest(false, Target{"bücher.example", 443})
	if err != nil || !bytes.Contains(request, []byte("xn--bcher-kva.example")) {
		t.Fatal("IDNA encoding", err)
	}
}

func TestDatagramReassembly(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, 65535)
	frames, err := EncodeUDPFragments(2, 1, payload, 1200)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := NewDatagramReassembler(DefaultReassemblyConfig())
	now := time.Now()
	for i := len(frames) - 1; i >= 0; i-- {
		frame, err := DecodeUDPFrame(frames[i])
		if err != nil {
			t.Fatal(err)
		}
		got, complete, err := r.Push(frame, now)
		if err != nil {
			t.Fatal(err)
		}
		if complete != (i == 0) {
			t.Fatal("completion boundary")
		}
		if complete && !bytes.Equal(got, payload) {
			t.Fatal("corrupt payload")
		}
	}
	if r.ReservedBytes() != 0 || r.SlotCount() != 0 {
		t.Fatal("reservation leak")
	}
	f, _ := DecodeUDPFrame(frames[0])
	_, _, _ = r.Push(f, now)
	f.Payload = bytes.Repeat([]byte{0xff}, len(f.Payload))
	if _, _, err := r.Push(f, now); err != ErrReassemblyConflict {
		t.Fatal(err)
	}
	if r.ReservedBytes() != 0 {
		t.Fatal("conflict leak")
	}
	_, _, _ = r.Push(f, now)
	r.Expire(now.Add(11 * time.Second))
	if r.ReservedBytes() != 0 {
		t.Fatal("expiry leak")
	}
}

func TestUOTBoundaries(t *testing.T) {
	var b bytes.Buffer
	for _, p := range [][]byte{nil, []byte("abc"), bytes.Repeat([]byte{3}, 65535)} {
		if err := WriteUOTPacket(&b, p); err != nil {
			t.Fatal(err)
		}
		out := make([]byte, 65535)
		n, err := ReadUOTPacket(&b, out)
		if err != nil || !bytes.Equal(p, out[:n]) {
			t.Fatal(n, err)
		}
	}
	for _, b := range [][]byte{{0}, {0, 2, 1}} {
		if _, err := ReadUOTPacket(bytes.NewReader(b), make([]byte, 10)); err != io.ErrUnexpectedEOF {
			t.Fatal(err)
		}
	}
}

func FuzzDatagram(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1})
	f.Add([]byte{0x40, 0, 0, 1, 0, 0, 0, 1, 0, 2, 0, 2, 1})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeUDPFrame(b) })
}
