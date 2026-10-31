// Package reverse implements the Mux.Cool transport carried by VLESS command
// 0x04, including Xray's reverse control channel and source/local metadata.
package reverse

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/metacubex/sing-vmess"
	M "github.com/metacubex/sing/common/metadata"
	"google.golang.org/protobuf/encoding/protowire"
)

const (
	statusNew       byte = 1
	statusKeep      byte = 2
	statusEnd       byte = 3
	statusKeepAlive byte = 4
	optionData      byte = 1
	optionError     byte = 2
	networkTCP      byte = 1
	networkUDP      byte = 2
	controlDomain        = "reverse"
	maxMetadata          = 512
	// Xray's Mux packet reader accepts at most one common/buf.Buffer.
	MaxPacketSize = 8192
)

type Metadata struct {
	Source      M.Socksaddr
	Local       M.Socksaddr
	Destination M.Socksaddr
}

type frame struct {
	id      uint16
	status  byte
	options byte
	network byte
	Metadata
	data []byte
}

func readFrame(reader io.Reader) (frame, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return frame{}, err
	}
	size := int(binary.BigEndian.Uint16(prefix[:]))
	if size < 4 || size > maxMetadata {
		return frame{}, fmt.Errorf("vless reverse: invalid metadata length %d", size)
	}
	header := make([]byte, size)
	if _, err := io.ReadFull(reader, header); err != nil {
		return frame{}, err
	}
	f := frame{id: binary.BigEndian.Uint16(header), status: header[2], options: header[3]}
	if f.status < statusNew || f.status > statusKeepAlive || f.options & ^byte(optionData|optionError) != 0 {
		return frame{}, errors.New("vless reverse: invalid frame flags")
	}
	r := bytes.NewReader(header[4:])
	if f.status == statusNew || (f.status == statusKeep && r.Len() > 0 && header[4] == networkUDP) {
		var err error
		f.network, f.Destination, err = readAddress(r)
		if err != nil {
			return frame{}, err
		}
	}
	if f.status == statusNew && r.Len() > 0 {
		if header[len(header)-r.Len()] != 0 {
			_, source, err := readAddress(r)
			if err != nil {
				return frame{}, err
			}
			f.Source = source
			if r.Len() > 0 && header[len(header)-r.Len()] != 0 {
				_, local, err := readAddress(r)
				if err != nil {
					return frame{}, err
				}
				f.Local = local
			}
		}
	}
	if f.options&optionData != 0 {
		if _, err := io.ReadFull(reader, prefix[:]); err != nil {
			return frame{}, err
		}
		size = int(binary.BigEndian.Uint16(prefix[:]))
		if f.network == networkUDP && size > MaxPacketSize {
			return frame{}, errors.New("vless reverse: UDP frame too large")
		}
		f.data = make([]byte, size)
		if _, err := io.ReadFull(reader, f.data); err != nil {
			return frame{}, err
		}
	}
	return f, nil
}

func readAddress(r *bytes.Reader) (byte, M.Socksaddr, error) {
	network, err := r.ReadByte()
	if err != nil {
		return 0, M.Socksaddr{}, err
	}
	if network != networkTCP && network != networkUDP {
		return 0, M.Socksaddr{}, fmt.Errorf("vless reverse: invalid network %d", network)
	}
	address, err := vmess.AddressSerializer.ReadAddrPort(r)
	return network, address, err
}

func (f frame) encode() ([]byte, error) {
	var buffer bytes.Buffer
	buffer.Write([]byte{0, 0, byte(f.id >> 8), byte(f.id), f.status, f.options})
	writeAddress := func(address M.Socksaddr) error {
		buffer.WriteByte(f.network)
		return vmess.AddressSerializer.WriteAddrPort(&buffer, address)
	}
	if f.status == statusNew || (f.status == statusKeep && f.network == networkUDP) {
		if err := writeAddress(f.Destination); err != nil {
			return nil, err
		}
	}
	if f.status == statusNew && f.Source.IsValid() && f.Local.IsValid() {
		if err := writeAddress(f.Source); err != nil {
			return nil, err
		}
		if err := writeAddress(f.Local); err != nil {
			return nil, err
		}
	}
	if buffer.Len()-2 > maxMetadata || len(f.data) > 65535 {
		return nil, errors.New("vless reverse: frame too large")
	}
	binary.BigEndian.PutUint16(buffer.Bytes()[:2], uint16(buffer.Len()-2))
	if f.options&optionData != 0 {
		buffer.Write([]byte{byte(len(f.data) >> 8), byte(len(f.data))})
		buffer.Write(f.data)
	}
	return buffer.Bytes(), nil
}

func readControl(data []byte) (bool, error) {
	var draining bool
	for len(data) > 0 {
		number, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return false, protowire.ParseError(n)
		}
		data = data[n:]
		if number == 1 {
			if typ != protowire.VarintType {
				return false, errors.New("vless reverse: invalid control state")
			}
			state, n := protowire.ConsumeVarint(data)
			if n < 0 || state > 1 {
				return false, errors.New("vless reverse: invalid control state")
			}
			draining = state == 1
			data = data[n:]
		} else {
			n := protowire.ConsumeFieldValue(number, typ, data)
			if n < 0 {
				return false, protowire.ParseError(n)
			}
			data = data[n:]
		}
	}
	return draining, nil
}
