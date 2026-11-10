package nowhere

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

const maxPacket = 65535
const maxFlowID = 1<<30 - 1

// Target is the fixed destination of a TCP or UDP flow. Unicode domain names
// are converted to IDNA wire names; DNS resolution belongs to the remote exit.
type Target struct {
	Host string
	Port uint16
}

func (t Target) String() string  { return net.JoinHostPort(t.Host, strconv.Itoa(int(t.Port))) }
func (t Target) Network() string { return "udp" }

func (t Target) addr() net.Addr {
	if ip, err := netip.ParseAddr(t.Host); err == nil {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip.Unmap(), t.Port))
	}
	return t
}

func (t Target) validate() error {
	if t.Port == 0 {
		return errors.New("nowhere: target port must be nonzero")
	}
	if ip, err := netip.ParseAddr(t.Host); err == nil {
		if ip.Zone() != "" {
			return errors.New("nowhere: scoped target addresses are unsupported")
		}
		return nil
	}
	if len(t.Host) == 0 || len(t.Host) > 253 {
		return errors.New("nowhere: invalid target domain")
	}
	for _, label := range strings.Split(t.Host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("nowhere: invalid target domain")
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return errors.New("nowhere: target requires an ASCII IDNA domain")
			}
		}
	}
	return nil
}

func flowRequest(udp bool, target Target) ([]byte, error) {
	if _, err := netip.ParseAddr(target.Host); err != nil {
		host, err := idna.Lookup.ToASCII(target.Host)
		if err != nil {
			return nil, errors.New("nowhere: invalid IDNA target")
		}
		target.Host = host
	}
	if err := target.validate(); err != nil {
		return nil, err
	}
	b := make([]byte, 1, 259)
	if udp {
		b[0] = 1
	}
	if ip, err := netip.ParseAddr(target.Host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			b = append(b, 1)
		} else {
			b = append(b, 4)
		}
		b = append(b, ip.AsSlice()...)
	} else {
		b = append(b, 3, byte(len(target.Host)))
		b = append(b, target.Host...)
	}
	return binary.BigEndian.AppendUint16(b, target.Port), nil
}

// SetupError is a peer's rejection before the payload phase.
type SetupError byte

func (e SetupError) Error() string {
	switch e {
	case 1:
		return "nowhere: invalid request"
	case 2:
		return "nowhere: flow limit reached"
	case 3:
		return "nowhere: target dial failed"
	case 4:
		return "nowhere: peer internal error"
	default:
		return fmt.Sprintf("nowhere: invalid setup result %d", byte(e))
	}
}

func readReady(r io.Reader) error {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	if b[0] != 0 {
		return SetupError(b[0])
	}
	return nil
}

func udpFlowID(raw uint64) (FlowID, error) {
	if raw&3 != 0 || raw>>2 >= maxFlowID {
		return 0, errors.New("nowhere: invalid or exhausted client stream ID")
	}
	return FlowID((raw >> 2) + 1), nil
}
