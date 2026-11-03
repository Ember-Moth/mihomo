package mmdb

import (
	"bytes"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/oschwald/maxminddb-golang"
)

type databaseType = uint8

const (
	typeMaxmind databaseType = iota
	typeSing
	typeMetaV0
)

// Readers own immutable Go memory, not a mapping of a replaceable file. Returning a
// snapshot keeps its backing bytes alive until the last lookup releases it. Publishing
// a replacement never closes a reader that another goroutine may still be using.
var (
	ipMu      sync.Mutex
	asnMu     sync.Mutex
	ipReader  atomic.Pointer[IPReader]
	asnReader atomic.Pointer[ASNReader]
)

func readBuffer(buffer []byte) (*maxminddb.Reader, error) {
	reader, err := maxminddb.FromBytes(bytes.Clone(buffer))
	if err != nil {
		return nil, err
	}
	// Validate the tree and every referenced record. Reader.Verify imposes extra
	// layout constraints that reject Meta-geoip0's shared records and requires the
	// optional description field. Preserve the source metadata and compact layout.
	if reader.Metadata.BinaryFormatMajorVersion != 2 || reader.Metadata.DatabaseType == "" ||
		(reader.Metadata.IPVersion != 4 && reader.Metadata.IPVersion != 6) || reader.Metadata.NodeCount == 0 {
		return nil, fmt.Errorf("invalid MMDB metadata")
	}
	networks := reader.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		var record any
		if _, err := networks.Network(&record); err != nil {
			return nil, err
		}
	}
	if err := networks.Err(); err != nil {
		return nil, err
	}
	return reader, nil
}

func ipSnapshot(reader *maxminddb.Reader) IPReader {
	result := IPReader{Reader: reader}
	switch reader.Metadata.DatabaseType {
	case "sing-geoip":
		result.databaseType = typeSing
	case "Meta-geoip0":
		result.databaseType = typeMetaV0
	}
	return result
}

func LoadFromBytes(buffer []byte) {
	ipMu.Lock()
	defer ipMu.Unlock()
	if ipReader.Load() != nil {
		return
	}
	reader, err := readBuffer(buffer)
	if err != nil {
		log.Fatalln("Can't load mmdb: %s", err)
		return
	}
	snapshot := ipSnapshot(reader)
	ipReader.Store(&snapshot)
}

func Verify(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	_, err = readBuffer(data)
	return err == nil
}

func IPInstance() IPReader {
	if reader := ipReader.Load(); reader != nil {
		return *reader
	}
	ipMu.Lock()
	defer ipMu.Unlock()
	if ipReader.Load() == nil {
		data, err := os.ReadFile(C.Path.MMDB())
		if err != nil {
			log.Fatalln("Can't load MMDB: %s", err)
			return IPReader{}
		}
		reader, err := readBuffer(data)
		if err != nil {
			log.Fatalln("Can't load MMDB: %s", err)
			return IPReader{}
		}
		snapshot := ipSnapshot(reader)
		ipReader.Store(&snapshot)
	}
	return *ipReader.Load()
}

func ASNInstance() ASNReader {
	if reader := asnReader.Load(); reader != nil {
		return *reader
	}
	asnMu.Lock()
	defer asnMu.Unlock()
	if asnReader.Load() == nil {
		data, err := os.ReadFile(C.Path.ASN())
		if err != nil {
			log.Fatalln("Can't load ASN: %s", err)
			return ASNReader{}
		}
		reader, err := readBuffer(data)
		if err != nil {
			log.Fatalln("Can't load ASN: %s", err)
			return ASNReader{}
		}
		asnReader.Store(&ASNReader{Reader: reader})
	}
	return *asnReader.Load()
}

// InstallIP verifies an owned snapshot first, persists it, then publishes it. A failed
// validation or persistence keeps both the current reader and existing lookups intact.
// persist must replace the file atomically and must not call back into mmdb.
func InstallIP(buffer []byte, persist func() error) error {
	reader, err := readBuffer(buffer)
	if err != nil {
		return err
	}
	ipMu.Lock()
	defer ipMu.Unlock()
	if err := persist(); err != nil {
		return err
	}
	snapshot := ipSnapshot(reader)
	ipReader.Store(&snapshot)
	return nil
}

func InstallASN(buffer []byte, persist func() error) error {
	reader, err := readBuffer(buffer)
	if err != nil {
		return err
	}
	switch reader.Metadata.DatabaseType {
	case "GeoLite2-ASN", "DBIP-ASN-Lite (compat=GeoLite2-ASN)", "ipinfo generic_asn_free.mmdb":
	default:
		return fmt.Errorf("unsupported ASN database type %q", reader.Metadata.DatabaseType)
	}
	asnMu.Lock()
	defer asnMu.Unlock()
	if err := persist(); err != nil {
		return err
	}
	asnReader.Store(&ASNReader{Reader: reader})
	return nil
}

func ReloadIP() {
	data, err := os.ReadFile(C.Path.MMDB())
	if err == nil {
		err = InstallIP(data, func() error { return nil })
	}
	if err != nil {
		log.Warnln("Can't reload MMDB: %s", err)
	}
}

func ReloadASN() {
	data, err := os.ReadFile(C.Path.ASN())
	if err == nil {
		err = InstallASN(data, func() error { return nil })
	}
	if err != nil {
		log.Warnln("Can't reload ASN: %s", err)
	}
}
