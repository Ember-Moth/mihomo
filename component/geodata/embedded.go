package geodata

import (
	"fmt"
	"sync/atomic"
)

var externalDownloads atomic.Bool
var siteUses, ipUses, asnUses atomic.Uint64

// SetExternalDownloads disables implicit GEO network fetches for an embedding host
// that supplies and updates the databases itself. Set before parsing configurations.
func SetExternalDownloads(enabled bool) { externalDownloads.Store(enabled) }

// UsageCounters lets an embedding host identify databases touched by one serialized
// configuration admission without resetting the process-wide updater's enable flags.
// Include ApplyConfig in the interval so inline rule providers are counted as well.
type UsageCounters struct{ Site, IP, ASN uint64 }

func Usage() UsageCounters { return UsageCounters{siteUses.Load(), ipUses.Load(), asnUses.Load()} }

func externalDownloadError(path string) error {
	return fmt.Errorf("GEO database %s is missing or invalid; downloads are managed by the host", path)
}
