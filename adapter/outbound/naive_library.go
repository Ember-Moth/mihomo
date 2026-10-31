//go:build with_naive && !with_purego

package outbound

// Select the native library for GOOS/GOARCH, as in sing-box. Purego builds
// load the matching shared library at runtime instead.
import _ "github.com/Ember-Moth/cronet-go/all"
