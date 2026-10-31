//go:build !with_naive

package adapter

import (
	"strings"
	"testing"
)

func TestNaiveUnavailable(t *testing.T) {
	_, err := ParseProxy(map[string]any{"type": "naive", "name": "naive", "server": "example.org", "port": 443})
	if err == nil || !strings.Contains(err.Error(), "with_naive") {
		t.Fatalf("expected actionable build-tag error, got %v", err)
	}
}
