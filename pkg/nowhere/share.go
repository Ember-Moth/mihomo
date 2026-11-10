package nowhere

import (
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ShareLink is a nowhere:// endpoint. Optional sni and pin carry certificate
// trust settings. Known query parameters use the first occurrence, matching
// Nowhere's URL parser; percent escapes are decoded exactly once.
type ShareLink struct {
	Server                             string
	Port                               uint16
	SharedKey, Network, SNI, Pin, Name string
	Morph                              bool
}

func ParseShareLink(raw string) (ShareLink, error) {
	var out ShareLink
	u, err := url.Parse(raw)
	if err != nil {
		return out, errors.New("nowhere: invalid share URL")
	}
	if strings.ToLower(u.Scheme) != "nowhere" || u.User == nil || u.Hostname() == "" || u.Path != "" || u.Opaque != "" {
		return out, errors.New("nowhere: share URL requires KEY@HOST:PORT without a path")
	}
	if _, present := u.User.Password(); present {
		return out, errors.New("nowhere: share URL must not contain password userinfo")
	}
	out.SharedKey = u.User.Username()
	if err := validateKey(out.SharedKey); err != nil {
		return out, err
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 {
		return out, errors.New("nowhere: invalid share port")
	}
	out.Server, out.Port = u.Hostname(), uint16(port)
	if strings.Contains(out.Server, ":") && !strings.HasPrefix(u.Host, "[") {
		return out, errors.New("nowhere: IPv6 share hosts require brackets")
	}
	if err := (Target{Host: out.Server, Port: out.Port}).validate(); err != nil {
		return out, err
	}
	values := make(map[string]string)
	for _, pair := range strings.Split(u.RawQuery, "&") {
		rawKey, rawValue, _ := strings.Cut(pair, "=")
		key, err := url.PathUnescape(rawKey)
		if err != nil {
			continue
		}
		if key != "net" && key != "morph" && key != "sni" && key != "pin" {
			continue
		}
		if _, exists := values[key]; exists {
			continue
		}
		value, err := url.PathUnescape(rawValue)
		if err != nil || !utf8.ValidString(value) {
			return out, errors.New("nowhere: malformed share query value")
		}
		values[key] = value
	}
	out.Network = "tcp"
	if network, exists := values["net"]; exists {
		if network != "tcp" && network != "udp" {
			return out, errors.New("nowhere: net must be tcp or udp")
		}
		out.Network = network
	}
	out.Morph = true
	if morph, exists := values["morph"]; exists {
		if morph != "0" && morph != "1" {
			return out, errors.New("nowhere: morph must be 0 or 1")
		}
		out.Morph = morph == "1"
	}
	out.SNI, out.Pin = values["sni"], values["pin"]
	if out.SNI == "none" {
		out.SNI = ""
	}
	if out.Pin == "none" {
		out.Pin = ""
	}
	if out.Pin != "" {
		pin, err := hex.DecodeString(out.Pin)
		if err != nil || len(pin) != 32 || strings.ToLower(out.Pin) != out.Pin {
			return out, errors.New("nowhere: invalid certificate pin")
		}
	}
	if out.SNI != "" {
		if err := (Target{Host: out.SNI, Port: 1}).validate(); err != nil {
			return out, errors.New("nowhere: invalid SNI")
		}
	}
	out.Name = u.Fragment
	if !utf8.ValidString(out.Name) {
		return out, errors.New("nowhere: invalid display name")
	}
	if out.Name == "" {
		out.Name = out.Server
	}
	return out, nil
}
