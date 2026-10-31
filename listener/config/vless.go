package config

import (
	"encoding/json"
	"errors"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/listener/reality"
	"github.com/metacubex/mihomo/listener/sing"
)

type VlessUser struct {
	Username string
	UUID     string
	Flow     string
	Reverse  *VlessReverse `yaml:"reverse,omitempty" json:"reverse,omitempty"`
}

type VlessReverse struct {
	Tag string `inbound:"tag" yaml:"tag" json:"tag"`
}

func ValidateVlessReverseUsers(users []VlessUser) error {
	enabled := false
	for _, user := range users {
		if user.Reverse != nil {
			if user.Reverse.Tag == "" {
				return errors.New("vless reverse user requires a tag")
			}
			enabled = true
		}
	}
	if !enabled {
		return nil
	}
	seen := make(map[[16]byte]bool)
	for _, user := range users {
		id := utils.UUIDMap(user.UUID)
		if seen[id] {
			return errors.New("duplicate vless user UUID with reverse enabled")
		}
		seen[id] = true
	}
	return nil
}

type VlessServer struct {
	Enable          bool
	Listen          string
	Users           []VlessUser
	Decryption      string
	WsPath          string
	XHTTPConfig     XHTTPConfig
	GrpcServiceName string
	Certificate     string
	PrivateKey      string
	ClientAuthType  string
	ClientAuthCert  string
	EchKey          string
	AllowInsecure   bool
	ShadowTLS       ShadowTLS      `yaml:"shadow-tls" json:"shadow-tls,omitempty"`
	ResTLS          ResTLS         `yaml:"res-tls" json:"res-tls,omitempty"`
	JLSConfig       JLSConfig      `yaml:"jls-config" json:"jls-config,omitempty"`
	RealityConfig   reality.Config `yaml:"reality-config" json:"reality-config,omitempty"`
	MuxOption       sing.MuxOption `yaml:"mux-option" json:"mux-option,omitempty"`
}

type XHTTPConfig struct {
	Path                 string
	Host                 string
	Mode                 string
	XPaddingBytes        string
	XPaddingObfsMode     bool
	XPaddingKey          string
	XPaddingHeader       string
	XPaddingPlacement    string
	XPaddingMethod       string
	UplinkHTTPMethod     string
	SessionPlacement     string
	SessionKey           string
	SeqPlacement         string
	SeqKey               string
	UplinkDataPlacement  string
	UplinkDataKey        string
	UplinkChunkSize      string
	NoSSEHeader          bool
	ScStreamUpServerSecs string
	ScMaxBufferedPosts   string
	ScMaxEachPostBytes   string
}

func (t VlessServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
