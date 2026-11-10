package nowhere

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

const ALPN = "nw3"
const exporterLabel = "EXPORTER-Nowhere-nw3-Auth"

func validateKey(key string) error {
	if len(key) != 32 {
		return errors.New("nowhere: shared key must be 32 lowercase hexadecimal characters")
	}
	for _, c := range []byte(key) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return errors.New("nowhere: shared key must be 32 lowercase hexadecimal characters")
		}
	}
	return nil
}

func hmacSHA256(key, data []byte) [32]byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(data)
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

func expandKey(root [32]byte, label string) [32]byte {
	return hmacSHA256(root[:], append([]byte(label), 1))
}

func vectorKey(sharedKey string) [32]byte {
	salt := sha256.Sum256([]byte("nowhere/nw3/auth-root"))
	// Shared keys are ASCII text, not hex-decoded bytes.
	return expandKey(hmacSHA256(salt[:], []byte(sharedKey)), "vector-authentication")
}

func authFrame(key [32]byte, transport byte, exporter []byte) [16]byte {
	var message [33]byte
	message[0] = transport
	copy(message[1:], exporter)
	tag := hmacSHA256(key[:], message[:])
	return [16]byte(tag[:16])
}
