package jose

import (
	"crypto/sha256"
	"fmt"
)

const (
	ed25519Len         = 32
	p256CoordLen       = 32
	p256UncompressedLen = 1 + 2*p256CoordLen
)

// KeyError is a public-key construction failure.
type KeyError struct {
	Kind     string
	Expected int
	Actual   int
}

func (e *KeyError) Error() string {
	switch e.Kind {
	case "bad_length":
		return fmt.Sprintf("expected %d bytes, got %d", e.Expected, e.Actual)
	case "not_uncompressed":
		return "not an uncompressed SEC 1 point"
	default:
		return "key error"
	}
}

// PublicKey is an Ed25519 or P-256 verification key.
type PublicKey struct {
	Ed25519 *[ed25519Len]byte
	P256X   *[p256CoordLen]byte
	P256Y   *[p256CoordLen]byte
}

// Ed25519FromBytes constructs an Ed25519 public key.
func Ed25519FromBytes(bytes []byte) (PublicKey, error) {
	if len(bytes) != ed25519Len {
		return PublicKey{}, &KeyError{Kind: "bad_length", Expected: ed25519Len, Actual: len(bytes)}
	}
	var x [ed25519Len]byte
	copy(x[:], bytes)
	return PublicKey{Ed25519: &x}, nil
}

// P256FromCoordinates constructs a P-256 public key from X and Y.
func P256FromCoordinates(x, y []byte) (PublicKey, error) {
	if len(x) != p256CoordLen || len(y) != p256CoordLen {
		return PublicKey{}, &KeyError{Kind: "bad_length", Expected: p256CoordLen, Actual: len(x)}
	}
	var xx, yy [p256CoordLen]byte
	copy(xx[:], x)
	copy(yy[:], y)
	return PublicKey{P256X: &xx, P256Y: &yy}, nil
}

// CanonicalJSON returns the RFC 7638 §3 required members in lexicographic order.
func (k PublicKey) CanonicalJSON() string {
	if k.Ed25519 != nil {
		return fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":"%s"}`, Encode(k.Ed25519[:]))
	}
	return fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, Encode(k.P256X[:]), Encode(k.P256Y[:]))
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint, base64url encoded.
func (k PublicKey) Thumbprint() string {
	sum := sha256.Sum256([]byte(k.CanonicalJSON()))
	return Encode(sum[:])
}
