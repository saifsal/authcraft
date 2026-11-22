package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"math/big"
)

// ErrBadSignature is returned when signature verification fails.
var ErrBadSignature = errors.New("signature verification failed")

// VerifySignature verifies a JWS signature over the ASCII bytes of header.payload.
// ES256 signatures use the fixed-width JOSE R||S format.
func VerifySignature(alg Alg, key KeyMaterial, signingInput, signature []byte) error {
	switch alg {
	case AlgEdDSA:
		if key.Public == nil || key.Public.Ed25519 == nil {
			return ErrBadSignature
		}
		if len(signature) != ed25519.SignatureSize {
			return ErrBadSignature
		}
		if !ed25519.Verify(key.Public.Ed25519[:], signingInput, signature) {
			return ErrBadSignature
		}
		return nil
	case AlgES256:
		if key.Public == nil || key.Public.P256X == nil || key.Public.P256Y == nil {
			return ErrBadSignature
		}
		if len(signature) != 64 {
			return ErrBadSignature
		}
		curve := elliptic.P256()
		x := new(big.Int).SetBytes(key.Public.P256X[:])
		y := new(big.Int).SetBytes(key.Public.P256Y[:])
		if !curve.IsOnCurve(x, y) {
			return ErrBadSignature
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		sum := sha256.Sum256(signingInput)
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if !ecdsa.Verify(pub, sum[:], r, s) {
			return ErrBadSignature
		}
		return nil
	case AlgHS256:
		if key.Secret == nil || len(key.Secret) < HS256MinKeyLen {
			return ErrBadSignature
		}
		if len(signature) != sha256.Size {
			return ErrBadSignature
		}
		mac := hmac.New(sha256.New, key.Secret)
		_, _ = mac.Write(signingInput)
		expected := mac.Sum(nil)
		if !hmac.Equal(expected, signature) {
			return ErrBadSignature
		}
		return nil
	default:
		return ErrBadSignature
	}
}
