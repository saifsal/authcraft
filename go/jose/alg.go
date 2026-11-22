// Package jose is a compact JWS/JWT verifier matching the authcraft Rust and Zig
// implementations against the shared vectors in testvectors/ (ADR 0002, ADR 0003).
package jose

// HS256MinKeyLen is the RFC 7518 §3.2 minimum key length for HS256 (256 bits).
const HS256MinKeyLen = 32

// Alg is a JWS algorithm known to this project. none is deliberately absent (ADR 0001).
type Alg int

const (
	AlgEdDSA Alg = iota
	AlgES256
	AlgHS256 // verification only
)

// Name returns the registered JOSE algorithm name.
func (a Alg) Name() string {
	switch a {
	case AlgEdDSA:
		return "EdDSA"
	case AlgES256:
		return "ES256"
	case AlgHS256:
		return "HS256"
	default:
		return ""
	}
}

// AlgFromName looks up an algorithm by its exact, case-sensitive name.
func AlgFromName(name string) (Alg, bool) {
	switch name {
	case "EdDSA":
		return AlgEdDSA, true
	case "ES256":
		return AlgES256, true
	case "HS256":
		return AlgHS256, true
	default:
		return 0, false
	}
}
