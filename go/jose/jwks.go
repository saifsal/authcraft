package jose

import "fmt"

// KeyMaterial is key bytes a verifier can use.
type KeyMaterial struct {
	Public *PublicKey
	Secret []byte
}

func (m KeyMaterial) naturalAlg() Alg {
	if m.Public != nil {
		if m.Public.Ed25519 != nil {
			return AlgEdDSA
		}
		return AlgES256
	}
	return AlgHS256
}

// Key is one JWKS entry.
type Key struct {
	Kid      *string
	Alg      *string
	Use      *string
	Material *KeyMaterial // nil when unusable
}

func (k *Key) usableFor(want Alg) bool {
	if k.Material == nil {
		return false
	}
	if k.Material.naturalAlg() != want {
		return false
	}
	if k.Alg != nil && *k.Alg != want.Name() {
		return false
	}
	if k.Use != nil && *k.Use != "sig" {
		return false
	}
	return true
}

// JwksError is a JWKS configuration error.
type JwksError struct {
	Kind  string
	Index int
	Kid   string
	Err   error
}

func (e *JwksError) Error() string {
	switch e.Kind {
	case "json":
		return fmt.Sprintf("JWKS is not valid JSON: %v", e.Err)
	case "not_object":
		return "JWKS is not a JSON object"
	case "missing_keys":
		return `JWKS has no "keys" member`
	case "keys_not_array":
		return `JWKS "keys" is not an array`
	case "key_not_object":
		return fmt.Sprintf("key %d is not a JSON object", e.Index)
	case "kid_not_string":
		return fmt.Sprintf("key %d has a non-string kid", e.Index)
	case "duplicate_kid":
		return fmt.Sprintf("duplicate kid %q", e.Kid)
	default:
		return "jwks error"
	}
}

// Jwks is a set of verification keys looked up by kid.
type Jwks struct {
	Keys []Key
}

// ParseJwks parses a JWKS document.
func ParseJwks(input []byte) (*Jwks, error) {
	root, err := Parse(input)
	if err != nil {
		return nil, &JwksError{Kind: "json", Err: err}
	}
	if !root.IsObject() {
		return nil, &JwksError{Kind: "not_object"}
	}
	keysVal := root.Get("keys")
	if keysVal == nil {
		return nil, &JwksError{Kind: "missing_keys"}
	}
	entries, ok := keysVal.AsArray()
	if !ok {
		return nil, &JwksError{Kind: "keys_not_array"}
	}

	seen := make(map[string]struct{})
	keys := make([]Key, 0, len(entries))
	for i, entry := range entries {
		if !entry.IsObject() {
			return nil, &JwksError{Kind: "key_not_object", Index: i}
		}
		var kid *string
		if v := entry.Get("kid"); v != nil {
			s, ok := v.AsStr()
			if !ok {
				return nil, &JwksError{Kind: "kid_not_string", Index: i}
			}
			kid = &s
			if _, dup := seen[s]; dup {
				return nil, &JwksError{Kind: "duplicate_kid", Kid: s}
			}
			seen[s] = struct{}{}
		}
		keys = append(keys, keyFromJSON(kid, entry))
	}
	return &Jwks{Keys: keys}, nil
}

// Find returns the key for kid and alg, or nil.
func (j *Jwks) Find(kid string, alg Alg) *Key {
	for i := range j.Keys {
		k := &j.Keys[i]
		if k.Kid == nil || *k.Kid != kid {
			continue
		}
		if k.usableFor(alg) {
			return k
		}
		return nil
	}
	return nil
}

type memberStr int

const (
	memberAbsent memberStr = iota
	memberValue
	memberInvalid
)

func readOptionalString(entry Value, name string) (memberStr, *string) {
	v := entry.Get(name)
	if v == nil {
		return memberAbsent, nil
	}
	s, ok := v.AsStr()
	if !ok {
		return memberInvalid, nil
	}
	return memberValue, &s
}

func keyFromJSON(kid *string, entry Value) Key {
	algKind, alg := readOptionalString(entry, "alg")
	useKind, use := readOptionalString(entry, "use")
	var material *KeyMaterial
	if algKind != memberInvalid && useKind != memberInvalid {
		material = loadMaterial(entry)
	}
	return Key{Kid: kid, Alg: alg, Use: use, Material: material}
}

func memberStrVal(entry Value, name string) (string, bool) {
	v := entry.Get(name)
	if v == nil {
		return "", false
	}
	return v.AsStr()
}

func memberBytes(entry Value, name string) ([]byte, bool) {
	s, ok := memberStrVal(entry, name)
	if !ok {
		return nil, false
	}
	b, err := Decode(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

func loadMaterial(entry Value) *KeyMaterial {
	kty, ok := memberStrVal(entry, "kty")
	if !ok {
		return nil
	}
	switch kty {
	case "OKP":
		crv, ok := memberStrVal(entry, "crv")
		if !ok || crv != "Ed25519" {
			return nil
		}
		x, ok := memberBytes(entry, "x")
		if !ok {
			return nil
		}
		pk, err := Ed25519FromBytes(x)
		if err != nil {
			return nil
		}
		return &KeyMaterial{Public: &pk}
	case "EC":
		crv, ok := memberStrVal(entry, "crv")
		if !ok || crv != "P-256" {
			return nil
		}
		x, ok := memberBytes(entry, "x")
		if !ok {
			return nil
		}
		y, ok := memberBytes(entry, "y")
		if !ok {
			return nil
		}
		pk, err := P256FromCoordinates(x, y)
		if err != nil {
			return nil
		}
		return &KeyMaterial{Public: &pk}
	case "oct":
		k, ok := memberBytes(entry, "k")
		if !ok || len(k) < HS256MinKeyLen {
			return nil
		}
		return &KeyMaterial{Secret: k}
	default:
		return nil
	}
}
