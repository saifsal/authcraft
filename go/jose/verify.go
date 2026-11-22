package jose

import "strings"

// Policy configures compact JWS/JWT verification.
type Policy struct {
	Algorithms    []Alg
	Issuer        *string
	Audience      *string
	Now           int64
	Leeway        uint64
	Typ           *string
	MaxTokenBytes int
}

// VerifyError is an ADR 0003 rejection.
type VerifyError struct {
	Code string
}

func (e *VerifyError) Error() string { return e.Code }

func errCode(code string) *VerifyError { return &VerifyError{Code: code} }

// VerifiedToken is a successfully verified compact JWT.
type VerifiedToken struct {
	Kid    string
	Alg    Alg
	Claims Value
}

// Verify verifies one compact JWS and validates JWT claims per ADR 0003.
func Verify(token []byte, jwks *Jwks, policy *Policy) (*VerifiedToken, error) {
	maxBytes := policy.MaxTokenBytes
	if maxBytes == 0 {
		maxBytes = 8192
	}
	if len(token) > maxBytes {
		return nil, errCode("too_large")
	}
	// Must be valid UTF-8 ASCII base64url + dots.
	for _, b := range token {
		if b > 0x7f {
			return nil, errCode("malformed")
		}
	}
	text := string(token)
	parts := strings.Split(text, ".")
	if len(parts) != 3 ||
		parts[0] == "" || parts[1] == "" || parts[2] == "" ||
		!isBase64urlAlphabet(parts[0]) ||
		!isBase64urlAlphabet(parts[1]) ||
		!isBase64urlAlphabet(parts[2]) {
		return nil, errCode("malformed")
	}
	headerSeg, payloadSeg, sigSeg := parts[0], parts[1], parts[2]

	headerBytes, err := Decode(headerSeg)
	if err != nil {
		return nil, errCode("malformed")
	}
	header, err := Parse(headerBytes)
	if err != nil || !header.IsObject() {
		return nil, errCode("malformed")
	}

	if crit := header.Get("crit"); crit != nil {
		entries, ok := crit.AsArray()
		if !ok || len(entries) == 0 {
			return nil, errCode("malformed")
		}
		for _, e := range entries {
			if _, ok := e.AsStr(); !ok {
				return nil, errCode("malformed")
			}
		}
		return nil, errCode("crit_unsupported")
	}

	algVal := header.Get("alg")
	if algVal == nil {
		return nil, errCode("alg_not_allowed")
	}
	algName, ok := algVal.AsStr()
	if !ok {
		return nil, errCode("alg_not_allowed")
	}
	alg, ok := AlgFromName(algName)
	if !ok || !algAllowed(policy.Algorithms, alg) {
		return nil, errCode("alg_not_allowed")
	}

	if policy.Typ != nil {
		typVal := header.Get("typ")
		if typVal == nil {
			return nil, errCode("typ_mismatch")
		}
		actual, ok := typVal.AsStr()
		if !ok || !typMatches(actual, *policy.Typ) {
			return nil, errCode("typ_mismatch")
		}
	}

	kidVal := header.Get("kid")
	if kidVal == nil {
		return nil, errCode("key_not_found")
	}
	kid, ok := kidVal.AsStr()
	if !ok {
		return nil, errCode("key_not_found")
	}
	key := jwks.Find(kid, alg)
	if key == nil || key.Material == nil {
		return nil, errCode("key_not_found")
	}

	sigBytes, err := Decode(sigSeg)
	if err != nil {
		return nil, errCode("bad_signature")
	}
	expectedLen := 64
	if alg == AlgHS256 {
		expectedLen = 32
	}
	if len(sigBytes) != expectedLen {
		return nil, errCode("bad_signature")
	}
	signingInput := headerSeg + "." + payloadSeg
	if err := VerifySignature(alg, *key.Material, []byte(signingInput), sigBytes); err != nil {
		return nil, errCode("bad_signature")
	}

	payloadBytes, err := Decode(payloadSeg)
	if err != nil {
		return nil, errCode("malformed")
	}
	claims, err := Parse(payloadBytes)
	if err != nil || !claims.IsObject() {
		return nil, errCode("malformed")
	}
	if err := validateClaims(&claims, policy); err != nil {
		return nil, err
	}
	return &VerifiedToken{Kid: kid, Alg: alg, Claims: claims}, nil
}

func algAllowed(algs []Alg, want Alg) bool {
	for _, a := range algs {
		if a == want {
			return true
		}
	}
	return false
}

func isBase64urlAlphabet(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' || b == '_' {
			continue
		}
		return false
	}
	return true
}

func typMatches(actual, expected string) bool {
	return strings.EqualFold(normalizeTyp(actual), normalizeTyp(expected))
}

func normalizeTyp(value string) string {
	if len(value) >= 12 && strings.EqualFold(value[:12], "application/") {
		return value[12:]
	}
	return value
}

func validateClaims(claims *Value, policy *Policy) error {
	if policy.Issuer != nil {
		iss := claims.Get("iss")
		if iss == nil {
			return errCode("wrong_issuer")
		}
		s, ok := iss.AsStr()
		if !ok || s != *policy.Issuer {
			return errCode("wrong_issuer")
		}
	}
	if policy.Audience != nil {
		aud := claims.Get("aud")
		if aud == nil {
			return errCode("wrong_audience")
		}
		matches := false
		if s, ok := aud.AsStr(); ok {
			matches = s == *policy.Audience
		} else if arr, ok := aud.AsArray(); ok {
			for _, v := range arr {
				s, ok := v.AsStr()
				if !ok {
					return errCode("malformed")
				}
				if s == *policy.Audience {
					matches = true
				}
			}
		}
		if !matches {
			return errCode("wrong_audience")
		}
	}

	expVal := claims.Get("exp")
	if expVal == nil {
		return errCode("malformed")
	}
	exp, ok := expVal.AsI64()
	if !ok {
		return errCode("malformed")
	}
	var nbf *int64
	if nbfVal := claims.Get("nbf"); nbfVal != nil {
		n, ok := nbfVal.AsI64()
		if !ok {
			return errCode("malformed")
		}
		nbf = &n
	}
	now := policy.Now
	leeway := int64(policy.Leeway)
	if now >= exp+leeway {
		return errCode("expired")
	}
	if nbf != nil && now+leeway < *nbf {
		return errCode("not_yet_valid")
	}
	return nil
}
