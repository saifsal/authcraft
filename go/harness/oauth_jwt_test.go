package harness

// JWT-layer check of the OAuth client-authentication, JAR, and introspection
// vectors (ADR 0014–0016) with the Go verifier.
//
// Go has no OAuth server, so these tests cannot reproduce flow-level outcomes
// (replay, missing parameters, PAR redemption). They port the JWT rules only:
// RFC 7523 client assertions (ADR 0014, including B3 typ) and RFC 9101 request
// objects (ADR 0015). Each vector is classified in jwtVerdicts as whether all
// of its JWTs pass those rules; the table must cover every vector file.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/saifsal/authcraft/go/jose"
)

const (
	asIssuer              = "https://auth.example"
	clientAssertionTyp    = "client-authentication+jwt"
	requestObjectTyp      = "oauth-authz-req+jwt"
	maxAssertionLifetime  = 300
	maxRequestObjLifetime = 300
)

var errJWT = errors.New("jwt rule failed")

// jwtVerdicts records, per vector id, whether every JWT in the vector passes
// the JWT-layer rules. false means at least one JWT is rejected by them.
var jwtVerdicts = map[string]bool{
	// testvectors/client_auth/
	"pos-private-key-jwt":                 true,
	"pos-par-private-key-jwt":             true,
	"pos-revoke-private-key-jwt":          true,
	"pos-typ-explicit":                    true,
	"neg-missing-assertion":               true, // no JWT; flow-level
	"neg-wrong-assertion-type":            true, // form parameter, not JWT
	"neg-replay-assertion":                true, // replay is flow-level
	"neg-par-assertion-replayed-at-token": true,
	"neg-par-missing-assertion":           true,
	"neg-revoke-missing-assertion":        true,
	"neg-aud-token-endpoint":              false,
	"neg-lifetime-too-long":               false,
	"neg-unknown-kid":                     false,
	"neg-sub-mismatch":                    false,
	"neg-public-client-assertion":         false, // spa has no keys
	"neg-typ-request-object":              false,
	"neg-typ-access-token":                false,
	"neg-typ-required-missing":            false,
	// testvectors/jar/
	"pos-jar-authorize":                true,
	"pos-jar-par":                      true,
	"pos-jar-required-signed":          true,
	"pos-jar-required-par":             true,
	"neg-jar-with-request-uri":         true, // parameter combination
	"neg-jar-unregistered-redirect":    true, // redirect check is flow-level
	"neg-jar-required-plain-authorize": true, // no JWT
	"neg-jar-required-plain-par":       true,
	"neg-jar-typ-missing":              false,
	"neg-jar-aud-wrong":                false,
	"neg-jar-client-id-mismatch":       false,
	"neg-jar-expired":                  false,
	"neg-jar-public-client":            false,
	// testvectors/introspect/
	"pos-rs-introspects-any-token":     true,
	"pos-client-introspects-own-token": true,
	"neg-client-other-token-inactive":  true, // visibility is flow-level
	"neg-public-caller":                true,
	"neg-missing-assertion@introspect": true,
	"neg-unknown-caller":               true,
}

// verdictKey disambiguates ids that appear in more than one directory.
func verdictKey(dir, id string) string {
	if dir == "introspect" && id == "neg-missing-assertion" {
		return id + "@introspect"
	}
	return id
}

// clientJWKS returns the registered JWKS per client id from
// testvectors/client_auth/schema.json; public clients map to nil.
func clientJWKS(t *testing.T, root string) map[string][]byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "client_auth", "schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Server struct {
			Clients []struct {
				ClientID string          `json:"client_id"`
				JWKS     json.RawMessage `json:"jwks"`
			} `json:"clients"`
		} `json:"x-authcraft-server"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	var svc []byte
	for _, c := range schema.Server.Clients {
		if len(c.JWKS) > 0 {
			out[c.ClientID] = mustCompactJSON(t, c.JWKS)
			if c.ClientID == "svc" {
				svc = out[c.ClientID]
			}
		} else {
			out[c.ClientID] = nil
		}
	}
	if svc == nil {
		t.Fatal("svc JWKS missing from client_auth schema")
	}
	// jar/ and introspect/ schemas: svc-strict and rs reuse the svc JWKS.
	out["svc-strict"] = svc
	out["rs"] = svc
	return out
}

// headerTyp reads the protected header typ of a compact JWS.
func headerTyp(token string) (string, bool, error) {
	seg, _, _ := strings.Cut(token, ".")
	raw, err := jose.Decode(seg)
	if err != nil {
		return "", false, err
	}
	h, err := jose.Parse(raw)
	if err != nil {
		return "", false, err
	}
	v := h.Get("typ")
	if v == nil {
		return "", false, nil
	}
	s, ok := v.AsStr()
	if !ok {
		return "", false, errJWT
	}
	return s, true, nil
}

func normTyp(s string) string {
	if len(s) >= 12 && strings.EqualFold(s[:12], "application/") {
		return s[12:]
	}
	return s
}

func clientAlgs() []jose.Alg {
	ed, _ := jose.AlgFromName("EdDSA")
	es, _ := jose.AlgFromName("ES256")
	return []jose.Alg{ed, es}
}

func verifyWith(token string, jwks []byte, iss string, now int64, typ *string) (*jose.VerifiedToken, error) {
	if jwks == nil {
		return nil, errJWT
	}
	set, err := jose.ParseJwks(jwks)
	if err != nil {
		return nil, err
	}
	aud := asIssuer
	return jose.Verify([]byte(token), set, &jose.Policy{
		Algorithms:    clientAlgs(),
		Issuer:        &iss,
		Audience:      &aud,
		Now:           now,
		Typ:           typ,
		MaxTokenBytes: 8192,
	})
}

func claimStr(v *jose.VerifiedToken, name string) (string, bool) {
	c := v.Claims.Get(name)
	if c == nil {
		return "", false
	}
	return c.AsStr()
}

func claimExp(v *jose.VerifiedToken) int64 {
	c := v.Claims.Get("exp")
	n, _ := c.AsI64()
	return n
}

// checkClientAssertion ports oauth::client_auth::verify_client_assertion
// without the jti cache.
func checkClientAssertion(token, clientID string, jwks []byte, now int64, requireTyp bool) error {
	v, err := verifyWith(token, jwks, clientID, now, nil)
	if err != nil {
		return err
	}
	typ, present, err := headerTyp(token)
	if err != nil {
		return err
	}
	switch {
	case !present:
		if requireTyp {
			return errJWT
		}
	case strings.EqualFold(normTyp(typ), clientAssertionTyp):
	case strings.EqualFold(normTyp(typ), "JWT") && !requireTyp:
	default:
		return errJWT
	}
	if sub, _ := claimStr(v, "sub"); sub != clientID {
		return errJWT
	}
	if claimExp(v)-now > maxAssertionLifetime {
		return errJWT
	}
	if jti, ok := claimStr(v, "jti"); !ok || jti == "" {
		return errJWT
	}
	return nil
}

// checkRequestObject ports oauth::request_object::verify_request_object.
func checkRequestObject(token, clientID string, jwks []byte, now int64) error {
	typ := requestObjectTyp
	v, err := verifyWith(token, jwks, clientID, now, &typ)
	if err != nil {
		return err
	}
	if cid, _ := claimStr(v, "client_id"); cid != clientID {
		return errJWT
	}
	if claimExp(v)-now > maxRequestObjLifetime {
		return errJWT
	}
	if v.Claims.Get("request") != nil || v.Claims.Get("request_uri") != nil {
		return errJWT
	}
	for _, name := range []string{"response_type", "redirect_uri", "code_challenge",
		"code_challenge_method", "state", "scope", "nonce"} {
		if c := v.Claims.Get(name); c != nil {
			if _, ok := c.AsStr(); !ok {
				return errJWT
			}
		}
	}
	return nil
}

type oauthVector struct {
	ID    string         `json:"id"`
	Steps map[string]any `json:"steps"`
}

func (v oauthVector) str(name string) string {
	s, _ := v.Steps[name].(string)
	return s
}

func (v oauthVector) num(name string) int64 {
	f, _ := v.Steps[name].(float64)
	return int64(f)
}

// jwtsPass applies the JWT-layer rules to every JWT a vector carries.
func jwtsPass(dir string, v oauthVector, keys map[string][]byte) bool {
	var errs []error
	switch dir {
	case "client_auth":
		if a := v.str("client_assertion"); a != "" {
			req, _ := v.Steps["require_client_assertion_typ"].(bool)
			id := v.str("client_id")
			errs = append(errs, checkClientAssertion(a, id, keys[id], v.num("now_token"), req))
		}
	case "jar":
		id := v.str("client_id")
		if r := v.str("request"); r != "" {
			errs = append(errs, checkRequestObject(r, id, keys[id], v.num("now")))
		}
		if a := v.str("client_assertion"); a != "" {
			errs = append(errs, checkClientAssertion(a, id, keys[id], v.num("now"), false))
		}
	case "introspect":
		if a := v.str("caller_assertion"); a != "" {
			id := v.str("caller")
			errs = append(errs, checkClientAssertion(a, id, keys[id], v.num("now"), false))
		}
		if a := v.str("token_client_assertion"); a != "" {
			id := v.str("token_client")
			errs = append(errs, checkClientAssertion(a, id, keys[id], v.num("now"), false))
		}
	}
	for _, e := range errs {
		if e != nil {
			return false
		}
	}
	return true
}

func TestOAuthVectorJWTsMatchGoRules(t *testing.T) {
	root := testvectorsRoot(t)
	keys := clientJWKS(t, root)
	seen := map[string]bool{}
	for _, dir := range []string{"client_auth", "jar", "introspect"} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".json") && e.Name() != "schema.json" {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			path := filepath.Join(root, dir, name)
			t.Run(dir+"/"+name, func(t *testing.T) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var v oauthVector
				if err := json.Unmarshal(data, &v); err != nil {
					t.Fatal(err)
				}
				if v.ID != strings.TrimSuffix(name, ".json") {
					t.Fatalf("id %q != file stem", v.ID)
				}
				key := verdictKey(dir, v.ID)
				want, ok := jwtVerdicts[key]
				if !ok {
					t.Fatalf("vector %s/%s is not classified in jwtVerdicts", dir, v.ID)
				}
				seen[key] = true
				if got := jwtsPass(dir, v, keys); got != want {
					t.Fatalf("JWT-layer verdict: got %v want %v", got, want)
				}
			})
		}
	}
	for key := range jwtVerdicts {
		if !seen[key] {
			t.Errorf("jwtVerdicts lists %q but no such vector exists", key)
		}
	}
}
