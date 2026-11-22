// Package harness runs the shared testvectors against the Go verifier and,
// when jose-cli is available, differentially against the Rust CLI (ADR 0002).
package harness

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/saifsal/authcraft/go/jose"
)

func testvectorsRoot(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "testvectors"),
		filepath.Join("..", "testvectors"),
		"testvectors",
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	t.Fatal("testvectors directory not found")
	return ""
}

func collectVectors(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	for _, sub := range []string{"generated", "rfc"} {
		dir := filepath.Join(root, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		var names []string
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			files = append(files, filepath.Join(dir, name))
		}
	}
	if len(files) == 0 {
		t.Fatal("no vectors found")
	}
	return files
}

// compact re-serialization of a JSON value for JWKS hand-off (stdlib decode then encode loses nothing we need for keys).
func mustCompactJSON(t *testing.T, raw json.RawMessage) []byte {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type vectorFile struct {
	ID     string          `json:"id"`
	Source string          `json:"source"`
	JWKS   json.RawMessage `json:"jwks"`
	Policy json.RawMessage `json:"policy"`
	Token  string          `json:"token"`
	Expect struct {
		OK    bool    `json:"ok"`
		Error *string `json:"error"`
		Kid   *string `json:"kid"`
		Alg   *string `json:"alg"`
	} `json:"expect"`
}

type policyJSON struct {
	Algs          []string `json:"algs"`
	Iss           *string  `json:"iss"`
	Aud           *string  `json:"aud"`
	Now           int64    `json:"now"`
	Leeway        *int64   `json:"leeway"`
	Typ           *string  `json:"typ"`
	MaxTokenBytes *int     `json:"max_token_bytes"`
}

func policyFrom(t *testing.T, raw json.RawMessage) jose.Policy {
	t.Helper()
	var p policyJSON
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	algs := make([]jose.Alg, len(p.Algs))
	for i, name := range p.Algs {
		a, ok := jose.AlgFromName(name)
		if !ok {
			t.Fatalf("unknown alg %q", name)
		}
		algs[i] = a
	}
	pol := jose.Policy{
		Algorithms:    algs,
		Issuer:        p.Iss,
		Audience:      p.Aud,
		Now:           p.Now,
		Typ:           p.Typ,
		MaxTokenBytes: 8192,
	}
	if p.Leeway != nil {
		pol.Leeway = uint64(*p.Leeway)
	}
	if p.MaxTokenBytes != nil {
		pol.MaxTokenBytes = *p.MaxTokenBytes
	}
	return pol
}

func runGoVector(t *testing.T, path string) (ok bool, code string, kid, alg string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Parse with our strict parser for the vector document itself, then extract
	// fields. Using encoding/json for the outer envelope is fine: vectors are
	// well-formed and do not rely on duplicate-key rejection at the file level.
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	stem := strings.TrimSuffix(filepath.Base(path), ".json")
	if vf.ID != stem {
		t.Fatalf("%s: id %q != stem %q", path, vf.ID, stem)
	}
	if vf.Source == "" {
		t.Fatalf("%s: empty source", path)
	}

	jwksBytes := mustCompactJSON(t, vf.JWKS)
	jwks, err := jose.ParseJwks(jwksBytes)
	if err != nil {
		t.Fatalf("%s: JWKS config error: %v", path, err)
	}
	policy := policyFrom(t, vf.Policy)

	verified, err := jose.Verify([]byte(vf.Token), jwks, &policy)
	if vf.Expect.OK {
		if err != nil {
			t.Fatalf("%s: expected success, got %v", path, err)
		}
		if vf.Expect.Kid != nil && verified.Kid != *vf.Expect.Kid {
			t.Fatalf("%s: kid got %q want %q", path, verified.Kid, *vf.Expect.Kid)
		}
		if vf.Expect.Alg != nil && verified.Alg.Name() != *vf.Expect.Alg {
			t.Fatalf("%s: alg got %q want %q", path, verified.Alg.Name(), *vf.Expect.Alg)
		}
		return true, "", verified.Kid, verified.Alg.Name()
	}
	if err == nil {
		t.Fatalf("%s: expected rejection, token verified", path)
	}
	ve, ok := err.(*jose.VerifyError)
	if !ok {
		t.Fatalf("%s: unexpected error type %T %v", path, err, err)
	}
	if vf.Expect.Error == nil || ve.Code != *vf.Expect.Error {
		want := ""
		if vf.Expect.Error != nil {
			want = *vf.Expect.Error
		}
		t.Fatalf("%s: wrong error code: got %q want %q", path, ve.Code, want)
	}
	return false, ve.Code, "", ""
}

func TestSharedVectorsMatchGoVerifier(t *testing.T) {
	root := testvectorsRoot(t)
	for _, path := range collectVectors(t, root) {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			runGoVector(t, path)
		})
	}
}

func TestRFCSignaturesWhenKidAbsent(t *testing.T) {
	root := testvectorsRoot(t)
	cases := []struct {
		id  string
		alg jose.Alg
	}{
		{"rfc7515-a1-hs256", jose.AlgHS256},
		{"rfc7515-a3-es256", jose.AlgES256},
		{"rfc8037-a4-eddsa", jose.AlgEdDSA},
	}
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			path := filepath.Join(root, "rfc", c.id+".json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var vf vectorFile
			if err := json.Unmarshal(data, &vf); err != nil {
				t.Fatal(err)
			}
			if vf.Expect.Error == nil || *vf.Expect.Error != "key_not_found" {
				t.Fatal("shared verdict")
			}
			jwks, err := jose.ParseJwks(mustCompactJSON(t, vf.JWKS))
			if err != nil {
				t.Fatal(err)
			}
			var material *jose.KeyMaterial
			for i := range jwks.Keys {
				if jwks.Keys[i].Material != nil {
					material = jwks.Keys[i].Material
					break
				}
			}
			if material == nil {
				t.Fatal("no usable key")
			}
			dot := strings.LastIndex(vf.Token, ".")
			if dot < 0 {
				t.Fatal("no signature separator")
			}
			sigBytes, err := jose.Decode(vf.Token[dot+1:])
			if err != nil {
				t.Fatal(err)
			}
			if err := jose.VerifySignature(c.alg, *material, []byte(vf.Token[:dot]), sigBytes); err != nil {
				t.Fatalf("published signature did not verify: %v", err)
			}
		})
	}
}

func findJoseCLI(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("AUTHCRAFT_JOSE_CLI"); p != "" {
		return p
	}
	candidates := []string{
		filepath.Join("..", "..", "rust", "target", "debug", "jose-cli"),
		filepath.Join("..", "..", "rust", "target", "release", "jose-cli"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

func TestDifferentialAgainstJoseCLI(t *testing.T) {
	cli := findJoseCLI(t)
	if cli == "" {
		t.Skip("jose-cli not built; set AUTHCRAFT_JOSE_CLI or cargo build -p jose-cli")
	}
	root := testvectorsRoot(t)
	tmpdir := t.TempDir()

	for _, path := range collectVectors(t, root) {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var vf vectorFile
			if err := json.Unmarshal(data, &vf); err != nil {
				t.Fatal(err)
			}

			goOK, goCode, _, _ := runGoVector(t, path)

			jwksPath := filepath.Join(tmpdir, filepath.Base(path)+".jwks.json")
			policyPath := filepath.Join(tmpdir, filepath.Base(path)+".policy.json")
			if err := os.WriteFile(jwksPath, mustCompactJSON(t, vf.JWKS), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(policyPath, vf.Policy, 0o600); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(cli, "verify", "--jwks", jwksPath, "--policy", policyPath, "--token", "-")
			cmd.Stdin = strings.NewReader(vf.Token)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			runErr := cmd.Run()

			var verdict struct {
				OK    bool    `json:"ok"`
				Error *string `json:"error"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &verdict); err != nil {
				t.Fatalf("jose-cli stdout not JSON verdict (%v): %q stderr=%q", runErr, stdout.String(), stderr.String())
			}

			if goOK != verdict.OK {
				t.Fatalf("ok mismatch: go=%v rust=%v", goOK, verdict.OK)
			}
			if !goOK {
				rustCode := ""
				if verdict.Error != nil {
					rustCode = *verdict.Error
				}
				if goCode != rustCode {
					t.Fatalf("error mismatch: go=%q rust=%q", goCode, rustCode)
				}
			}
			if vf.Expect.OK != goOK {
				t.Fatalf("both disagree with vector expect.ok=%v", vf.Expect.OK)
			}
		})
	}
}
