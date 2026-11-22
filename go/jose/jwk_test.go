package jose

import "testing"

func TestRFC8037Thumbprint(t *testing.T) {
	x, err := Decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if err != nil {
		t.Fatal(err)
	}
	key, err := Ed25519FromBytes(x)
	if err != nil {
		t.Fatal(err)
	}
	wantCanon := `{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	if key.CanonicalJSON() != wantCanon {
		t.Fatalf("canonical: %s", key.CanonicalJSON())
	}
	if tp := key.Thumbprint(); tp != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Fatalf("thumbprint: %s", tp)
	}
}

func TestP256Thumbprint(t *testing.T) {
	x, _ := Decode("l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs")
	y, _ := Decode("9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA")
	key, err := P256FromCoordinates(x, y)
	if err != nil {
		t.Fatal(err)
	}
	if tp := key.Thumbprint(); tp != "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" {
		t.Fatalf("thumbprint: %s", tp)
	}
}
