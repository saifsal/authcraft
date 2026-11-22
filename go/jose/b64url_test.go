package jose

import "testing"

func TestRFC4648(t *testing.T) {
	cases := []struct{ plain, encoded string }{
		{"", ""},
		{"f", "Zg"},
		{"fo", "Zm8"},
		{"foo", "Zm9v"},
		{"foob", "Zm9vYg"},
		{"fooba", "Zm9vYmE"},
		{"foobar", "Zm9vYmFy"},
	}
	for _, c := range cases {
		if got := Encode([]byte(c.plain)); got != c.encoded {
			t.Fatalf("encode %q: got %q want %q", c.plain, got, c.encoded)
		}
		got, err := Decode(c.encoded)
		if err != nil || string(got) != c.plain {
			t.Fatalf("decode %q: got %q %v want %q", c.encoded, got, err, c.plain)
		}
	}
}

func TestRejectsPaddingAndNonCanonical(t *testing.T) {
	if _, err := Decode("Zg=="); err == nil {
		t.Fatal("expected padding rejection")
	}
	if _, err := Decode("A"); err == nil {
		t.Fatal("expected length rejection")
	}
	for _, s := range []string{"Zh", "Zi", "Zj", "Zm9"} {
		if _, err := Decode(s); err == nil {
			t.Fatalf("expected non-canonical rejection for %q", s)
		}
	}
}
