package jose

import "testing"

func TestRejectsDuplicateKeys(t *testing.T) {
	_, err := Parse([]byte(`{"alg":"EdDSA","alg":"none"}`))
	if err == nil {
		t.Fatal("expected duplicate key error")
	}
	je, ok := err.(*JsonError)
	if !ok || je.Kind != "duplicate_key" || je.Name != "alg" {
		t.Fatalf("got %#v", err)
	}
}

func TestOnlyPlainIntegersAreInts(t *testing.T) {
	v, err := Parse([]byte("42"))
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := v.AsI64(); !ok || n != 42 {
		t.Fatalf("got %v %v", n, ok)
	}
	for _, s := range []string{"1.0", "1e3", "9223372036854775808"} {
		v, err := Parse([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := v.AsI64(); ok {
			t.Fatalf("%s should not be Int", s)
		}
	}
}

func TestDuplicateAfterUnescape(t *testing.T) {
	_, err := Parse([]byte(`{"a":1,"\u0061":2}`))
	if err == nil {
		t.Fatal("expected duplicate")
	}
}
