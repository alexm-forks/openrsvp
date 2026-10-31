package event

import "testing"

func TestShareTokenLength(t *testing.T) {
	tok, err := generateBase62Token(ShareTokenLength)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 16 {
		t.Fatalf("share token length %d, want 16", len(tok))
	}
}
