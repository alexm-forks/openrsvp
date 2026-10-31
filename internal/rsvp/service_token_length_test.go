package rsvp

import "testing"

func TestRSVPTokenLength(t *testing.T) {
	tok, err := generateBase62Token(RSVPTokenLength)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 22 {
		t.Fatalf("rsvp token length %d, want 22", len(tok))
	}
}
