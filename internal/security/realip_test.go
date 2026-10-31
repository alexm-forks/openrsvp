package security

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustPrefixes parses CIDR strings the way config.Load does.
func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()

	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		require.NoError(t, err, "test prefix %q must parse", cidr)
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

// serveRealIP runs the middleware and returns the RemoteAddr the next
// handler observes.
func serveRealIP(trusted []netip.Prefix, remoteAddr string, forwarded []string, realIP string) string {
	var seen string
	handler := RealIPMiddleware(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.RemoteAddr
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	for _, value := range forwarded {
		req.Header.Add("X-Forwarded-For", value)
	}
	if realIP != "" {
		req.Header.Set("X-Real-IP", realIP)
	}

	handler.ServeHTTP(httptest.NewRecorder(), req)
	return seen
}

func TestRealIPMiddleware(t *testing.T) {
	tests := []struct {
		name       string
		trusted    []string
		remoteAddr string
		forwarded  []string
		realIP     string
		want       string
	}{
		{
			name:       "untrusted peer cannot spoof",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "203.0.113.9:1234",
			forwarded:  []string{"1.2.3.4"},
			want:       "203.0.113.9:1234",
		},
		{
			name:       "trusted peer sets the forwarded address",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			forwarded:  []string{"1.2.3.4"},
			want:       "1.2.3.4:1234",
		},
		{
			name:       "rightmost untrusted entry wins",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			forwarded:  []string{"1.2.3.4, 5.6.7.8, 10.0.0.9"},
			want:       "5.6.7.8:1234",
		},
		{
			name:       "all entries trusted uses the leftmost",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			forwarded:  []string{"10.0.0.5, 10.0.0.6"},
			want:       "10.0.0.5:1234",
		},
		{
			name:       "multiple header lines are joined",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			forwarded:  []string{"1.2.3.4", "5.6.7.8, 10.0.0.9"},
			want:       "5.6.7.8:1234",
		},
		{
			name:       "ipv6 peer and ipv6 forwarded address",
			trusted:    []string{"2001:db8::/32"},
			remoteAddr: "[2001:db8::1]:4444",
			forwarded:  []string{"2001:db8:1::9, 2606:4700::1"},
			want:       "[2606:4700::1]:4444",
		},
		{
			name:       "malformed entries fall back to the peer",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			forwarded:  []string{"not-an-ip, still-not-an-ip"},
			want:       "10.0.0.1:1234",
		},
		{
			name:       "x-real-ip accepted from a trusted peer",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			realIP:     "1.2.3.4",
			want:       "1.2.3.4:1234",
		},
		{
			name:       "x-real-ip ignored from an untrusted peer",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "203.0.113.9:1234",
			realIP:     "1.2.3.4",
			want:       "203.0.113.9:1234",
		},
		{
			name:       "malformed forwarded header falls back to x-real-ip",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			forwarded:  []string{"garbage"},
			realIP:     "1.2.3.4",
			want:       "1.2.3.4:1234",
		},
		{
			name:       "no trusted prefixes leaves the address alone",
			remoteAddr: "10.0.0.1:1234",
			forwarded:  []string{"1.2.3.4"},
			realIP:     "5.6.7.8",
			want:       "10.0.0.1:1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trusted := mustPrefixes(t, tt.trusted...)
			got := serveRealIP(trusted, tt.remoteAddr, tt.forwarded, tt.realIP)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRealIPMiddlewareEntryCap(t *testing.T) {
	trusted := mustPrefixes(t, "10.0.0.0/8")

	// More than maxForwardedEntries trusted addresses, then the client the
	// proxy appended last. The window is read from the right, so the client
	// is found.
	entries := make([]string, 0, maxForwardedEntries+11)
	for i := 0; i < maxForwardedEntries+10; i++ {
		entries = append(entries, fmt.Sprintf("10.1.0.%d", i))
	}
	entries = append(entries, "203.0.113.9")

	got := serveRealIP(trusted, "10.0.0.1:1234", []string{strings.Join(entries, ", ")}, "")
	assert.Equal(t, "203.0.113.9:1234", got)

	// All entries trusted: the leftmost one inside the window wins.
	got = serveRealIP(trusted, "10.0.0.1:1234", []string{strings.Join(entries[:maxForwardedEntries+10], ", ")}, "")
	assert.Equal(t, "10.1.0.10:1234", got)
}

// A client sends a long X-Forwarded-For of forged entries so that the entry
// its proxy appends falls past the parse limit. The forged address must not
// become the client address, or the client could pick any rate limit bucket.
func TestRealIPMiddlewareForgedPaddingIgnored(t *testing.T) {
	trusted := mustPrefixes(t, "10.0.0.1/32")

	forged := strings.Repeat("junk,", maxForwardedEntries-1) + "6.6.6.6"
	cases := map[string][]string{
		// nginx $proxy_add_x_forwarded_for appends to the client's value.
		"single header": {forged + ", 203.0.113.9"},
		// Some proxies add a second header line instead.
		"separate header": {forged, "203.0.113.9"},
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			got := serveRealIP(trusted, "10.0.0.1:1234", header, "")
			assert.Equal(t, "203.0.113.9:1234", got)
		})
	}
}
