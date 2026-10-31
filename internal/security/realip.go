package security

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// maxForwardedEntries is the largest number of X-Forwarded-For entries the
// middleware parses. A huge header cannot burn CPU.
const maxForwardedEntries = 50

// RealIPMiddleware returns chi-compatible middleware that replaces
// r.RemoteAddr with the client address reported by a trusted reverse proxy.
//
// The middleware reads X-Forwarded-For and X-Real-IP only when the peer
// address is inside one of the trusted prefixes. A direct client keeps its
// own address, so it cannot spoof a new rate limit bucket. The rewritten
// value keeps the host:port shape that downstream code expects.
func RealIPMiddleware(trusted []netip.Prefix) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if addr, ok := clientAddr(r, trusted); ok {
				r.RemoteAddr = addr
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientAddr returns the host:port form of the real client address. The
// second result is false when the headers give nothing usable, and the
// caller must then keep r.RemoteAddr unchanged.
func clientAddr(r *http.Request, trusted []netip.Prefix) (string, bool) {
	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", false
	}

	peer, err := netip.ParseAddr(host)
	if err != nil {
		return "", false
	}

	if !isTrustedAddr(peer.Unmap(), trusted) {
		return "", false
	}

	if addr, ok := forwardedAddr(r, trusted); ok {
		return net.JoinHostPort(addr.String(), port), true
	}

	// The peer is a directly connected trusted proxy, so accept X-Real-IP.
	realIP, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP")))
	if err != nil {
		return "", false
	}

	return net.JoinHostPort(realIP.Unmap().String(), port), true
}

// forwardedAddr picks the client address from the X-Forwarded-For header.
// It returns the rightmost entry that is not a trusted proxy, because an
// attacker controls every entry to the left of its own proxy hop. It returns
// the leftmost entry it read when all of them are trusted.
//
// The header is read from the right, and at most maxForwardedEntries entries
// are parsed. The entries a trusted proxy appends are on the right, so a long
// header of forged entries on the left cannot push them out of the window.
func forwardedAddr(r *http.Request, trusted []netip.Prefix) (netip.Addr, bool) {
	var (
		leftmost netip.Addr
		found    bool
		parsed   int
	)

	values := r.Header.Values("X-Forwarded-For")
	for v := len(values) - 1; v >= 0 && parsed < maxForwardedEntries; v-- {
		rest := values[v]
		for parsed < maxForwardedEntries {
			var entry string
			if i := strings.LastIndexByte(rest, ','); i >= 0 {
				entry, rest = rest[i+1:], rest[:i]
			} else {
				entry, rest = rest, ""
			}
			parsed++

			if addr, err := netip.ParseAddr(strings.TrimSpace(entry)); err == nil {
				addr = addr.Unmap()
				if !isTrustedAddr(addr, trusted) {
					return addr, true
				}
				leftmost, found = addr, true
			}

			if rest == "" {
				break
			}
		}
	}

	return leftmost, found
}

// isTrustedAddr reports whether addr is inside one of the trusted prefixes.
func isTrustedAddr(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, prefix := range trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
