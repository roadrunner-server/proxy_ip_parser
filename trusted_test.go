package proxy

import (
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

type headerTable struct {
	key      string // header key
	val      string // header val
	expected string // expected result
}

func TestIP(t *testing.T) {
	headers := []headerTable{
		{xff, "8.8.8.8", "8.8.8.8"},                                   // Single address
		{xff, "8.8.8.8, 8.8.4.4", "8.8.8.8"},                          // Multiple
		{xff, "8.8.8.8,8.8.4.4", "8.8.8.8"},                           // Multiple separated without space, ie https://cloud.google.com/load-balancing/docs/https#x-forwarded-for_header
		{xff, "[2001:db8:cafe::17]:4711", "[2001:db8:cafe::17]:4711"}, // IPv6 address
		{xff, "", ""},                                                  // None
		{xrip, "8.8.8.8", "8.8.8.8"},                                   // Single address
		{xrip, "8.8.8.8, 8.8.4.4", "8.8.8.8, 8.8.4.4"},                 // Multiple
		{xrip, "[2001:db8:cafe::17]:4711", "[2001:db8:cafe::17]:4711"}, // IPv6 address
		{xrip, "", ""},                                                 // None
		{cfip, "8.8.8.8", "8.8.8.8"},                                   // Single address
		{tcip, "8.8.8.8", "8.8.8.8"},                                   // Single address
		{forwarded, `for="_foo"`, "_foo"},                              // Hostname
		{forwarded, `For="[2001:db8:cafe::17]:4711`, `[2001:db8:cafe::17]:4711`},      // IPv6 address
		{forwarded, `for=192.0.2.60;proto=http;by=203.0.113.43`, `192.0.2.60`},        // Multiple params
		{forwarded, `for=192.0.2.43, for=198.51.100.17`, "192.0.2.43"},                // Multiple params
		{forwarded, `for="workstation.local",for=198.51.100.17`, "workstation.local"}, // Hostname
	}

	tr := &Plugin{resolvers: defaultResolvers()}
	for _, v := range headers {
		req := &http.Request{
			Header: http.Header{
				v.key: []string{v.val},
			}}
		res := tr.resolveIP(req.Header)
		if res != v.expected {
			t.Fatalf("wrong header for %s: got %s want %s", v.key, res,
				v.expected)
		}
	}
}

// header builds an http.Header from key/value pairs.
func header(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func resolverNames(rs []resolver) []string {
	out := make([]string, len(rs))
	for i := range rs {
		out[i] = rs[i].name
	}
	return out
}

// An allowlist consults only the configured headers; unlisted ones are ignored.
func TestResolveIPAllowlistIgnoresUnlisted(t *testing.T) {
	p := &Plugin{resolvers: buildResolvers([]string{xrip})}
	// X-Forwarded-For is present but not on the allowlist, so it is ignored.
	require.Equal(t, "9.9.9.9", p.resolveIP(header(xff, "8.8.8.8", xrip, "9.9.9.9")))
}

// The first header in the allowlist that yields a value wins.
func TestResolveIPOrderWins(t *testing.T) {
	h := header(xff, "1.1.1.1", xrip, "2.2.2.2")

	xripFirst := &Plugin{resolvers: buildResolvers([]string{xrip, xff})}
	require.Equal(t, "2.2.2.2", xripFirst.resolveIP(h))

	xffFirst := &Plugin{resolvers: buildResolvers([]string{xff, xrip})}
	require.Equal(t, "1.1.1.1", xffFirst.resolveIP(h))
}

// Custom (non-built-in) headers are taken verbatim.
func TestResolveIPCustomHeaderVerbatim(t *testing.T) {
	p := &Plugin{resolvers: buildResolvers([]string{"X-Client-Ip"})}
	require.Equal(t, "3.3.3.3", p.resolveIP(header("X-Client-Ip", "3.3.3.3")))
}

// A present but unparseable header falls through to the next resolver. The old
// if/else-if chain short-circuited here; the ordered chain keeps looking.
func TestResolveIPFallThroughOnParseFailure(t *testing.T) {
	p := &Plugin{resolvers: buildResolvers([]string{forwarded, xrip})}
	// "Forwarded" with no for= directive yields nothing, so X-Real-Ip is used.
	require.Equal(t, "8.8.8.8", p.resolveIP(header(forwarded, "by=203.0.113.43;proto=https", xrip, "8.8.8.8")))
}

func TestBuildResolvers(t *testing.T) {
	// trim, canonicalize, dedup, skip blanks
	rs := buildResolvers([]string{" x-real-ip ", "X-Real-Ip", "", "Cf-Connecting-Ip"})
	require.Equal(t, []string{xrip, cfip}, resolverNames(rs))

	// empty / all-blank input falls back to the default chain
	def := resolverNames(defaultResolvers())
	require.Equal(t, def, resolverNames(buildResolvers(nil)))
	require.Equal(t, def, resolverNames(buildResolvers([]string{"", "   "})))
}

func TestCidrsInRange(t *testing.T) {
	ipAddr := "62.76.33.22/22"

	ip, ipNet, err := net.ParseCIDR(ipAddr)
	require.NoError(t, err)

	addrs := make([]string, 0, 1024)

	for ipWithMask := ip.Mask(ipNet.Mask); ipNet.Contains(ipWithMask); inc(ipWithMask) {
		addrs = append(addrs, ip.String())
	}

	require.Len(t, addrs, 1024)
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
