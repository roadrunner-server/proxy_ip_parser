package proxy

import (
	"io"
	"net/http"
	"testing"

	"tests/helpers"

	httpPlugin "github.com/roadrunner-server/http/v6"
	proxy "github.com/roadrunner-server/proxy_ip_parser/v6"
	"github.com/roadrunner-server/server/v6"
	"github.com/stretchr/testify/require"
)

const (
	xffAddr       = "127.0.0.1:12311"
	forwardedAddr = "127.0.0.1:12811"
	allowlistAddr = "127.0.0.1:12411"

	// loopback is what the worker reports when the middleware declines to
	// trust the proxy header and falls back to the real peer address.
	loopback = "127.0.0.1"
)

func proxyPlugins() []any {
	return []any{&server.Plugin{}, &httpPlugin.Plugin{}, &proxy.Plugin{}}
}

// resolvedIP sends a request carrying the given proxy header and returns the
// REMOTE_ADDR the PHP worker saw, which is what the middleware resolved.
func resolvedIP(t *testing.T, addr, header, value string) string {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"?hello=world", nil)
	require.NoError(t, err)
	req.Header.Set(header, value)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer func() { require.NoError(t, resp.Body.Close()) }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	return string(body)
}

// TestXForwardedFor covers the X-Forwarded-For path. The peer is loopback and
// loopback is a trusted subnet, so the left-most element of the header is
// adopted. parseXFF does not validate that the element is an IP, so a
// non-address value is passed through to the worker unchanged.
func TestXForwardedFor(t *testing.T) {
	helpers.Start(t, "configs/.rr-http-xff.yaml", proxyPlugins(), helpers.WithTCPProbe(xffAddr))

	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"public address is adopted", "9.10.11.12", "9.10.11.12"},
		{"trusted loopback stays loopback", loopback, loopback},
		{"left-most element of a list wins", "9.10.11.12, 172.16.0.1", "9.10.11.12"},
		{"non-address value is taken verbatim", "foo.workstation", "foo.workstation"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, resolvedIP(t, xffAddr, "X-Forwarded-For", tc.header))
		})
	}
}

// TestForwarded covers the RFC 7239 Forwarded header, whose for= element the
// plugin extracts with a regex.
func TestForwarded(t *testing.T) {
	helpers.Start(t, "configs/.rr-http-f.yaml", proxyPlugins(), helpers.WithTCPProbe(forwardedAddr))

	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"for element is extracted", "by=foo;for=3.11.0.1;host=foo.workstation;proto=http", "3.11.0.1"},
		{"trusted loopback stays loopback", "by=foo;for=127.0.0.1;host=foo.workstation;proto=http", loopback},
		{"value without for= falls back to the peer", "foo.workstation", loopback},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, resolvedIP(t, forwardedAddr, "Forwarded", tc.header))
		})
	}
}

// TestTrustedHeadersAllowlist pins the allowlist to X-Real-Ip, so that header is
// honored and every other proxy header is ignored.
func TestTrustedHeadersAllowlist(t *testing.T) {
	helpers.Start(t, "configs/.rr-http-headers.yaml", proxyPlugins(), helpers.WithTCPProbe(allowlistAddr))

	t.Run("listed header is honored", func(t *testing.T) {
		require.Equal(t, "5.6.7.8", resolvedIP(t, allowlistAddr, "X-Real-Ip", "5.6.7.8"))
	})

	t.Run("unlisted header is ignored", func(t *testing.T) {
		require.Equal(t, loopback, resolvedIP(t, allowlistAddr, "X-Forwarded-For", "5.6.7.8"))
	})

	t.Run("unlisted Forwarded is ignored", func(t *testing.T) {
		require.Equal(t, loopback, resolvedIP(t, allowlistAddr, "Forwarded", "for=5.6.7.8"))
	})
}
