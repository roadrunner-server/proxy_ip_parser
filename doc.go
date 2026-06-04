// Package proxy provides an HTTP middleware plugin for RoadRunner that resolves
// the real client IP address from proxy headers (Forwarded, X-Forwarded-For,
// X-Real-Ip, True-Client-Ip, Cf-Connecting-Ip) when requests arrive through
// trusted subnets.
//
// The headers consulted are configurable via http.trusted_headers: an ordered
// allowlist where the first non-empty match wins. When it is unset, the headers
// above are used in that default order.
package proxy
