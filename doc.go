// Package proxy provides an HTTP middleware plugin for RoadRunner that resolves
// the real client IP address from proxy headers (X-Forwarded-For, X-Real-Ip,
// True-Client-Ip, CF-Connecting-Ip, Forwarded) when requests arrive through
// trusted subnets.
package proxy
