package proxy

import (
	"net"
)

// Cidrs is a slice of IPNet addresses
type Cidrs []*net.IPNet

type Config struct {
	// TrustedSubnets declare IP subnets which are allowed to set ip using X-Real-Ip and X-Forwarded-For
	TrustedSubnets []string `mapstructure:"trusted_subnets"`
}
