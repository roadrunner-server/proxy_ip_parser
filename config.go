package proxy_ip_parser

import (
	"net"
)

// Cidrs is a slice of IPNet addresses
type Cidrs []*net.IPNet

// IsTrusted checks if the ip address exists in the provided in the config addresses
func (c *Cidrs) IsTrusted(ip string) bool {
	if len(*c) == 0 {
		return false
	}

	i := net.ParseIP(ip)
	if i == nil {
		return false
	}

	for _, cird := range *c {
		if cird.Contains(i) {
			return true
		}
	}

	return false
}

// ParseCIDRs parse IPNet addresses and return slice of its
func ParseCIDRs(subnets []string) (Cidrs, error) {
	c := make(Cidrs, 0, len(subnets))
	for _, cidr := range subnets {
		_, cr, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}

		c = append(c, cr)
	}

	return c, nil
}

type Config struct {
	// TrustedSubnets declare IP subnets which are allowed to set ip using X-Real-Ip and X-Forwarded-For
	TrustedSubnets []string `mapstructure:"trusted_subnets"`

	// slice of net.IPNet
	//Cidrs Cidrs `mapstructure:"cidrs"`
}

func (c *Config) InitDefaults() error {
	//var err error
	//c.Cidrs, err = ParseCIDRs(c.TrustedSubnets)
	//if err != nil {
	//	return err
	//}

	return nil
}
