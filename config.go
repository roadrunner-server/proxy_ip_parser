package proxy

type Config struct {
	// TrustedSubnets declare IP subnets which are allowed to set ip using X-Real-Ip and X-Forwarded-For
	TrustedSubnets []string `mapstructure:"trusted_subnets"`
	// TrustedHeaders is the ordered allowlist of headers consulted to resolve the
	// real client IP. When empty, the built-in default order is used.
	TrustedHeaders []string `mapstructure:"trusted_headers"`
}
