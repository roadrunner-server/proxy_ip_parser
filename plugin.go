package proxy

import (
	"net"
	"net/http"
	"regexp"
	"strings"

	rrcontext "github.com/roadrunner-server/context"
	"github.com/roadrunner-server/errors"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

const (
	name      string = "proxy_ip_parser"
	configKey string = "http.trusted_subnets"
	xff       string = "X-Forwarded-For"
	xrip      string = "X-Real-Ip"
	tcip      string = "True-Client-Ip"
	cfip      string = "Cf-Connecting-Ip"
	forwarded string = "Forwarded"
)

var (
	forwardedRegex = regexp.MustCompile(`(?i)(?:for=)([^(;|,| )]+)`)
)

type Logger interface {
	NamedLogger(name string) *zap.Logger
}

type Configurer interface {
	// UnmarshalKey takes a single key and unmarshal it into a Struct.
	UnmarshalKey(name string, out any) error
	// Has checks if a config section exists.
	Has(name string) bool
}

type Plugin struct {
	cfg     *Config
	log     *zap.Logger
	trusted []*net.IPNet
}

func (p *Plugin) Init(cfg Configurer, l Logger) error {
	const op = errors.Op("proxy_ip_parser_init")

	if !cfg.Has(configKey) {
		return errors.E(errors.Disabled)
	}

	p.cfg = &Config{}
	err := cfg.UnmarshalKey(configKey, &p.cfg.TrustedSubnets)
	if err != nil {
		return errors.E(op, err)
	}

	if len(p.cfg.TrustedSubnets) == 0 {
		return errors.E(errors.Disabled)
	}

	p.log = l.NamedLogger(name)

	p.trusted = make([]*net.IPNet, len(p.cfg.TrustedSubnets))
	for i := range p.cfg.TrustedSubnets {
		_, ipNet, err := net.ParseCIDR(p.cfg.TrustedSubnets[i])
		if err != nil {
			return errors.E(op, err)
		}

		p.trusted[i] = ipNet
	}

	return nil
}

func (p *Plugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if val, ok := r.Context().Value(rrcontext.OtelTracerNameKey).(string); ok {
			tp := trace.SpanFromContext(r.Context()).TracerProvider()
			ctx, span := tp.Tracer(val).Start(r.Context(), name)
			defer span.End()
			r = r.WithContext(ctx)
		}

		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ip := net.ParseIP(host)
		for i := range p.trusted {
			if p.trusted[i].Contains(ip) {
				resolvedIP := p.resolveIP(r.Header)
				if resolvedIP != "" {
					r.RemoteAddr = resolvedIP
				}
				break
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (p *Plugin) Name() string {
	return name
}

// get real ip passing multiple proxy
func (p *Plugin) resolveIP(headers http.Header) string {
	// new Forwarded header
	// https://datatracker.ietf.org/doc/html/rfc7239
	if fwd := headers.Get(forwarded); fwd != "" {
		if get := forwardedRegex.FindStringSubmatch(fwd); len(get) > 1 {
			// IPv6 -> It is important to note that an IPv6 address and any nodename with
			// node-port specified MUST be quoted
			// we should trim the "
			return strings.Trim(get[1], `"`)
		}
		// XFF parse
	} else if fwd := headers.Get(xff); fwd != "" {
		s := strings.Index(fwd, ",")
		if s == -1 {
			return fwd
		}

		if len(fwd) < s {
			return ""
		}

		return fwd[:s]
		// next -> X-Real-Ip
	} else if fwd := headers.Get(xrip); fwd != "" {
		return fwd
	}

	// The logic here is the following:
	// CloudFlare headers
	// True-Client-IP is a general CF header in which copied information from X-Real-Ip in CF.
	// CF-Connecting-IP is an Enterprise feature and we check it last in order.
	// This operations are near O(1) because Headers struct are the map type -> type MIMEHeader map[string][]string
	if fwd := headers.Get(tcip); fwd != "" {
		return fwd
	}

	if fwd := headers.Get(cfip); fwd != "" {
		return fwd
	}

	return ""
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
