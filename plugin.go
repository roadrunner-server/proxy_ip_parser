package proxy

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"

	rrcontext "github.com/roadrunner-server/context"
	"github.com/roadrunner-server/errors"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	jprop "go.opentelemetry.io/contrib/propagators/jaeger"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.20.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	name       string = "proxy_ip_parser"
	configKey  string = "http.trusted_subnets"
	headersKey string = "http.trusted_headers"
	xff        string = "X-Forwarded-For"
	xrip       string = "X-Real-Ip"
	tcip       string = "True-Client-Ip"
	cfip       string = "Cf-Connecting-Ip"
	forwarded  string = "Forwarded"
)

var forwardedRegex = regexp.MustCompile(`(?i)(?:for=)([^(;|,| )]+)`)

type Logger interface {
	NamedLogger(name string) *slog.Logger
}

type Configurer interface {
	// UnmarshalKey takes a single key and unmarshal it into a Struct.
	UnmarshalKey(name string, out any) error
	// Has checks if a config section exists.
	Has(name string) bool
}

type Plugin struct {
	cfg       *Config
	log       *slog.Logger
	trusted   []*net.IPNet
	resolvers []resolver
	prop      propagation.TextMapPropagator
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
	p.prop = propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}, jprop.Jaeger{})

	p.trusted = make([]*net.IPNet, len(p.cfg.TrustedSubnets))
	for i := range p.cfg.TrustedSubnets {
		_, ipNet, err := net.ParseCIDR(p.cfg.TrustedSubnets[i])
		if err != nil {
			return errors.E(op, err)
		}

		p.trusted[i] = ipNet
	}

	if cfg.Has(headersKey) {
		if err := cfg.UnmarshalKey(headersKey, &p.cfg.TrustedHeaders); err != nil {
			return errors.E(op, err)
		}
	}
	p.resolvers = buildResolvers(p.cfg.TrustedHeaders)

	return nil
}

func (p *Plugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var span trace.Span
		if val, ok := r.Context().Value(rrcontext.OtelTracerNameKey).(string); ok {
			tp := trace.SpanFromContext(r.Context()).TracerProvider()
			var ctx context.Context
			ctx, span = tp.Tracer(val, trace.WithSchemaURL(semconv.SchemaURL),
				trace.WithInstrumentationVersion(otelhttp.Version)).
				Start(r.Context(), name, trace.WithSpanKind(trace.SpanKindInternal))

			// inject
			p.prop.Inject(ctx, propagation.HeaderCarrier(r.Header))
			r = r.WithContext(ctx)
		}

		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			if span != nil {
				span.End()
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ip := net.ParseIP(host)
		for _, subnet := range p.trusted {
			if subnet.Contains(ip) {
				resolvedIP := p.resolveIP(r.Header)
				if resolvedIP != "" {
					r.RemoteAddr = resolvedIP
				}
				break
			}
		}

		// end span before calling next handler so it measures
		// only this middleware's processing time
		if span != nil {
			span.End()
		}

		next.ServeHTTP(w, r)
	})
}

func (p *Plugin) Name() string {
	return name
}

// resolver extracts a candidate client IP from a single header value.
type resolver struct {
	name  string // canonical header name, e.g. "X-Forwarded-For"
	parse func(string) string
}

// defaultResolvers returns the built-in resolution chain used when
// http.trusted_headers is not configured. True-Client-Ip and Cf-Connecting-Ip
// (CloudFlare) are checked last, matching their historical priority. The parser
// for each header comes from parserFor, the single source of that mapping.
func defaultResolvers() []resolver {
	chain := []string{forwarded, xff, xrip, tcip, cfip}
	resolvers := make([]resolver, len(chain))
	for i, h := range chain {
		resolvers[i] = resolver{h, parserFor(h)}
	}
	return resolvers
}

// buildResolvers turns the configured header allowlist into an ordered resolver
// chain. Entries are trimmed and canonicalized, blanks and duplicates dropped.
// An empty allowlist falls back to the default chain.
func buildResolvers(headers []string) []resolver {
	resolvers := make([]resolver, 0, len(headers))
	seen := make(map[string]struct{}, len(headers))

	for _, hdr := range headers {
		h := strings.TrimSpace(hdr)
		if h == "" {
			continue
		}

		canon := http.CanonicalHeaderKey(h)
		if _, ok := seen[canon]; ok {
			continue
		}

		seen[canon] = struct{}{}
		resolvers = append(resolvers, resolver{canon, parserFor(canon)})
	}

	if len(resolvers) == 0 {
		return defaultResolvers()
	}

	return resolvers
}

// parserFor selects the value parser for a canonical header name. The two
// structured headers keep dedicated parsers; everything else (including custom
// headers) is taken verbatim.
func parserFor(canon string) func(string) string {
	switch canon {
	case forwarded:
		return parseForwarded
	case xff:
		return parseXFF
	default:
		return parseVerbatim
	}
}

// parseForwarded extracts the "for=" target from an RFC 7239 Forwarded header.
// https://datatracker.ietf.org/doc/html/rfc7239
func parseForwarded(v string) string {
	if m := forwardedRegex.FindStringSubmatch(v); len(m) > 1 {
		// An IPv6 address (and any node-port) MUST be quoted, so trim the quotes.
		return strings.Trim(m[1], `"`)
	}

	return ""
}

// parseXFF takes the left-most address from an X-Forwarded-For list.
func parseXFF(v string) string {
	// Cut returns the whole string when no comma is present.
	before, _, _ := strings.Cut(v, ",")
	return before
}

// parseVerbatim returns the header value unchanged (X-Real-Ip, True-Client-Ip,
// Cf-Connecting-Ip and custom headers carry a single address).
func parseVerbatim(v string) string {
	return v
}

// resolveIP returns the first non-empty client IP parsed from the configured
// (or default) header chain.
func (p *Plugin) resolveIP(headers http.Header) string {
	for _, r := range p.resolvers {
		if raw := headers.Get(r.name); raw != "" {
			if ip := r.parse(raw); ip != "" {
				return ip
			}
		}
	}

	return ""
}
