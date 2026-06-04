package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	rrcontext "github.com/roadrunner-server/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestMiddlewareSpanEndsBeforeNextHandler(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

	_, ipNet, err := net.ParseCIDR("127.0.0.0/8")
	require.NoError(t, err)

	p := &Plugin{trusted: []*net.IPNet{ipNet}, prop: propagation.TraceContext{}}

	// "next" handler that creates its own span to mark when downstream starts
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, span := tp.Tracer("test").Start(r.Context(), "nextHandler")
		defer span.End()
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Middleware(next)

	// create a parent span so the middleware finds a TracerProvider in context
	ctx, parentSpan := tp.Tracer("test").Start(t.Context(), "parent")
	defer parentSpan.End()

	// set OtelTracerNameKey so the middleware activates its OTel branch
	ctx = context.WithValue(ctx, rrcontext.OtelTracerNameKey, "test-tracer")

	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// flush and collect spans
	require.NoError(t, tp.ForceFlush(t.Context()))

	spans := exporter.GetSpans()

	var middlewareSpan, nextSpan tracetest.SpanStub
	for _, s := range spans {
		switch s.Name {
		case name:
			middlewareSpan = s
		case "nextHandler":
			nextSpan = s
		}
	}

	require.NotEmpty(t, middlewareSpan.Name, "proxy_ip_parser middleware span was not found in exported spans")
	require.NotEmpty(t, nextSpan.Name, "next handler span was not found in exported spans")
	require.NotZero(t, middlewareSpan.EndTime, "proxy_ip_parser span should have ended")
	require.NotZero(t, nextSpan.StartTime, "next handler span should have started")

	assert.True(t,
		!middlewareSpan.EndTime.After(nextSpan.StartTime),
		"proxy_ip_parser span must end before (or at) the next handler span starts: middleware.End=%v, next.Start=%v",
		middlewareSpan.EndTime, nextSpan.StartTime,
	)
}

func TestMiddlewareSpanEndsOnError(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

	p := &Plugin{prop: propagation.TraceContext{}}

	nextCalled := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		nextCalled = true
	})

	handler := p.Middleware(next)

	ctx, parentSpan := tp.Tracer("test").Start(t.Context(), "parent")
	defer parentSpan.End()

	ctx = context.WithValue(ctx, rrcontext.OtelTracerNameKey, "test-tracer")

	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	req.RemoteAddr = "invalid-addr" // triggers SplitHostPort error
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.False(t, nextCalled, "next handler must not be called on error")
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// flush and collect spans
	require.NoError(t, tp.ForceFlush(t.Context()))

	spans := exporter.GetSpans()

	var middlewareSpan tracetest.SpanStub
	for _, s := range spans {
		if s.Name == name {
			middlewareSpan = s
		}
	}

	require.NotEmpty(t, middlewareSpan.Name, "proxy_ip_parser span was not found in exported spans")
	require.NotZero(t, middlewareSpan.EndTime, "proxy_ip_parser span should have ended on error path")
}

func TestMiddlewareNoSpanWithoutOtelContext(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

	_, ipNet, err := net.ParseCIDR("127.0.0.0/8")
	require.NoError(t, err)

	p := &Plugin{trusted: []*net.IPNet{ipNet}}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Middleware(next)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusOK, rec.Code)

	require.NoError(t, tp.ForceFlush(t.Context()))

	// no span should be created when OTel context is absent
	for _, s := range exporter.GetSpans() {
		assert.NotEqual(t, name, s.Name, "no proxy_ip_parser span should exist without OTel context")
	}
}
