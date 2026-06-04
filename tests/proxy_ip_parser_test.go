package proxy_ip_parser //nolint:stylecheck

import (
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/roadrunner-server/config/v6"
	"github.com/roadrunner-server/endure/v2"
	httpPlugin "github.com/roadrunner-server/http/v6"
	"github.com/roadrunner-server/logger/v6"
	ipparser "github.com/roadrunner-server/proxy_ip_parser/v6"
	"github.com/roadrunner-server/server/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXFF(t *testing.T) {
	cont := endure.New(slog.LevelDebug)

	cfg := &config.Plugin{
		Version: "2024.2.0",
		Path:    "configs/.rr-http-xff.yaml",
	}

	err := cont.RegisterAll(
		cfg,
		&logger.Plugin{},
		&server.Plugin{},
		&ipparser.Plugin{},
		&httpPlugin.Plugin{},
	)
	assert.NoError(t, err)

	err = cont.Init()
	if err != nil {
		t.Fatal(err)
	}

	ch, err := cont.Serve()
	assert.NoError(t, err)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	wg := &sync.WaitGroup{}

	stopCh := make(chan struct{}, 1)

	wg.Go(func() {
		for {
			select {
			case e := <-ch:
				assert.Fail(t, "error", e.Error.Error())
				err = cont.Stop()
				if err != nil {
					assert.FailNow(t, "error", err.Error())
				}
			case <-sig:
				err = cont.Stop()
				if err != nil {
					assert.FailNow(t, "error", err.Error())
				}
				return
			case <-stopCh:
				// timeout
				err = cont.Stop()
				if err != nil {
					assert.FailNow(t, "error", err.Error())
				}
				return
			}
		}
	})

	time.Sleep(time.Second * 2)

	req, err := http.NewRequest("GET", "http://127.0.0.1:12311?hello=world", nil)
	assert.NoError(t, err)
	req.Header.Add("X-Forwarded-For", "127.0.0.1")

	r, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 201, r.StatusCode)

	err = r.Body.Close()
	assert.NoError(t, err)

	// ---

	req, err = http.NewRequest("GET", "http://127.0.0.1:12311?hello=world", nil)
	assert.NoError(t, err)
	req.Header.Add("X-Forwarded-For", "foo.workstation")

	r, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 201, r.StatusCode)

	err = r.Body.Close()
	assert.NoError(t, err)

	// ---

	req, err = http.NewRequest("GET", "http://127.0.0.1:12311?hello=world", nil)
	assert.NoError(t, err)
	req.Header.Add("X-Forwarded-For", "9.10.11.12")

	r, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 201, r.StatusCode)

	err = r.Body.Close()
	assert.NoError(t, err)

	stopCh <- struct{}{}
	wg.Wait()
}

func TestForwarded(t *testing.T) {
	cont := endure.New(slog.LevelDebug)

	cfg := &config.Plugin{
		Version: "2024.2.0",
		Path:    "configs/.rr-http-f.yaml",
	}

	err := cont.RegisterAll(
		cfg,
		&ipparser.Plugin{},
		&logger.Plugin{},
		&server.Plugin{},
		&httpPlugin.Plugin{},
	)
	assert.NoError(t, err)

	err = cont.Init()
	if err != nil {
		t.Fatal(err)
	}

	ch, err := cont.Serve()
	assert.NoError(t, err)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	wg := &sync.WaitGroup{}

	stopCh := make(chan struct{}, 1)

	wg.Go(func() {
		for {
			select {
			case e := <-ch:
				assert.Fail(t, "error", e.Error.Error())
				err = cont.Stop()
				if err != nil {
					assert.FailNow(t, "error", err.Error())
				}
			case <-sig:
				err = cont.Stop()
				if err != nil {
					assert.FailNow(t, "error", err.Error())
				}
				return
			case <-stopCh:
				// timeout
				err = cont.Stop()
				if err != nil {
					assert.FailNow(t, "error", err.Error())
				}
				return
			}
		}
	})

	time.Sleep(time.Second * 2)

	req, err := http.NewRequest("GET", "http://127.0.0.1:12811?hello=world", nil)
	assert.NoError(t, err)
	req.Header.Add("Forwarded", "foo.workstation")

	r, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 201, r.StatusCode)

	err = r.Body.Close()
	assert.NoError(t, err)

	// --

	req, err = http.NewRequest("GET", "http://127.0.0.1:12811?hello=world", nil)
	assert.NoError(t, err)
	req.Header.Add("Forwarded", "by=foo;for=127.0.0.1;host=foo.workstation;proto=http")

	r, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 201, r.StatusCode)

	err = r.Body.Close()
	assert.NoError(t, err)

	// --

	req, err = http.NewRequest("GET", "http://127.0.0.1:12811?hello=world", nil)
	assert.NoError(t, err)
	req.Header.Add("Forwarded", "by=foo;for=127.0.0.1;host=foo.workstation;proto=http")

	r, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 201, r.StatusCode)

	err = r.Body.Close()
	assert.NoError(t, err)

	// --

	req, err = http.NewRequest("GET", "http://127.0.0.1:12811?hello=world", nil)
	assert.NoError(t, err)
	req.Header.Add("Forwarded", "by=foo;for=3.11.0.1;host=foo.workstation;proto=http")

	r, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, 201, r.StatusCode)

	err = r.Body.Close()
	assert.NoError(t, err)

	stopCh <- struct{}{}
	wg.Wait()
}

// TestTrustedHeadersAllowlist verifies that, with trusted_headers: [ X-Real-Ip ],
// only X-Real-Ip is honored when resolving the client IP and X-Forwarded-For is
// ignored. The ip worker echoes REMOTE_ADDR so we can assert the resolved value.
func TestTrustedHeadersAllowlist(t *testing.T) {
	cont := endure.New(slog.LevelDebug)

	cfg := &config.Plugin{
		Version: "2024.2.0",
		Path:    "configs/.rr-http-headers.yaml",
	}

	err := cont.RegisterAll(
		cfg,
		&logger.Plugin{},
		&server.Plugin{},
		&ipparser.Plugin{},
		&httpPlugin.Plugin{},
	)
	assert.NoError(t, err)

	err = cont.Init()
	if err != nil {
		t.Fatal(err)
	}

	ch, err := cont.Serve()
	assert.NoError(t, err)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	wg := &sync.WaitGroup{}

	stopCh := make(chan struct{}, 1)

	wg.Go(func() {
		for {
			select {
			case e := <-ch:
				assert.Fail(t, "error", e.Error.Error())
				err = cont.Stop()
				if err != nil {
					assert.FailNow(t, "error", err.Error())
				}
			case <-sig:
				err = cont.Stop()
				if err != nil {
					assert.FailNow(t, "error", err.Error())
				}
				return
			case <-stopCh:
				// timeout
				err = cont.Stop()
				if err != nil {
					assert.FailNow(t, "error", err.Error())
				}
				return
			}
		}
	})

	time.Sleep(time.Second * 2)

	// X-Real-Ip is on the allowlist -> trusted, becomes REMOTE_ADDR.
	req, err := http.NewRequest("GET", "http://127.0.0.1:12411", nil)
	assert.NoError(t, err)
	req.Header.Set("X-Real-Ip", "5.6.7.8")

	r, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 200, r.StatusCode)

	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	assert.Equal(t, "5.6.7.8", string(body))
	assert.NoError(t, r.Body.Close())

	// ---

	// X-Forwarded-For is NOT on the allowlist -> ignored, REMOTE_ADDR stays the peer.
	req, err = http.NewRequest("GET", "http://127.0.0.1:12411", nil)
	assert.NoError(t, err)
	req.Header.Set("X-Forwarded-For", "5.6.7.8")

	r, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, 200, r.StatusCode)

	body, err = io.ReadAll(r.Body)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", string(body))
	assert.NoError(t, r.Body.Close())

	stopCh <- struct{}{}
	wg.Wait()
}
