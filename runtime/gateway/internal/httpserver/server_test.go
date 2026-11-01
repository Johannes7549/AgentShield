package httpserver

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentshield/agentshield/runtime/gateway/internal/config"
)

func testConfig(t *testing.T) config.Config {
	t.Helper()
	cfg, err := config.Load(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestLiveAndReady(t *testing.T) {
	server := New(testConfig(t), nil, nil)
	live := httptest.NewRecorder()
	server.Handler.ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if live.Code != http.StatusOK {
		t.Fatalf("live status = %d", live.Code)
	}
	if !strings.Contains(live.Body.String(), `"authorization":"not_configured"`) {
		t.Fatalf("live body = %s", live.Body.String())
	}
	if live.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff header")
	}

	ready := httptest.NewRecorder()
	server.Handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready status = %d", ready.Code)
	}
}

func TestAuthorizeWithoutDependenciesIsNotAllow(t *testing.T) {
	server := New(testConfig(t), nil, nil)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/runtime/authorize", strings.NewReader(`{}`))
	server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), `"outcome":"allow"`) {
		t.Fatalf("unconfigured authorize returned allow: %s", response.Body.String())
	}
}

func TestNotFoundDoesNotEchoRequest(t *testing.T) {
	server := New(testConfig(t), nil, nil)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/health/live?token=super-secret-value", nil)
	request.URL.Path = "/nope"
	request.URL.RawQuery = "token=super-secret-value"
	server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "super-secret-value") {
		t.Fatalf("response echoed the request: %s", response.Body.String())
	}
}

func TestLimitedBody(t *testing.T) {
	body := bytes.Repeat([]byte("a"), 64)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/runtime/authorize", bytes.NewReader(body))
	response := httptest.NewRecorder()
	reader := LimitedBody(response, request, 16)
	_, err := io.ReadAll(reader)
	if err == nil {
		t.Fatal("expected the body limit to fail")
	}
}
