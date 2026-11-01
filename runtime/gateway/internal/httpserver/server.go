package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/agentshield/agentshield/runtime/gateway/internal/authz"
	"github.com/agentshield/agentshield/runtime/gateway/internal/config"
	"github.com/agentshield/agentshield/runtime/gateway/internal/idgen"
	"github.com/agentshield/agentshield/runtime/identity"
	"github.com/agentshield/agentshield/runtime/policy-engine"
)

type Authorizer interface {
	Authorize(ctx context.Context, body []byte, headers authz.Headers) (authz.Result, error)
	Execute(ctx context.Context, body []byte, headers authz.Headers) (authz.ExecuteResult, error)
}

func New(cfg config.Config, authorizer Authorizer, ready func(context.Context) error) *http.Server {
	handler := &handler{cfg: cfg, authorizer: authorizer, ready: ready}
	return &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func LimitedBody(w http.ResponseWriter, r *http.Request, max int64) io.ReadCloser {
	return http.MaxBytesReader(w, r.Body, max)
}

type handler struct {
	cfg        config.Config
	authorizer Authorizer
	ready      func(context.Context) error
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/health/live":
		authorization := "not_configured"
		if h.authorizer != nil {
			authorization = "ok"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"service": config.ServiceName,
			"version": config.Version,
			"checks": map[string]string{
				"process":       "ok",
				"authorization": authorization,
			},
		})
	case r.Method == http.MethodGet && r.URL.Path == "/health/ready":
		h.serveReady(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/runtime/authorize":
		h.serveAuthorize(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/runtime/execute":
		h.serveExecute(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found", "not found")
	}
}

func (h *handler) serveReady(w http.ResponseWriter, r *http.Request) {
	if h.authorizer == nil || h.ready == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status":  "not_ready",
			"service": config.ServiceName,
			"version": config.Version,
			"reason":  "authorization dependencies are not configured",
			"checks": map[string]string{
				"authorization": "not_configured",
			},
		})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	if err := h.ready(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status":  "not_ready",
			"service": config.ServiceName,
			"version": config.Version,
			"reason":  "authorization dependencies are unavailable",
			"checks": map[string]string{
				"authorization": "unavailable",
			},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"service": config.ServiceName,
		"version": config.Version,
		"reason":  "dependencies answered",
		"checks": map[string]string{
			"process":       "ok",
			"authorization": "ok",
		},
	})
}

func (h *handler) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	if h.authorizer == nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "authorization is not configured")
		return
	}
	body, ok := readBody(w, r, h.cfg.MaxBodyBytes)
	if !ok {
		return
	}
	result, err := h.authorizer.Authorize(r.Context(), body, signatureHeaders(r))
	if err != nil {
		writeFailure(w, err)
		return
	}
	status := http.StatusOK
	if result.Outcome == string(policy.OutcomeDeny) {
		status = http.StatusForbidden
	}
	writeJSON(w, status, result)
}

func (h *handler) serveExecute(w http.ResponseWriter, r *http.Request) {
	if h.authorizer == nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "authorization is not configured")
		return
	}
	body, ok := readBody(w, r, h.cfg.MaxBodyBytes)
	if !ok {
		return
	}
	result, err := h.authorizer.Execute(r.Context(), body, signatureHeaders(r))
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func readBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, bool) {
	defer r.Body.Close()
	body, err := io.ReadAll(LimitedBody(w, r, max))
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "request body is invalid")
		return nil, false
	}
	return body, true
}

func signatureHeaders(r *http.Request) authz.Headers {
	return authz.Headers{
		AgentID:       r.Header.Get(identity.HeaderAgentID),
		Timestamp:     r.Header.Get(identity.HeaderTimestamp),
		Nonce:         r.Header.Get(identity.HeaderNonce),
		Signature:     r.Header.Get(identity.HeaderSignature),
		Authorization: r.Header.Get("Authorization"),
	}
}

func writeFailure(w http.ResponseWriter, err error) {
	var failure *authz.Failure
	if errors.As(err, &failure) {
		writeError(w, failure.Status, failure.Code, failure.Message)
		return
	}
	writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
}

func writeError(w http.ResponseWriter, status int, code string, message string) {
	requestID, err := idgen.New()
	if err != nil {
		requestID = "00000000-0000-4000-8000-000000000000"
	}
	writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"code":       code,
			"message":    message,
			"request_id": requestID,
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(body)
}
