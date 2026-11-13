// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"satellion.com/passmcp-sdk-go/oauth"
)

// MCP Streamable HTTP routing and session headers.
const (
	HeaderProtocolVersion = "MCP-Protocol-Version"
	HeaderMethod          = "MCP-Method"
	HeaderSessionID       = "Mcp-Session-Id"
)

// HTTPError describes a non-2xx Streamable HTTP transport failure.
type HTTPError struct {
	StatusCode      int
	WWWAuthenticate string
}

// Error formats the HTTP status code.
func (e *HTTPError) Error() string {
	return fmt.Sprintf("mcp: unexpected HTTP status %d", e.StatusCode)
}

// ServeHTTP implements Streamable HTTP for MCP: Origin allowlist, optional
// RFC 9728 Bearer authentication, POST-only method guard, mirrored routing
// header validation (-32020), optional Mcp-Session-Id lifecycle, 202 Accepted
// for notifications, and 404 Not Found for -32601 on stateless 2026-07-28.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.originGuard.Allowed(r.Header.Get("Origin")) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	if !s.authorizeHTTP(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodyBytes))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.servePOSTBody(w, r, body)
}

func (s *Server) authorizeHTTP(w http.ResponseWriter, r *http.Request) bool {
	s.mu.RLock()
	authFn := s.bearerAuth
	resMeta := s.resourceMetadataURL
	s.mu.RUnlock()
	if authFn == nil {
		return true
	}
	token, ok := extractBearerToken(r.Header.Get("Authorization"))
	if ok && authFn(token) {
		return true
	}
	challenge := oauth.BearerChallenge{ResourceMetadata: resMeta}
	w.Header().Set("WWW-Authenticate", challenge.HeaderValue())
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

func extractBearerToken(header string) (string, bool) {
	trimmed := strings.TrimSpace(header)
	if len(trimmed) <= 7 || !strings.EqualFold(trimmed[:7], "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(trimmed[7:])
	return tok, tok != ""
}

func (s *Server) servePOSTBody(w http.ResponseWriter, r *http.Request, body []byte) {
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONRPCError(w, http.StatusBadRequest, json.RawMessage("null"), CodeParseError, "Parse error")
		return
	}
	if !s.validateHTTPHeaders(w, r, req) {
		return
	}
	if !s.enforceHTTPSession(w, r, req) {
		return
	}
	resp, err := s.HandleJSON(r.Context(), body)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if len(resp) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	status := s.httpStatusForResponse(resp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(resp)
}

func (s *Server) validateHTTPHeaders(w http.ResponseWriter, r *http.Request, req rpcRequest) bool {
	hdrVer := strings.TrimSpace(r.Header.Get(HeaderProtocolVersion))
	if hdrVer != "" && !isSupportedRevision(hdrVer) {
		writeJSONRPCError(w, http.StatusBadRequest, normalizeID(req.ID), CodeUnsupportedProtocolVersion, "unsupported MCP-Protocol-Version")
		return false
	}
	hdrMethod := strings.TrimSpace(r.Header.Get(HeaderMethod))
	if hdrMethod != "" && hdrMethod != req.Method {
		writeJSONRPCError(w, http.StatusBadRequest, normalizeID(req.ID), CodeHeaderMismatch, "HeaderMismatch: MCP-Method disagrees with JSON-RPC method")
		return false
	}
	return true
}

func isSupportedRevision(rev string) bool {
	return rev == Revision20260728 || rev == Revision20251125 || rev == Revision20250618
}

func (s *Server) enforceHTTPSession(w http.ResponseWriter, r *http.Request, req rpcRequest) bool {
	s.mu.RLock()
	enabled := s.sessionsEnabled
	s.mu.RUnlock()
	if !enabled {
		return true
	}
	if req.Method == "initialize" && len(req.ID) > 0 {
		w.Header().Set(HeaderSessionID, s.issueSessionID())
		return true
	}
	sid := strings.TrimSpace(r.Header.Get(HeaderSessionID))
	if !s.hasSession(sid) {
		http.Error(w, "unknown or missing Mcp-Session-Id", http.StatusNotFound)
		return false
	}
	return true
}

func (s *Server) httpStatusForResponse(resp []byte) int {
	if s.Revision() != Revision20260728 {
		return http.StatusOK
	}
	var env struct {
		Error *RPCError `json:"error"`
	}
	if json.Unmarshal(resp, &env) == nil && env.Error != nil && env.Error.Code == CodeMethodNotFound {
		return http.StatusNotFound
	}
	return http.StatusOK
}

func writeJSONRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, msg string) {
	payload, _ := marshalError(id, code, msg, nil)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

// HTTPTransportOption configures a client HTTPTransport.
type HTTPTransportOption func(*HTTPTransport)

// WithBearerToken attaches an Authorization: Bearer header to outgoing HTTP requests.
func WithBearerToken(token string) HTTPTransportOption {
	return func(t *HTTPTransport) {
		t.bearerToken = strings.TrimSpace(token)
	}
}

// WithSessionID seeds the initial Mcp-Session-Id header sent on HTTP requests.
func WithSessionID(sessionID string) HTTPTransportOption {
	return func(t *HTTPTransport) {
		t.sessionID = strings.TrimSpace(sessionID)
	}
}

// WithStatelessHeaders mirrors MCP-Protocol-Version and MCP-Method onto every
// outgoing HTTP request per the 2026-07-28 HTTP binding.
func WithStatelessHeaders(revision string) HTTPTransportOption {
	return func(t *HTTPTransport) {
		t.statelessRevision = strings.TrimSpace(revision)
	}
}

// HTTPTransport implements Dispatcher over Streamable HTTP POST.
type HTTPTransport struct {
	endpoint          string
	client            *http.Client
	bearerToken       string
	statelessRevision string

	mu        sync.RWMutex
	sessionID string
}

// NewHTTPTransport constructs a Streamable HTTP client transport.
func NewHTTPTransport(endpoint string, roundTripper http.RoundTripper, opts ...HTTPTransportOption) *HTTPTransport {
	t := &HTTPTransport{
		endpoint: endpoint,
		client:   &http.Client{Transport: roundTripper},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(t)
		}
	}
	return t
}

// SessionID returns the most recent Mcp-Session-Id observed or configured.
func (t *HTTPTransport) SessionID() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.sessionID
}

// HandleJSON sends a single JSON-RPC 2.0 request or notification over HTTP POST.
func (t *HTTPTransport) HandleJSON(ctx context.Context, raw []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	t.applyRequestHeaders(req, raw)
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if sid := strings.TrimSpace(resp.Header.Get(HeaderSessionID)); sid != "" {
		t.mu.Lock()
		t.sessionID = sid
		t.mu.Unlock()
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRequestBodyBytes))
	if err != nil {
		return nil, err
	}
	return decodeHTTPResponse(resp, body)
}

func (t *HTTPTransport) applyRequestHeaders(req *http.Request, raw []byte) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if t.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+t.bearerToken)
	}
	if sid := t.SessionID(); sid != "" {
		req.Header.Set(HeaderSessionID, sid)
	}
	if t.statelessRevision != "" {
		req.Header.Set(HeaderProtocolVersion, t.statelessRevision)
		var peek struct {
			Method string `json:"method"`
		}
		if json.Unmarshal(raw, &peek) == nil && peek.Method != "" {
			req.Header.Set(HeaderMethod, peek.Method)
		}
	}
}

func decodeHTTPResponse(resp *http.Response, body []byte) ([]byte, error) {
	if resp.StatusCode == http.StatusAccepted {
		return nil, nil
	}
	if resp.StatusCode == http.StatusOK {
		return body, nil
	}
	if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusNotFound) &&
		strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") && len(body) > 0 {
		return body, nil
	}
	return nil, &HTTPError{
		StatusCode:      resp.StatusCode,
		WWWAuthenticate: resp.Header.Get("WWW-Authenticate"),
	}
}
