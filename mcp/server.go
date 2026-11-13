// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
)

// ToolHandler executes a registered MCP tool.
type ToolHandler func(ctx context.Context, args map[string]any) (CallToolResult, error)

// ResourceHandler reads the contents of a registered resource or template URI.
type ResourceHandler func(ctx context.Context, uri string) (ResourceContents, error)

// PromptHandler renders a registered prompt with caller arguments.
type PromptHandler func(ctx context.Context, args map[string]string) (GetPromptResult, error)

// BearerAuthenticator validates an HTTP Bearer access token.
type BearerAuthenticator func(token string) bool

// ServerOption configures a Server at construction time.
type ServerOption func(*Server)

type toolEntry struct {
	tool    Tool
	handler ToolHandler
}

type resourceEntry struct {
	resource Resource
	handler  ResourceHandler
}

type templateEntry struct {
	template ResourceTemplate
	handler  ResourceHandler
}

type promptEntry struct {
	prompt  Prompt
	handler PromptHandler
}

// Server is a capability-derived JSON-RPC 2.0 MCP server supporting in-memory,
// stdio, and Streamable HTTP transports.
type Server struct {
	mu                  sync.RWMutex
	info                ServerInfo
	revision            string
	instructions        string
	cacheHints          *CacheHints
	originGuard         *OriginGuard
	bearerAuth          BearerAuthenticator
	resourceMetadataURL string
	sessionsEnabled     bool
	sessions            map[string]struct{}

	toolOrder     []string
	tools         map[string]toolEntry
	resourceOrder []string
	resources     map[string]resourceEntry
	templates     []templateEntry
	promptOrder   []string
	prompts       map[string]promptEntry
}

// WithRevision sets the server's negotiated MCP protocol revision.
func WithRevision(revision string) ServerOption {
	return func(s *Server) {
		if strings.TrimSpace(revision) != "" {
			s.revision = revision
		}
	}
}

// WithCacheHints sets SEP-2549 list cache metadata emitted on 2026-07-28 lists.
func WithCacheHints(hints CacheHints) ServerOption {
	return func(s *Server) {
		copied := hints
		s.cacheHints = &copied
	}
}

// WithAllowedOrigins configures the HTTP Origin allowlist enforced by ServeHTTP.
func WithAllowedOrigins(origins ...string) ServerOption {
	return func(s *Server) {
		s.originGuard = NewOriginGuard(origins...)
	}
}

// WithInstructions sets optional human/model instructions returned on discovery.
func WithInstructions(instructions string) ServerOption {
	return func(s *Server) {
		s.instructions = instructions
	}
}

// WithBearerAuthenticator requires HTTP requests to carry a valid Bearer token
// and emits RFC 9728 WWW-Authenticate challenges on 401 Unauthorized responses.
func WithBearerAuthenticator(auth BearerAuthenticator, resourceMetadataURL string) ServerOption {
	return func(s *Server) {
		s.bearerAuth = auth
		s.resourceMetadataURL = strings.TrimSpace(resourceMetadataURL)
	}
}

// WithSessions enables MCP session-ID issuance on HTTP initialize and rejects
// unknown or missing Mcp-Session-Id headers with 404 Not Found.
func WithSessions(enabled bool) ServerOption {
	return func(s *Server) {
		s.sessionsEnabled = enabled
	}
}

// NewServer constructs a conforming MCP server defaulting to revision
// 2026-07-28, private zero-TTL SEP-2549 cache hints, and a strict empty
// OriginGuard allowlist.
func NewServer(info ServerInfo, opts ...ServerOption) *Server {
	defaultHints := CacheHints{TTLMs: 0, CacheScope: CacheScopePrivate}
	s := &Server{
		info:        info,
		revision:    Revision20260728,
		cacheHints:  &defaultHints,
		originGuard: NewOriginGuard(),
		sessions:    make(map[string]struct{}),
		tools:       make(map[string]toolEntry),
		resources:   make(map[string]resourceEntry),
		prompts:     make(map[string]promptEntry),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// Info returns the server's identity metadata.
func (s *Server) Info() ServerInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.info
}

// Revision returns the server's configured MCP protocol revision.
func (s *Server) Revision() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revision
}

// SetCacheHints validates and updates the server's SEP-2549 cache hints.
func (s *Server) SetCacheHints(hints CacheHints) error {
	if err := hints.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := hints
	s.cacheHints = &copied
	return nil
}

// Capabilities derives the server's MCP capability object strictly from
// registered handlers so undeclared groups are never advertised.
func (s *Server) Capabilities() Capabilities {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.capabilitiesLocked()
}

func (s *Server) capabilitiesLocked() Capabilities {
	var caps Capabilities
	if len(s.tools) > 0 {
		caps.Tools = &Capability{}
	}
	if len(s.resources) > 0 || len(s.templates) > 0 {
		caps.Resources = &Capability{}
	}
	if len(s.prompts) > 0 {
		caps.Prompts = &Capability{}
	}
	return caps
}

// RegisterTool registers or replaces a named tool and enables tools/*.
func (s *Server) RegisterTool(tool Tool, handler ToolHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tools[tool.Name]; !exists {
		s.toolOrder = append(s.toolOrder, tool.Name)
	}
	s.tools[tool.Name] = toolEntry{tool: tool, handler: handler}
}

// RegisterResource registers or replaces a static URI resource and enables resources/*.
func (s *Server) RegisterResource(res Resource, handler ResourceHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.resources[res.URI]; !exists {
		s.resourceOrder = append(s.resourceOrder, res.URI)
	}
	s.resources[res.URI] = resourceEntry{resource: res, handler: handler}
}

// RegisterResourceTemplate registers a URI template and enables resources/*.
func (s *Server) RegisterResourceTemplate(tmpl ResourceTemplate, handler ResourceHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.templates = append(s.templates, templateEntry{template: tmpl, handler: handler})
}

// RegisterPrompt registers or replaces a prompt template and enables prompts/*.
func (s *Server) RegisterPrompt(prompt Prompt, handler PromptHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.prompts[prompt.Name]; !exists {
		s.promptOrder = append(s.promptOrder, prompt.Name)
	}
	s.prompts[prompt.Name] = promptEntry{prompt: prompt, handler: handler}
}

func (s *Server) issueSessionID() string {
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	sid := hex.EncodeToString(raw[:])
	s.mu.Lock()
	s.sessions[sid] = struct{}{}
	s.mu.Unlock()
	return sid
}

func (s *Server) hasSession(sid string) bool {
	if sid == "" {
		return false
	}
	s.mu.RLock()
	_, ok := s.sessions[sid]
	s.mu.RUnlock()
	return ok
}

// HandleJSON processes a single JSON-RPC 2.0 message. Notifications (requests
// without an id) return nil, nil.
func (s *Server) HandleJSON(ctx context.Context, raw []byte) ([]byte, error) {
	var req rpcRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return marshalError(json.RawMessage("null"), CodeParseError, "Parse error", nil)
	}
	if req.JSONRPC != "2.0" || strings.TrimSpace(req.Method) == "" {
		return marshalError(normalizeID(req.ID), CodeInvalidRequest, "invalid JSON-RPC 2.0 request", nil)
	}
	if len(req.ID) == 0 {
		return nil, nil
	}
	res, rpcErr := s.dispatch(ctx, req.Method, req.Params)
	if rpcErr != nil {
		return marshalError(req.ID, rpcErr.Code, rpcErr.Message, rpcErr.Data)
	}
	return json.Marshal(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: res})
}

func (s *Server) dispatch(ctx context.Context, method string, params json.RawMessage) (any, *RPCError) {
	switch method {
	case "initialize":
		return s.handleInitialize(), nil
	case "notifications/initialized", "notifications/cancelled", "ping":
		return map[string]any{}, nil
	case "server/discover":
		return s.handleDiscover()
	default:
		return s.dispatchCatalog(ctx, method, params)
	}
}
