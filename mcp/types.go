// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Package mcp implements a capability-derived MCP JSON-RPC 2.0 server,
// stdio and Streamable HTTP transports, and a policy-enforcing client covering
// protocol revisions 2025-06-18 through 2026-07-28.
package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Supported MCP specification revisions.
const (
	Revision20260728 = "2026-07-28"
	Revision20251125 = "2025-11-25"
	Revision20250618 = "2025-06-18"
)

// SEP-2549 cache scope values and stateless metadata keys.
const (
	CacheScopePublic  = "public"
	CacheScopePrivate = "private"
	MetaServerInfo    = "io.modelcontextprotocol/serverInfo"
)

// Standard JSON-RPC 2.0 and MCP error codes.
const (
	CodeParseError                 = -32700
	CodeInvalidRequest             = -32600
	CodeMethodNotFound             = -32601
	CodeInvalidParams              = -32602
	CodeInternalError              = -32603
	CodeResourceNotFoundLegacy     = -32002
	CodeHeaderMismatch             = -32020
	CodeUnsupportedProtocolVersion = -32022
)

// Sentinel errors returned by server configuration and client policy checks.
var (
	ErrInvalidCacheHints    = errors.New("mcp: invalid SEP-2549 cache hints")
	ErrMutationRefused      = errors.New("mcp: tool refused by read-only client policy")
	ErrToolDenied           = errors.New("mcp: tool is denied by client policy")
	ErrUntrustedAttestation = errors.New("mcp: target attestation verification failed")
)

// ServerInfo identifies an MCP server or client implementation.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Title   string `json:"title,omitempty"`
}

// CacheHints carries SEP-2549 list cache metadata emitted on 2026-07-28 list
// responses. Callers may specify either TTLMs + CacheScope directly or
// Cacheable + TTL (seconds) + Scope.
type CacheHints struct {
	Cacheable  bool   `json:"-"`
	TTL        int    `json:"-"`
	Scope      string `json:"-"`
	TTLMs      int    `json:"ttlMs"`
	CacheScope string `json:"cacheScope"`
}

// Effective resolves the normalized SEP-2549 ttlMs and cacheScope values.
func (h CacheHints) Effective() (int, string, error) {
	if h.TTLMs < 0 || h.TTL < 0 {
		return 0, "", fmt.Errorf("%w: ttl (%d ms / %d s) must be >= 0", ErrInvalidCacheHints, h.TTLMs, h.TTL)
	}
	scope := h.CacheScope
	if scope == "" {
		scope = h.Scope
	}
	if scope != CacheScopePublic && scope != CacheScopePrivate {
		return 0, "", fmt.Errorf("%w: cacheScope %q must be %q or %q",
			ErrInvalidCacheHints, scope, CacheScopePublic, CacheScopePrivate)
	}
	ttlMs := h.TTLMs
	if ttlMs == 0 && h.Cacheable && h.TTL > 0 {
		ttlMs = h.TTL * 1000
	}
	return ttlMs, scope, nil
}

// Validate enforces the SEP-2549 schema invariants: non-negative ttlMs and a
// cacheScope of either "public" or "private".
func (h CacheHints) Validate() error {
	_, _, err := h.Effective()
	return err
}

// MarshalJSON emits normalized ttlMs and cacheScope fields.
func (h CacheHints) MarshalJSON() ([]byte, error) {
	ttlMs, scope, err := h.Effective()
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		TTLMs      int    `json:"ttlMs"`
		CacheScope string `json:"cacheScope"`
	}{
		TTLMs:      ttlMs,
		CacheScope: scope,
	})
}

// Capability marks a declared server capability group.
type Capability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// Capabilities describes the capability groups declared by a server.
// Undeclared groups remain nil so they are omitted on the wire.
type Capabilities struct {
	Tools     *Capability `json:"tools,omitempty"`
	Resources *Capability `json:"resources,omitempty"`
	Prompts   *Capability `json:"prompts,omitempty"`
}

// ToolAnnotations holds optional MCP tool behaviour hints.
type ToolAnnotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    *bool  `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool  `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool  `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool  `json:"openWorldHint,omitempty"`
}

// Tool describes one callable MCP tool.
type Tool struct {
	Name         string           `json:"name"`
	Title        string           `json:"title,omitempty"`
	Description  string           `json:"description,omitempty"`
	InputSchema  map[string]any   `json:"inputSchema"`
	OutputSchema map[string]any   `json:"outputSchema,omitempty"`
	ReadOnly     bool             `json:"-"`
	Annotations  *ToolAnnotations `json:"annotations,omitempty"`
}

type wireTool struct {
	Name         string           `json:"name"`
	Title        string           `json:"title,omitempty"`
	Description  string           `json:"description,omitempty"`
	InputSchema  map[string]any   `json:"inputSchema"`
	OutputSchema map[string]any   `json:"outputSchema,omitempty"`
	Annotations  *ToolAnnotations `json:"annotations,omitempty"`
}

// IsReadOnly reports whether the tool explicitly declares readOnlyHint: true.
// Under ADR 0004 and the MCP specification, unannotated tools are treated as
// potentially mutating.
func (t Tool) IsReadOnly() bool {
	if t.Annotations != nil && t.Annotations.ReadOnlyHint != nil {
		return *t.Annotations.ReadOnlyHint
	}
	return t.ReadOnly
}

// MarshalJSON emits a standard MCP tool descriptor with default object
// inputSchema and synchronized annotations.readOnlyHint.
func (t Tool) MarshalJSON() ([]byte, error) {
	schema := t.InputSchema
	if len(schema) == 0 {
		schema = map[string]any{"type": "object"}
	}
	ann := t.Annotations
	if t.ReadOnly && (ann == nil || ann.ReadOnlyHint == nil) {
		ro := true
		copied := ToolAnnotations{ReadOnlyHint: &ro}
		if ann != nil {
			copied = *ann
			copied.ReadOnlyHint = &ro
		}
		ann = &copied
	}
	return json.Marshal(wireTool{
		Name:         t.Name,
		Title:        t.Title,
		Description:  t.Description,
		InputSchema:  schema,
		OutputSchema: t.OutputSchema,
		Annotations:  ann,
	})
}

// UnmarshalJSON decodes a wire tool descriptor and synchronizes ReadOnly.
func (t *Tool) UnmarshalJSON(data []byte) error {
	var w wireTool
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	t.Name = w.Name
	t.Title = w.Title
	t.Description = w.Description
	t.InputSchema = w.InputSchema
	t.OutputSchema = w.OutputSchema
	t.Annotations = w.Annotations
	t.ReadOnly = t.IsReadOnly()
	return nil
}

// ContentBlock represents a single item inside a tool or prompt response.
type ContentBlock struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	URI      string `json:"uri,omitempty"`
}

// CallToolResult is the response payload of tools/call.
type CallToolResult struct {
	Content           []ContentBlock `json:"content"`
	IsError           bool           `json:"isError,omitempty"`
	StructuredContent any            `json:"structuredContent,omitempty"`
}

// TextResult constructs a non-error text CallToolResult.
func TextResult(text string) CallToolResult {
	return CallToolResult{
		Content: []ContentBlock{{Type: "text", Text: text}},
	}
}

// StructuredTextResult constructs a non-error CallToolResult carrying both
// human-readable text content and machine-checkable structuredContent.
func StructuredTextResult(text string, structured any) CallToolResult {
	return CallToolResult{
		Content:           []ContentBlock{{Type: "text", Text: text}},
		StructuredContent: structured,
	}
}

// ErrorTextResult constructs an error CallToolResult (isError: true).
func ErrorTextResult(text string) CallToolResult {
	return CallToolResult{
		Content: []ContentBlock{{Type: "text", Text: text}},
		IsError: true,
	}
}

// Resource describes a readable server resource.
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// ResourceTemplate describes a parameterized URI template on the server.
type ResourceTemplate struct {
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// ResourceContents carries the body of a read resource.
type ResourceContents struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"`
}

// ReadResourceResult is the response payload of resources/read.
type ReadResourceResult struct {
	Contents []ResourceContents `json:"contents"`
}

// PromptArgument describes a named argument accepted by a prompt.
type PromptArgument struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// Prompt describes a server prompt template.
type Prompt struct {
	Name        string           `json:"name"`
	Title       string           `json:"title,omitempty"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

// PromptMessage is one message inside a rendered prompt.
type PromptMessage struct {
	Role    string       `json:"role"`
	Content ContentBlock `json:"content"`
}

// GetPromptResult is the response payload of prompts/get.
type GetPromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

// InitializeResult is returned by initialize.
type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ServerInfo      ServerInfo   `json:"serverInfo"`
	Instructions    string       `json:"instructions,omitempty"`
}

// DiscoverMeta carries stateless 2026-07-28 _meta properties on server/discover,
// including io.modelcontextprotocol/serverInfo and SEP-2549 cache hints.
type DiscoverMeta struct {
	ServerInfo *ServerInfo `json:"io.modelcontextprotocol/serverInfo,omitempty"`
	TTLMs      int         `json:"ttlMs"`
	CacheScope string      `json:"cacheScope"`
}

// DiscoverResult is returned by stateless server/discover.
type DiscoverResult struct {
	ResultType        string             `json:"resultType,omitempty"`
	ProtocolVersion   string             `json:"protocolVersion"`
	SupportedVersions []string           `json:"supportedVersions,omitempty"`
	ServerInfo        ServerInfo         `json:"serverInfo"`
	Capabilities      Capabilities       `json:"capabilities"`
	Instructions      string             `json:"instructions,omitempty"`
	Tools             []Tool             `json:"tools,omitempty"`
	Resources         []Resource         `json:"resources,omitempty"`
	ResourceTemplates []ResourceTemplate `json:"resourceTemplates,omitempty"`
	Prompts           []Prompt           `json:"prompts,omitempty"`
	Meta              *DiscoverMeta      `json:"_meta,omitempty"`
}

// RPCError represents a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Error formats the JSON-RPC error code and message.
func (e *RPCError) Error() string {
	return fmt.Sprintf("mcp: rpc error %d: %s", e.Code, e.Message)
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

func normalizeID(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

func marshalError(id json.RawMessage, code int, msg string, data any) ([]byte, error) {
	return json.Marshal(rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &RPCError{Code: code, Message: msg, Data: data},
	})
}

func missingResourceError(revision, uri string) *RPCError {
	code := CodeResourceNotFoundLegacy
	if revision == Revision20260728 {
		code = CodeInvalidParams
	}
	return &RPCError{
		Code:    code,
		Message: fmt.Sprintf("resource %q not found; call resources/list for available URIs", uri),
		Data:    map[string]any{"uri": uri},
	}
}
