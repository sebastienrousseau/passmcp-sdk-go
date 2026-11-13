// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"

	"satellion.com/passmcp-reporting/attestation"
)

// Dispatcher exchanges raw JSON-RPC 2.0 payloads with an MCP server.
// *Server, *HTTPTransport, and *StdioTransport implement Dispatcher directly.
type Dispatcher interface {
	HandleJSON(ctx context.Context, raw []byte) ([]byte, error)
}

// Policy controls client-side tool invocation safety. By default
// AllowMutations is false, enforcing ADR 0004 (only tools declaring
// readOnlyHint: true may execute).
type Policy struct {
	AllowMutations bool
	Deny           []string
}

// ClientOption configures a Client.
type ClientOption func(*Client)

type attestationGate struct {
	statement *attestation.Statement
	transport string
	endpoint  string
}

// Client is a policy-enforcing MCP JSON-RPC 2.0 client.
type Client struct {
	dispatcher Dispatcher
	clientInfo ServerInfo
	revision   string
	policy     Policy
	gate       *attestationGate
	nextID     atomic.Int64

	mu          sync.RWMutex
	toolsLoaded bool
	tools       map[string]Tool
}

// WithPolicy sets the client's tool execution policy.
func WithPolicy(policy Policy) ClientOption {
	return func(c *Client) {
		c.policy = policy
	}
}

// WithClientInfo overrides the client identity sent during initialize.
func WithClientInfo(info ServerInfo) ClientOption {
	return func(c *Client) {
		c.clientInfo = info
	}
}

// WithClientRevision sets the protocol revision requested during initialize.
func WithClientRevision(revision string) ClientOption {
	return func(c *Client) {
		if revision != "" {
			c.revision = revision
		}
	}
}

// RequireAttestation gates every client operation on an offline-verified
// passmcp attestation covering transport and endpoint.
func RequireAttestation(st *attestation.Statement, transport, endpoint string) ClientOption {
	return func(c *Client) {
		c.gate = &attestationGate{
			statement: st,
			transport: transport,
			endpoint:  endpoint,
		}
	}
}

// NewClient constructs a Client over any Dispatcher (such as *Server,
// *HTTPTransport, or *StdioTransport).
func NewClient(dispatcher Dispatcher, opts ...ClientOption) *Client {
	c := &Client{
		dispatcher: dispatcher,
		clientInfo: ServerInfo{Name: "passmcp-sdk-go", Version: "0.0.10"},
		revision:   Revision20260728,
		tools:      make(map[string]Tool),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// NewHTTPClient constructs a Client over Streamable HTTP POST using transport
// (or http.DefaultTransport when transport is nil).
func NewHTTPClient(endpoint string, transport http.RoundTripper, opts ...ClientOption) *Client {
	return NewClient(NewHTTPTransport(endpoint, transport), opts...)
}

func (c *Client) checkGate() error {
	if c.gate == nil {
		return nil
	}
	if c.gate.statement == nil {
		return fmt.Errorf("%w: nil statement", ErrUntrustedAttestation)
	}
	if err := c.gate.statement.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrUntrustedAttestation, err)
	}
	if !c.gate.statement.Covers(c.gate.transport, c.gate.endpoint) {
		return fmt.Errorf("%w: statement does not cover %s %s",
			ErrUntrustedAttestation, c.gate.transport, c.gate.endpoint)
	}
	return nil
}

// Connect performs the MCP initialize handshake and emits notifications/initialized.
func (c *Client) Connect(ctx context.Context) (InitializeResult, error) {
	var out InitializeResult
	params := map[string]any{
		"protocolVersion": c.revision,
		"capabilities":    map[string]any{},
		"clientInfo":      c.clientInfo,
	}
	if err := c.call(ctx, "initialize", params, &out); err != nil {
		return InitializeResult{}, err
	}
	if err := c.notify(ctx, "notifications/initialized"); err != nil {
		return InitializeResult{}, err
	}
	return out, nil
}

// Discover performs a stateless server/discover call and caches any returned tools.
func (c *Client) Discover(ctx context.Context) (DiscoverResult, error) {
	var out DiscoverResult
	if err := c.call(ctx, "server/discover", map[string]any{}, &out); err != nil {
		return DiscoverResult{}, err
	}
	if out.Capabilities.Tools != nil {
		c.cacheTools(out.Tools)
	}
	return out, nil
}

// Ping sends a JSON-RPC ping request.
func (c *Client) Ping(ctx context.Context) error {
	var out map[string]any
	return c.call(ctx, "ping", map[string]any{}, &out)
}

// ListTools fetches tools/list and updates the client's policy catalog.
func (c *Client) ListTools(ctx context.Context) ([]Tool, error) {
	var out struct {
		Tools []Tool `json:"tools"`
	}
	if err := c.call(ctx, "tools/list", map[string]any{}, &out); err != nil {
		return nil, err
	}
	c.cacheTools(out.Tools)
	return out.Tools, nil
}

func (c *Client) cacheTools(tools []Tool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tools = make(map[string]Tool, len(tools))
	for _, t := range tools {
		c.tools[t.Name] = t
	}
	c.toolsLoaded = true
}

// CallTool enforces Policy (denylist and readOnlyHint default) before invoking
// tools/call on the server.
func (c *Client) CallTool(ctx context.Context, name string, args map[string]any) (CallToolResult, error) {
	if err := c.checkGate(); err != nil {
		return CallToolResult{}, err
	}
	if slices.Contains(c.policy.Deny, name) {
		return CallToolResult{}, fmt.Errorf("%w: %s", ErrToolDenied, name)
	}
	if !c.policy.AllowMutations {
		if err := c.requireReadOnlyTool(ctx, name); err != nil {
			return CallToolResult{}, err
		}
	}
	if args == nil {
		args = map[string]any{}
	}
	var out CallToolResult
	err := c.call(ctx, "tools/call", map[string]any{"name": name, "arguments": args}, &out)
	return out, err
}

func (c *Client) requireReadOnlyTool(ctx context.Context, name string) error {
	c.mu.RLock()
	loaded := c.toolsLoaded
	tool, ok := c.tools[name]
	c.mu.RUnlock()
	if !loaded {
		if _, err := c.ListTools(ctx); err != nil {
			return err
		}
		c.mu.RLock()
		tool, ok = c.tools[name]
		c.mu.RUnlock()
	}
	if !ok || !tool.IsReadOnly() {
		return fmt.Errorf("%w: %s lacks readOnlyHint: true", ErrMutationRefused, name)
	}
	return nil
}

// ListResources fetches resources/list from the server.
func (c *Client) ListResources(ctx context.Context) ([]Resource, error) {
	var out struct {
		Resources []Resource `json:"resources"`
	}
	err := c.call(ctx, "resources/list", map[string]any{}, &out)
	return out.Resources, err
}

// ListResourceTemplates fetches resources/templates/list from the server.
func (c *Client) ListResourceTemplates(ctx context.Context) ([]ResourceTemplate, error) {
	var out struct {
		Templates []ResourceTemplate `json:"resourceTemplates"`
	}
	err := c.call(ctx, "resources/templates/list", map[string]any{}, &out)
	return out.Templates, err
}

// ReadResource fetches resources/read for the given URI.
func (c *Client) ReadResource(ctx context.Context, uri string) (ReadResourceResult, error) {
	var out ReadResourceResult
	err := c.call(ctx, "resources/read", map[string]any{"uri": uri}, &out)
	return out, err
}

// ListPrompts fetches prompts/list from the server.
func (c *Client) ListPrompts(ctx context.Context) ([]Prompt, error) {
	var out struct {
		Prompts []Prompt `json:"prompts"`
	}
	err := c.call(ctx, "prompts/list", map[string]any{}, &out)
	return out.Prompts, err
}

// GetPrompt fetches prompts/get for name and args.
func (c *Client) GetPrompt(ctx context.Context, name string, args map[string]string) (GetPromptResult, error) {
	var out GetPromptResult
	err := c.call(ctx, "prompts/get", map[string]any{"name": name, "arguments": args}, &out)
	return out, err
}

func (c *Client) notify(ctx context.Context, method string) error {
	if err := c.checkGate(); err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method})
	if err != nil {
		return err
	}
	_, err = c.dispatcher.HandleJSON(ctx, payload)
	return err
}

func (c *Client) call(ctx context.Context, method string, params any, dst any) error {
	if err := c.checkGate(); err != nil {
		return err
	}
	id := c.nextID.Add(1)
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return err
	}
	rawResp, err := c.dispatcher.HandleJSON(ctx, payload)
	if err != nil {
		return err
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *RPCError       `json:"error"`
	}
	if err := json.Unmarshal(rawResp, &env); err != nil {
		return fmt.Errorf("mcp: decode response: %w", err)
	}
	if env.Error != nil {
		return env.Error
	}
	if dst == nil {
		return nil
	}
	return json.Unmarshal(env.Result, dst)
}
