// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"satellion.com/passmcp-reporting/attestation"
	"satellion.com/passmcp-sdk-go/mcp"
)

type handlerRoundTripper struct {
	handler http.Handler
}

func (rt handlerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	rt.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}

func TestUndeclaredCapabilitiesAndDiscovery(t *testing.T) {
	srv := mcp.NewServer(
		mcp.ServerInfo{Name: "empty-srv", Version: "0.0.10"},
		mcp.WithInstructions("read-only gateway"),
	)
	if srv.Info().Name != "empty-srv" || srv.Revision() != mcp.Revision20260728 {
		t.Fatalf("unexpected server metadata: %+v rev=%s", srv.Info(), srv.Revision())
	}
	if caps := srv.Capabilities(); caps.Tools != nil || caps.Resources != nil || caps.Prompts != nil {
		t.Fatalf("expected empty capabilities, got %+v", caps)
	}

	cli := mcp.NewClient(srv)
	ctx := context.Background()
	initRes, err := cli.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if initRes.Capabilities.Tools != nil || initRes.Capabilities.Resources != nil || initRes.Capabilities.Prompts != nil {
		t.Fatalf("expected empty capabilities, got %+v", initRes.Capabilities)
	}
	if err := cli.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	disc, err := cli.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if disc.Instructions != "read-only gateway" || disc.Meta == nil || disc.Meta.CacheScope != mcp.CacheScopePrivate {
		t.Fatalf("unexpected discover result: %+v", disc)
	}

	assertMethodNotFound(t, func() error { _, e := cli.ListTools(ctx); return e })
	assertMethodNotFound(t, func() error { _, e := cli.ListResources(ctx); return e })
	assertMethodNotFound(t, func() error { _, e := cli.ListResourceTemplates(ctx); return e })
	assertMethodNotFound(t, func() error { _, e := cli.ReadResource(ctx, "mem://a"); return e })
	assertMethodNotFound(t, func() error { _, e := cli.ListPrompts(ctx); return e })
	assertMethodNotFound(t, func() error { _, e := cli.GetPrompt(ctx, "p", nil); return e })
}

func assertMethodNotFound(t *testing.T, fn func() error) {
	t.Helper()
	err := fn()
	var rpcErr *mcp.RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != mcp.CodeMethodNotFound {
		t.Fatalf("got %v, want RPCError %d", err, mcp.CodeMethodNotFound)
	}
}

func TestSEP2164MissingResourceByRevision(t *testing.T) {
	ctx := context.Background()
	srvLatest := mcp.NewServer(mcp.ServerInfo{Name: "r", Version: "0.0.10"})
	srvLatest.RegisterResource(mcp.Resource{URI: "doc://readme", Name: "readme"}, func(_ context.Context, uri string) (mcp.ResourceContents, error) {
		return mcp.ResourceContents{URI: uri, MimeType: "text/plain", Text: "hello"}, nil
	})
	srvLatest.RegisterResource(mcp.Resource{URI: "doc://broken", Name: "broken"}, func(_ context.Context, _ string) (mcp.ResourceContents, error) {
		return mcp.ResourceContents{}, errors.New("storage offline")
	})
	srvLatest.RegisterResourceTemplate(mcp.ResourceTemplate{URITemplate: "item://{id}", Name: "item"}, func(_ context.Context, uri string) (mcp.ResourceContents, error) {
		return mcp.ResourceContents{URI: uri, Text: "templated"}, nil
	})

	cli := mcp.NewClient(srvLatest)
	resources, err := cli.ListResources(ctx)
	if err != nil || len(resources) != 2 {
		t.Fatalf("ListResources: %+v err=%v", resources, err)
	}
	templates, err := cli.ListResourceTemplates(ctx)
	if err != nil || len(templates) != 1 {
		t.Fatalf("ListResourceTemplates: %+v err=%v", templates, err)
	}
	readRes, err := cli.ReadResource(ctx, "item://42")
	if err != nil || len(readRes.Contents) != 1 || readRes.Contents[0].Text != "templated" {
		t.Fatalf("template ReadResource: %+v err=%v", readRes, err)
	}
	if _, err := cli.ReadResource(ctx, "doc://broken"); err == nil {
		t.Fatal("expected broken resource error")
	}

	_, err = cli.ReadResource(ctx, "doc://missing")
	assertResourceError(t, err, mcp.CodeInvalidParams, "doc://missing")

	srvLegacy := mcp.NewServer(
		mcp.ServerInfo{Name: "legacy", Version: "0.0.10"},
		mcp.WithRevision(mcp.Revision20250618),
	)
	srvLegacy.RegisterResource(mcp.Resource{URI: "doc://readme", Name: "readme"}, func(_ context.Context, uri string) (mcp.ResourceContents, error) {
		return mcp.ResourceContents{URI: uri, Text: "legacy"}, nil
	})
	_, err = mcp.NewClient(srvLegacy, mcp.WithClientRevision(mcp.Revision20250618)).ReadResource(ctx, "doc://missing")
	assertResourceError(t, err, mcp.CodeResourceNotFoundLegacy, "doc://missing")
}

func assertResourceError(t *testing.T, err error, wantCode int, wantURI string) {
	t.Helper()
	var rpcErr *mcp.RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != wantCode {
		t.Fatalf("got %v, want code %d", err, wantCode)
	}
	if rpcErr.Error() == "" {
		t.Fatal("empty RPCError string")
	}
	data, ok := rpcErr.Data.(map[string]any)
	if !ok || data["uri"] != wantURI {
		t.Fatalf("error.data = %#v, want uri=%q", rpcErr.Data, wantURI)
	}
}

func TestSEP2549CacheHintsValidationAndEmission(t *testing.T) {
	if err := (mcp.CacheHints{TTLMs: -1, CacheScope: mcp.CacheScopePublic}).Validate(); !errors.Is(err, mcp.ErrInvalidCacheHints) {
		t.Fatalf("expected negative ttlMs rejection, got %v", err)
	}
	if err := (mcp.CacheHints{TTLMs: 10, CacheScope: "shared"}).Validate(); !errors.Is(err, mcp.ErrInvalidCacheHints) {
		t.Fatalf("expected invalid cacheScope rejection, got %v", err)
	}

	srv := mcp.NewServer(mcp.ServerInfo{Name: "catalog", Version: "0.0.10"})
	if err := srv.SetCacheHints(mcp.CacheHints{TTLMs: -5, CacheScope: mcp.CacheScopePublic}); err == nil {
		t.Fatal("SetCacheHints accepted negative ttlMs")
	}
	if err := srv.SetCacheHints(mcp.CacheHints{TTLMs: 60000, CacheScope: mcp.CacheScopePublic}); err != nil {
		t.Fatalf("SetCacheHints valid: %v", err)
	}
	ro := true
	srv.RegisterTool(mcp.Tool{
		Name:        "ping_tool",
		ReadOnly:    true,
		Annotations: &mcp.ToolAnnotations{Title: "Ping"},
	}, func(_ context.Context, _ map[string]any) (mcp.CallToolResult, error) {
		return mcp.TextResult("pong"), nil
	})
	srv.RegisterTool(mcp.Tool{
		Name:        "explicit_ro",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: &ro},
	}, func(_ context.Context, _ map[string]any) (mcp.CallToolResult, error) {
		return mcp.TextResult("ok"), nil
	})

	raw, err := srv.HandleJSON(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("HandleJSON: %v", err)
	}
	var resp struct {
		Result struct {
			Meta mcp.CacheHints `json:"_meta"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Result.Meta.TTLMs != 60000 || resp.Result.Meta.CacheScope != mcp.CacheScopePublic {
		t.Fatalf("_meta = %+v, want 60000/public", resp.Result.Meta)
	}

	badSrv := mcp.NewServer(
		mcp.ServerInfo{Name: "bad", Version: "0.0.10"},
		mcp.WithCacheHints(mcp.CacheHints{TTLMs: -1, CacheScope: mcp.CacheScopePublic}),
	)
	badSrv.RegisterTool(mcp.Tool{Name: "t", ReadOnly: true}, nil)
	if _, err := mcp.NewClient(badSrv).ListTools(context.Background()); err == nil {
		t.Fatal("expected invalid configured cache hints to fail tools/list")
	}
	if _, err := mcp.NewClient(badSrv).Discover(context.Background()); err == nil {
		t.Fatal("expected invalid configured cache hints to fail server/discover")
	}
}

func TestClientPolicyAndPrompts(t *testing.T) {
	srv := newFullFixtureServer()
	ctx := context.Background()

	roClient := mcp.NewClient(
		srv,
		mcp.WithClientInfo(mcp.ServerInfo{Name: "test-cli", Version: "0.0.10"}),
		mcp.WithPolicy(mcp.Policy{AllowMutations: false, Deny: []string{"blocked_ro"}}),
	)
	if _, err := roClient.CallTool(ctx, "blocked_ro", nil); !errors.Is(err, mcp.ErrToolDenied) {
		t.Fatalf("denied tool: got %v, want ErrToolDenied", err)
	}
	if _, err := roClient.CallTool(ctx, "mutate_db", nil); !errors.Is(err, mcp.ErrMutationRefused) {
		t.Fatalf("mutating tool: got %v, want ErrMutationRefused", err)
	}
	res, err := roClient.CallTool(ctx, "health", nil)
	if err != nil || len(res.Content) != 1 || res.Content[0].Text != "ok" {
		t.Fatalf("read-only tool failed: %+v err=%v", res, err)
	}
	errRes, err := roClient.CallTool(ctx, "fail_ro", nil)
	if err != nil || !errRes.IsError {
		t.Fatalf("expected tool error result, got %+v err=%v", errRes, err)
	}

	mutClient := mcp.NewClient(srv, mcp.WithPolicy(mcp.Policy{AllowMutations: true}))
	if _, err := mutClient.CallTool(ctx, "mutate_db", map[string]any{"k": "v"}); err != nil {
		t.Fatalf("AllowMutations CallTool: %v", err)
	}

	prompts, err := roClient.ListPrompts(ctx)
	if err != nil || len(prompts) != 2 {
		t.Fatalf("ListPrompts: %+v err=%v", prompts, err)
	}
	gotPrompt, err := roClient.GetPrompt(ctx, "summarize", map[string]string{"topic": "mcp"})
	if err != nil || len(gotPrompt.Messages) != 1 {
		t.Fatalf("GetPrompt: %+v err=%v", gotPrompt, err)
	}
	if _, err := roClient.GetPrompt(ctx, "broken_prompt", nil); err == nil {
		t.Fatal("expected broken_prompt error")
	}
}

func newFullFixtureServer() *mcp.Server {
	srv := mcp.NewServer(mcp.ServerInfo{Name: "full", Version: "0.0.10"})
	srv.RegisterTool(mcp.Tool{Name: "health", Description: "ro", ReadOnly: true}, func(_ context.Context, _ map[string]any) (mcp.CallToolResult, error) {
		return mcp.TextResult("ok"), nil
	})
	srv.RegisterTool(mcp.Tool{Name: "blocked_ro", ReadOnly: true}, func(_ context.Context, _ map[string]any) (mcp.CallToolResult, error) {
		return mcp.TextResult("blocked"), nil
	})
	srv.RegisterTool(mcp.Tool{Name: "fail_ro", ReadOnly: true}, func(_ context.Context, _ map[string]any) (mcp.CallToolResult, error) {
		return mcp.CallToolResult{}, errors.New("tool failed")
	})
	srv.RegisterTool(mcp.Tool{Name: "mutate_db", Description: "writes"}, func(_ context.Context, _ map[string]any) (mcp.CallToolResult, error) {
		return mcp.TextResult("mutated"), nil
	})
	srv.RegisterResource(mcp.Resource{URI: "mem://one", Name: "one"}, func(_ context.Context, uri string) (mcp.ResourceContents, error) {
		return mcp.ResourceContents{URI: uri, Text: "1"}, nil
	})
	srv.RegisterResourceTemplate(mcp.ResourceTemplate{URITemplate: "mem://t/{id}", Name: "t"}, func(_ context.Context, uri string) (mcp.ResourceContents, error) {
		return mcp.ResourceContents{URI: uri, Text: "t"}, nil
	})
	srv.RegisterPrompt(mcp.Prompt{Name: "summarize"}, func(_ context.Context, args map[string]string) (mcp.GetPromptResult, error) {
		return mcp.GetPromptResult{
			Messages: []mcp.PromptMessage{{Role: "user", Content: mcp.ContentBlock{Type: "text", Text: args["topic"]}}},
		}, nil
	})
	srv.RegisterPrompt(mcp.Prompt{Name: "broken_prompt"}, func(_ context.Context, _ map[string]string) (mcp.GetPromptResult, error) {
		return mcp.GetPromptResult{}, errors.New("prompt render failed")
	})
	return srv
}

func TestHTTPOriginGuardAndAttestationGate(t *testing.T) {
	srv := newFullFixtureServer()
	guarded := mcp.NewServer(
		mcp.ServerInfo{Name: "http-srv", Version: "0.0.10"},
		mcp.WithAllowedOrigins("https://console.example.com", "*", "null", "https://bad.example.com/path", "https://u:p@bad.example.com"),
	)
	guarded.RegisterTool(mcp.Tool{Name: "health", ReadOnly: true}, func(_ context.Context, _ map[string]any) (mcp.CallToolResult, error) {
		return mcp.TextResult("ok"), nil
	})

	checkOriginStatus(t, guarded, "https://evil.example.com", http.StatusForbidden)
	checkOriginStatus(t, guarded, "null", http.StatusForbidden)
	checkOriginStatus(t, guarded, "://malformed", http.StatusForbidden)
	checkOriginStatus(t, guarded, "https://CONSOLE.example.com", http.StatusOK)

	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://mcp.example.com/mcp", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", rec.Code)
	}

	rawStmt, err := os.ReadFile("../testdata/statement.json")
	if err != nil {
		t.Fatalf("read statement.json: %v", err)
	}
	st, err := attestation.Parse(rawStmt)
	if err != nil {
		t.Fatalf("Parse statement: %v", err)
	}

	rt := handlerRoundTripper{handler: guarded}
	httpCli := mcp.NewHTTPClient("https://mcp.example.com/mcp", rt, mcp.RequireAttestation(st, "http", "https://mcp.example.com/mcp"))
	if _, err := httpCli.Connect(context.Background()); err != nil {
		t.Fatalf("HTTP Connect with valid attestation: %v", err)
	}
	if _, err := httpCli.CallTool(context.Background(), "health", nil); err != nil {
		t.Fatalf("HTTP CallTool: %v", err)
	}

	disc, err := mcp.NewClient(srv).Discover(context.Background())
	if err != nil || len(disc.Tools) != 4 || len(disc.Resources) != 1 || len(disc.ResourceTemplates) != 1 || len(disc.Prompts) != 2 {
		t.Fatalf("full Discover: %+v err=%v", disc, err)
	}

	badCli := mcp.NewHTTPClient("https://mcp.example.com/mcp", rt, mcp.RequireAttestation(st, "http", "https://other.example.com/mcp"))
	if _, err := badCli.Connect(context.Background()); !errors.Is(err, mcp.ErrUntrustedAttestation) {
		t.Fatalf("mismatched attestation: got %v, want ErrUntrustedAttestation", err)
	}
	nilCli := mcp.NewClient(srv, mcp.RequireAttestation(nil, "http", "https://mcp.example.com/mcp"))
	if _, err := nilCli.Discover(context.Background()); !errors.Is(err, mcp.ErrUntrustedAttestation) {
		t.Fatalf("nil attestation: got %v, want ErrUntrustedAttestation", err)
	}
}

func checkOriginStatus(t *testing.T, h http.Handler, origin string, wantStatus int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Origin", origin)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("Origin %q status = %d, want %d", origin, rec.Code, wantStatus)
	}
}

func TestJSONRPCFramingAndOriginWrap(t *testing.T) {
	srv := newFullFixtureServer()
	ctx := context.Background()

	cases := []struct {
		payload  string
		wantCode int
	}{
		{`{not-json`, mcp.CodeParseError},
		{`{"jsonrpc":"1.0","method":"ping"}`, mcp.CodeInvalidRequest},
		{`{"jsonrpc":"2.0","id":1,"method":"unknown/op"}`, mcp.CodeMethodNotFound},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`, mcp.CodeInvalidParams},
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope"}}`, mcp.CodeInvalidParams},
		{`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{}}`, mcp.CodeInvalidParams},
		{`{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{}}`, mcp.CodeInvalidParams},
		{`{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"nope"}}`, mcp.CodeInvalidParams},
	}
	for _, tc := range cases {
		raw, err := srv.HandleJSON(ctx, []byte(tc.payload))
		if err != nil {
			t.Fatalf("HandleJSON(%s): %v", tc.payload, err)
		}
		var env struct {
			Error *mcp.RPCError `json:"error"`
		}
		if err := json.Unmarshal(raw, &env); err != nil || env.Error == nil || env.Error.Code != tc.wantCode {
			t.Fatalf("payload %s -> %s, want code %d", tc.payload, string(raw), tc.wantCode)
		}
	}

	guard := mcp.NewOriginGuard("https://allowed.example.com")
	wrapped := guard.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Origin", "https://denied.example.com")
	wrapped.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("Wrap denied origin status = %d, want 403", rec.Code)
	}
	recOK := httptest.NewRecorder()
	reqOK := httptest.NewRequest(http.MethodPost, "/", nil)
	reqOK.Header.Set("Origin", "https://allowed.example.com")
	wrapped.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusNoContent {
		t.Fatalf("Wrap allowed origin status = %d, want 204", recOK.Code)
	}
}
