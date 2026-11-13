// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package mcp_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"satellion.com/passmcp-sdk-go/mcp"
	"satellion.com/passmcp-sdk-go/oauth"
)

func buildStrictTypedServer() *mcp.Server {
	srv := mcp.NewServer(
		mcp.ServerInfo{Name: "typed-srv", Version: "0.0.10", Title: "Typed"},
		mcp.WithCacheHints(mcp.CacheHints{Cacheable: true, TTL: 300, Scope: mcp.CacheScopePublic}),
	)
	ro := true
	srv.RegisterTool(mcp.Tool{
		Name:        "inspect",
		Title:       "Inspect",
		Description: "Inspect typed parameters and return structured output.",
		InputSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []any{"endpoint", "retries"},
			"properties": map[string]any{
				"endpoint": map[string]any{"type": "string"},
				"retries":  map[string]any{"type": "integer"},
				"ratio":    map[string]any{"type": "number"},
				"verbose":  map[string]any{"type": "boolean"},
				"tags":     map[string]any{"type": "array"},
				"meta":     map[string]any{"type": "object"},
			},
		},
		OutputSchema: map[string]any{
			"type":     "object",
			"required": []string{"endpoint"},
		},
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: &ro},
	}, func(_ context.Context, args map[string]any) (mcp.CallToolResult, error) {
		ep, _ := args["endpoint"].(string)
		if ep == "bad-rpc" {
			return mcp.CallToolResult{}, &mcp.RPCError{Code: mcp.CodeInvalidParams, Message: "endpoint rejected"}
		}
		return mcp.StructuredTextResult("ok:"+ep, map[string]any{"endpoint": ep}), nil
	})
	srv.RegisterPrompt(mcp.Prompt{
		Name:        "audit",
		Title:       "Audit",
		Description: "Audit prompt requiring server_name",
		Arguments:   []mcp.PromptArgument{{Name: "server_name", Required: true}},
	}, func(_ context.Context, args map[string]string) (mcp.GetPromptResult, error) {
		return mcp.GetPromptResult{
			Messages: []mcp.PromptMessage{{
				Role:    "user",
				Content: mcp.ContentBlock{Type: "text", Text: "audit " + args["server_name"]},
			}},
		}, nil
	})
	return srv
}

func TestSchemaAndPromptNegativeValidation(t *testing.T) {
	srv := buildStrictTypedServer()
	cli := mcp.NewClient(srv)
	ctx := context.Background()

	disc, err := cli.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if disc.ResultType != "discover" || disc.Meta == nil || disc.Meta.TTLMs != 300000 ||
		disc.Meta.ServerInfo == nil || disc.Meta.ServerInfo.Name != "typed-srv" {
		t.Fatalf("unexpected discover payload: %+v meta=%+v", disc, disc.Meta)
	}

	res, err := cli.CallTool(ctx, "inspect", map[string]any{
		"endpoint": "https://mcp.example.com/mcp",
		"retries":  2,
		"ratio":    0.5,
		"verbose":  true,
		"tags":     []any{"a"},
		"meta":     map[string]any{"k": "v"},
	})
	if err != nil || res.StructuredContent == nil {
		t.Fatalf("valid CallTool failed: %+v err=%v", res, err)
	}

	badArgs := []map[string]any{
		{"retries": 1},
		{"endpoint": "https://x", "retries": 1, "extra": true},
		{"endpoint": 123, "retries": 1},
		{"endpoint": "https://x", "retries": 1.5},
		{"endpoint": "https://x", "retries": 1, "ratio": "bad"},
		{"endpoint": "https://x", "retries": 1, "verbose": "yes"},
		{"endpoint": "https://x", "retries": 1, "tags": "not-array"},
		{"endpoint": "https://x", "retries": 1, "meta": "not-obj"},
		{"endpoint": "bad-rpc", "retries": 1},
	}
	for i, args := range badArgs {
		_, callErr := cli.CallTool(ctx, "inspect", args)
		assertRPCErrorCode(t, fmt.Sprintf("case-%d", i), callErr, mcp.CodeInvalidParams)
	}

	_, promptErr := cli.GetPrompt(ctx, "audit", map[string]string{})
	assertRPCErrorCode(t, "missing-prompt-arg", promptErr, mcp.CodeInvalidParams)
	if _, err := cli.GetPrompt(ctx, "audit", map[string]string{"server_name": "demo"}); err != nil {
		t.Fatalf("valid GetPrompt: %v", err)
	}
}

func assertRPCErrorCode(t *testing.T, label string, err error, want int) {
	t.Helper()
	var rpcErr *mcp.RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != want {
		t.Fatalf("%s: got %v, want RPCError %d", label, err, want)
	}
}

func TestStdioServeFramingAndStreams(t *testing.T) {
	srv := buildStrictTypedServer()
	ctx := context.Background()

	input := strings.Join([]string{
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{truncated-json`,
		`{"jsonrpc":"2.0","id":7,"method":"ping"}`,
		"",
	}, "\n")
	var out bytes.Buffer
	bufWriter := bufio.NewWriter(&out)
	if err := srv.ServeStdio(ctx, strings.NewReader(input), bufWriter); err != nil {
		t.Fatalf("ServeStdio: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines (%q), want 2 (parse error + ping)", len(lines), out.String())
	}
	if !strings.Contains(lines[0], "-32700") || !strings.Contains(lines[1], `"id":7`) {
		t.Fatalf("unexpected stdio lines: %v", lines)
	}

	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := srv.ServeStdio(ctx, c2sR, s2cW)
		_ = s2cW.Close()
		done <- err
	}()

	tr := mcp.NewStdioStreamTransport(s2cR, c2sW)
	cli := mcp.NewClient(tr)
	if _, err := cli.Connect(ctx); err != nil {
		t.Fatalf("stdio stream Connect: %v", err)
	}
	if err := cli.Ping(ctx); err != nil {
		t.Fatalf("stdio stream Ping: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("stdio stream Close: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("ServeStdio pipe exit: %v", err)
	}
}

func TestStdioSubprocessHelper(t *testing.T) {
	if os.Getenv("PASSMCP_TEST_STDIO_CHILD") != "1" {
		return
	}
	_, _ = fmt.Fprintln(os.Stderr, "child-ready")
	srv := buildStrictTypedServer()
	if err := srv.ServeStdio(context.Background(), os.Stdin, os.Stdout); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func TestStdioCommandTransportSubprocess(t *testing.T) {
	ctx := context.Background()
	t.Setenv("PASSMCP_TEST_STDIO_CHILD", "1")
	tr, err := mcp.NewStdioCommandTransport(ctx, os.Args[0], "-test.run=^TestStdioSubprocessHelper$")
	if err != nil {
		t.Fatalf("NewStdioCommandTransport: %v", err)
	}
	cli := mcp.NewClient(tr)
	disc, err := cli.Discover(ctx)
	if err != nil || len(disc.Tools) != 1 {
		t.Fatalf("subprocess Discover: %+v err=%v", disc, err)
	}
	res, err := cli.CallTool(ctx, "inspect", map[string]any{"endpoint": "https://a.example", "retries": 0})
	if err != nil || len(res.Content) == 0 {
		t.Fatalf("subprocess CallTool: %+v err=%v", res, err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("subprocess Close: %v", err)
	}
	if !strings.Contains(tr.Stderr(), "child-ready") {
		t.Fatalf("expected stderr capture, got %q", tr.Stderr())
	}
}

func TestHTTPBearerHeadersAndStateless404(t *testing.T) {
	metaURL := "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
	srv := mcp.NewServer(
		mcp.ServerInfo{Name: "http-auth", Version: "0.0.10"},
		mcp.WithBearerAuthenticator(func(tok string) bool { return tok == "secret-tok" }, metaURL),
	)
	ro := true
	srv.RegisterTool(mcp.Tool{Name: "ping_ro", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: &ro}},
		func(_ context.Context, _ map[string]any) (mcp.CallToolResult, error) {
			return mcp.TextResult("pong"), nil
		})
	rt := handlerRoundTripper{handler: srv}
	ctx := context.Background()

	unauthCli := mcp.NewClient(mcp.NewHTTPTransport("https://mcp.example.com/mcp", rt))
	err := unauthCli.Ping(ctx)
	var httpErr *mcp.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 HTTPError, got %v", err)
	}
	chal, parseErr := oauth.ParseWWWAuthenticate(httpErr.WWWAuthenticate)
	if parseErr != nil || chal.ResourceMetadata != metaURL {
		t.Fatalf("WWW-Authenticate = %q, parsed=%+v err=%v", httpErr.WWWAuthenticate, chal, parseErr)
	}

	authTr := mcp.NewHTTPTransport(
		"https://mcp.example.com/mcp",
		rt,
		mcp.WithBearerToken("secret-tok"),
		mcp.WithStatelessHeaders(mcp.Revision20260728),
	)
	authCli := mcp.NewClient(authTr)
	if err := authCli.Ping(ctx); err != nil {
		t.Fatalf("authenticated Ping: %v", err)
	}
	_, resErr := authCli.ListResources(ctx)
	assertRPCErrorCode(t, "stateless-404-method-not-found", resErr, mcp.CodeMethodNotFound)

	assertRawHTTPStatusAndCode(t, srv, "secret-tok", `{bad-json`, nil, http.StatusBadRequest, mcp.CodeParseError)
	assertRawHTTPStatusAndCode(t, srv, "secret-tok", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		map[string]string{
			mcp.HeaderProtocolVersion: mcp.Revision20260728,
			mcp.HeaderMethod:          "tools/call",
		}, http.StatusBadRequest, mcp.CodeHeaderMismatch)
	assertRawHTTPStatusAndCode(t, srv, "secret-tok", `{"jsonrpc":"2.0","id":1,"method":"ping"}`,
		map[string]string{mcp.HeaderProtocolVersion: "1999-01-01"},
		http.StatusBadRequest, mcp.CodeUnsupportedProtocolVersion)
}

func assertRawHTTPStatusAndCode(
	t *testing.T,
	h http.Handler,
	token string,
	body string,
	headers map[string]string,
	wantStatus int,
	wantCode int,
) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/mcp", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+token)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("status = %d, want %d (body=%s)", rec.Code, wantStatus, rec.Body.String())
	}
	var env struct {
		Error *mcp.RPCError `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil || env.Error == nil || env.Error.Code != wantCode {
		t.Fatalf("body = %s, want RPCError %d", rec.Body.String(), wantCode)
	}
}

func TestHTTPSessionModeLifecycle(t *testing.T) {
	srv := mcp.NewServer(
		mcp.ServerInfo{Name: "sess-srv", Version: "0.0.10"},
		mcp.WithRevision(mcp.Revision20251125),
		mcp.WithSessions(true),
	)
	rt := handlerRoundTripper{handler: srv}
	ctx := context.Background()

	bogusTr := mcp.NewHTTPTransport("https://mcp.example.com/mcp", rt, mcp.WithSessionID("forged-id"))
	if err := mcp.NewClient(bogusTr, mcp.WithClientRevision(mcp.Revision20251125)).Ping(ctx); err == nil {
		t.Fatal("expected 404 for unknown Mcp-Session-Id")
	}

	tr := mcp.NewHTTPTransport("https://mcp.example.com/mcp", rt)
	cli := mcp.NewClient(tr, mcp.WithClientRevision(mcp.Revision20251125))
	if _, err := cli.Connect(ctx); err != nil {
		t.Fatalf("session Connect: %v", err)
	}
	if tr.SessionID() == "" {
		t.Fatal("expected non-empty Mcp-Session-Id after Connect")
	}
	if err := cli.Ping(ctx); err != nil {
		t.Fatalf("session Ping: %v", err)
	}
}
