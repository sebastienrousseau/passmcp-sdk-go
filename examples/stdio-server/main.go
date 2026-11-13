// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Command stdio-server runs the reference MCP server over stdin/stdout for
// live passmcp conformance verification.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"satellion.com/passmcp-sdk-go/mcp"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := buildDemoServer()
	if err := srv.ServeStdio(ctx, os.Stdin, os.Stdout); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "stdio-server: %v\n", err)
		os.Exit(1)
	}
}

func buildDemoServer() *mcp.Server {
	srv := mcp.NewServer(
		mcp.ServerInfo{Name: "passmcp-sdk-go-demo", Version: "0.0.9"},
		mcp.WithInstructions(
			"Reference MCP server built with passmcp-sdk demonstrating read-only tools, SEP-2164 resources, prompts, and SEP-2549 cache hints.",
		),
		mcp.WithCacheHints(mcp.CacheHints{
			Cacheable: true,
			TTL:       300,
			Scope:     mcp.CacheScopePublic,
		}),
	)
	registerInspectTool(srv)
	registerOverviewResource(srv)
	registerAuditPrompt(srv)
	return srv
}

func registerInspectTool(srv *mcp.Server) {
	ro, destr, idem, openWorld := true, false, true, false
	srv.RegisterTool(mcp.Tool{
		Name:  "inspect_target",
		Title: "Inspect MCP Target",
		Description: "Inspect an HTTPS or stdio MCP target endpoint and report its " +
			"transport binding without modifying server state.",
		InputSchema: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []string{"endpoint"},
			"properties": map[string]any{
				"endpoint": map[string]any{
					"type":        "string",
					"description": "HTTPS or stdio target endpoint identifier to inspect",
				},
			},
		},
		OutputSchema: map[string]any{
			"type":     "object",
			"required": []string{"endpoint", "transport"},
			"properties": map[string]any{
				"endpoint":  map[string]any{"type": "string"},
				"transport": map[string]any{"type": "string"},
			},
		},
		Annotations: &mcp.ToolAnnotations{
			Title:           "Inspect MCP Target",
			ReadOnlyHint:    &ro,
			DestructiveHint: &destr,
			IdempotentHint:  &idem,
			OpenWorldHint:   &openWorld,
		},
	}, handleInspectTarget)
}

func handleInspectTarget(_ context.Context, args map[string]any) (mcp.CallToolResult, error) {
	raw, ok := args["endpoint"].(string)
	endpoint := strings.TrimSpace(raw)
	if !ok || endpoint == "" {
		return mcp.CallToolResult{}, &mcp.RPCError{
			Code:    mcp.CodeInvalidParams,
			Message: "argument \"endpoint\" must be a non-empty string",
		}
	}
	transport := "stdio"
	lower := strings.ToLower(endpoint)
	if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://") {
		transport = "http"
	}
	summary := fmt.Sprintf("Target %s uses %s transport.", endpoint, transport)
	return mcp.StructuredTextResult(summary, map[string]any{
		"endpoint":  endpoint,
		"transport": transport,
	}), nil
}

func registerOverviewResource(srv *mcp.Server) {
	srv.RegisterResource(mcp.Resource{
		URI:         "passmcp://sdk/overview",
		Name:        "sdk-overview",
		Title:       "SDK Overview",
		Description: "Overview of the passmcp SDK capabilities and supported MCP revisions.",
		MimeType:    "text/plain",
	}, func(_ context.Context, uri string) (mcp.ResourceContents, error) {
		return mcp.ResourceContents{
			URI:      uri,
			MimeType: "text/plain",
			Text: "passmcp-sdk-go supports MCP revisions 2026-07-28, 2025-11-25, and " +
				"2025-06-18 over stdio and Streamable HTTP.",
		}, nil
	})
}

func registerAuditPrompt(srv *mcp.Server) {
	srv.RegisterPrompt(mcp.Prompt{
		Name:        "audit_summary",
		Title:       "Audit Summary Prompt",
		Description: "Generate a concise audit summary prompt for a named MCP server.",
		Arguments: []mcp.PromptArgument{
			{
				Name:        "server_name",
				Description: "Name of the MCP server being audited",
				Required:    true,
			},
		},
	}, func(_ context.Context, args map[string]string) (mcp.GetPromptResult, error) {
		name := args["server_name"]
		return mcp.GetPromptResult{
			Description: "Audit summary prompt for " + name,
			Messages: []mcp.PromptMessage{
				{
					Role: "user",
					Content: mcp.ContentBlock{
						Type: "text",
						Text: fmt.Sprintf("Summarize the MCP conformance and attestation posture for %s.", name),
					},
				},
			},
		}, nil
	})
}
