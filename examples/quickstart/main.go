// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Command quickstart demonstrates capability-gated MCP server setup,
// stateless server/discover, read-only tool invocation, and offline passmcp
// attestation verification.
package main

import (
	"context"
	"fmt"
	"os"

	"satellion.com/passmcp-reporting/attestation"
	"satellion.com/passmcp-sdk-go/mcp"
)

func main() {
	srv := mcp.NewServer(mcp.ServerInfo{Name: "billing", Version: "0.0.10"})
	srv.RegisterTool(mcp.Tool{
		Name:        "health",
		Description: "Read-only service health check",
		ReadOnly:    true,
	}, func(_ context.Context, _ map[string]any) (mcp.CallToolResult, error) {
		return mcp.TextResult("ok"), nil
	})

	raw, err := os.ReadFile("testdata/statement.json")
	if err != nil {
		panic(err)
	}
	st, err := attestation.Parse(raw)
	if err != nil || !st.Covers("http", "https://mcp.example.com/mcp") {
		panic("untrusted server")
	}

	ctx := context.Background()
	cli := mcp.NewClient(srv, mcp.RequireAttestation(st, "http", "https://mcp.example.com/mcp"))
	disc, err := cli.Discover(ctx)
	if err != nil {
		panic(err)
	}
	res, err := cli.CallTool(ctx, "health", nil)
	if err != nil {
		panic(err)
	}

	fmt.Printf(
		"server=%s protocol=%s tools=%d health=%s grade=%s\n",
		srv.Info().Name,
		disc.ProtocolVersion,
		len(disc.Tools),
		res.Content[0].Text,
		st.Predicate.Score.Grade,
	)
}
