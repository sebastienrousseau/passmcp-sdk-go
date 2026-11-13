<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<h1 align="center">passmcp-sdk-go</h1>

<p align="center">
  Apache-2.0 Go MCP client and server SDK (`satellion.com/passmcp-sdk-go`) with capability-gated `2026-07-28` conformance and offline `passmcp` attestation verification.
</p>

<p align="center">
  <a href="https://github.com/sebastienrousseau/passmcp-sdk-go/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/sebastienrousseau/passmcp-sdk-go/ci.yml?branch=main&style=for-the-badge" alt="Build: CI status" /></a>
  <a href="https://github.com/sebastienrousseau/passmcp-sdk-go/releases"><img src="https://img.shields.io/github/v/release/sebastienrousseau/passmcp-sdk-go?style=for-the-badge" alt="Release: latest tag" /></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=for-the-badge" alt="License: Apache-2.0" /></a>
  <a href="https://github.com/sebastienrousseau/passmcp-sdk-go"><img src="https://img.shields.io/badge/go-1.26%2B-00ADD8?style=for-the-badge" alt="Go 1.26+" /></a>
</p>


## Contents

- [Install](#install)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [The passmcp-sdk-go ecosystem](#the-passmcp-sdk-go-ecosystem)
- [Capabilities at a glance](#capabilities-at-a-glance)
- [Ecosystem comparison](#ecosystem-comparison)
- [Benchmarks](#benchmarks)
- [Features](#features)
- [Configuration](#configuration)
- [Examples](#examples)
- [When not to use passmcp-sdk-go](#when-not-to-use-passmcp-sdk-go)
- [Development](#development)
- [Security](#security)
- [Documentation](#documentation)
- [Stability guarantees](#stability-guarantees)
- [License](#license)

---

## Install

```sh
go get satellion.com/passmcp-sdk-go@v0.0.10
```

---

## Requirements

| Requirement | Floor | Notes |
| :--- | :--- | :--- |
| Toolchain | Go 1.26+ | Enforced in `go.mod` and `.github/workflows/ci.yml` |
| Licence | Apache-2.0 | Safe to embed in proprietary and open-source gateways, agents, and servers |
| Network | None for verification | Attestation parsing and `covers()` run strictly offline |

---

## Quick Start

```go
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

	raw, _ := os.ReadFile("testdata/statement.json")
	st, err := attestation.Parse(raw)
	if err != nil || !st.Covers("http", "https://mcp.example.com/mcp") {
		panic("untrusted server")
	}
	fmt.Println(srv.Info().Name, st.Predicate.Score.Grade)
}
```

---

## The passmcp-sdk-go ecosystem

Every component is released at **0.0.10** and moves in lockstep: one version across the family, released together ([docs/ecosystem.md](https://github.com/sebastienrousseau/passmcp/blob/main/docs/ecosystem.md)).

| Component | Purpose | Use case |
| :--- | :--- | :--- |
| [passmcp](https://github.com/sebastienrousseau/passmcp) | The MCP server diagnostic: checks in nine phases, every finding tied to the request that showed it, signed attestations | Test a server before your agents trust it, and gate it in CI |
| [passmcp-reporting](https://github.com/sebastienrousseau/passmcp-reporting) | The attestation format, its JSON Schemas and offline verifier, the graph model, and the agentgateway processor | Verify an attestation in a gateway, registry or pipeline |
| [passmcp-server](https://github.com/sebastienrousseau/passmcp-server) | passmcp's diagnostics as read-only MCP tools | Evaluate a server, or check an attestation, from inside the agent |
| [passmcp-action](https://github.com/sebastienrousseau/passmcp-action) | passmcp in GitHub Actions and GitLab CI, the image pinned by digest | Fail a build on the findings you choose |
| [passmcp-graph](https://github.com/sebastienrousseau/passmcp-graph) | A local graph of agents, servers, tools and identities built from attestations | Find inherited risk and over-privilege, and gate on policy |
| [passmcp-registry](https://github.com/sebastienrousseau/passmcp-registry) | A signed public scorecard of the MCP Registry's remote servers (no run published yet) | Check a public server's standing before connecting to it |
| [passmcp-lsp](https://github.com/sebastienrousseau/passmcp-lsp) | A language server for MCP artefacts, with check-id hover from the guidance catalogue | Catch mistakes in server.json, tool schemas and client configuration while editing |
| [passmcp-census](https://github.com/sebastienrousseau/passmcp-census) | The reliability census: methodology, disclosure log and reproduction command (no edition published yet) | Cite ecosystem-wide reliability figures, and reproduce them, once an edition is published |
| [satellion.com](https://github.com/sebastienrousseau/satellion.github.io) | The website, the Go module paths and the format URIs | Read the manual, and resolve `satellion.com/...` imports |
| [passmcp-sdk-go](https://github.com/sebastienrousseau/passmcp-sdk-go) | Apache-2.0 Go MCP client and server SDK with offline attestation verification (not yet released) | Build an MCP server or client in Go that clears passmcp's checks and verifies attestations offline |
| [passmcp-sdk-python](https://github.com/sebastienrousseau/passmcp-sdk-python) | Apache-2.0 Python MCP client and server SDK with offline attestation verification (not yet released) | Build an MCP server or client in Python that clears passmcp's checks and verifies attestations offline |
| [passmcp-sdk-java](https://github.com/sebastienrousseau/passmcp-sdk-java) | Apache-2.0 Java MCP client and server SDK with offline attestation verification (not yet released) | Build an MCP server or client in Java that clears passmcp's checks and verifies attestations offline |
| [passmcp-sdk-cpp](https://github.com/sebastienrousseau/passmcp-sdk-cpp) | Apache-2.0 C++20 MCP client and server SDK with offline attestation verification (not yet released) | Build an MCP server or client in C++ that clears passmcp's checks and verifies attestations offline |
| [passmcp-sdk-typescript](https://github.com/sebastienrousseau/passmcp-sdk-typescript) | Apache-2.0 TypeScript MCP client and server SDK with offline attestation verification (not yet released) | Build an MCP server or client in TypeScript that clears passmcp's checks and verifies attestations offline |
| [passmcp-sdk-rust](https://github.com/sebastienrousseau/passmcp-sdk-rust) | Apache-2.0 Rust MCP client and server SDK with offline attestation verification (not yet released) | Build an MCP server or client in Rust that clears passmcp's checks and verifies attestations offline |

---

## Capabilities at a glance

| Area | Capability | Status |
| :--- | :--- | :--- |
| Protocol | JSON-RPC 2.0 `initialize`, `ping`, and stateless `server/discover` (`2025-06-18` through `2026-07-28`) | Released in `0.0.10` |
| Transports | Newline-delimited `stdio` (`ServeStdio`, `StdioTransport`) and Streamable `http` (`ServeHTTP`, `HTTPTransport`, `-32020` mirrored header check, `Mcp-Session-Id`) | Released in `0.0.10` |
| OAuth 2.1 & PKCE | RFC 7636 `S256` PKCE, RFC 9728 Protected Resource Metadata & `WWW-Authenticate` challenges, and RFC 8414 Authorization Server validation (`oauth`) | Released in `0.0.10` |
| Capability gating | Derived `capabilities`; undeclared `tools/*`, `resources/*`, and `prompts/*` return `-32601` (`404` on stateless HTTP) | Released in `0.0.10` |
| SEP-2164 | Missing `resources/read` returns `-32602` with `error.data.uri` on `2026-07-28` (`-32002` on earlier revisions) | Released in `0.0.10` |
| SEP-2549 | `ttlMs` (`>= 0`) and `cacheScope` (`public` / `private`) validated and emitted on list responses | Released in `0.0.10` |
| Origin & safety | Strict HTTP `Origin` allowlist check and `readOnlyHint: true` default client execution policy | Released in `0.0.10` |
| Attestation | Offline `in-toto` `Statement/v1` (`mcp-evaluation/v1`) SHA-256 / SHA-512 target-descriptor verifier (`attest`) | Released in `0.0.10` |

---

## Ecosystem comparison

| Property | `passmcp-sdk-go` | Generic JSON-RPC / default SDK scaffolding |
| :--- | :--- | :--- |
| Undeclared capability RPCs | Derived from registered handlers; `-32601` automatically | Often left wired with empty lists or generic `-32603` errors |
| SEP-2164 & SEP-2549 (`2026-07-28`) | Built into resource reads and list responses | Hand-rolled per server |
| Client tool safety | Refuses unannotated tools by default (ADR 0004) | Executes any tool unless caller filters |
| Offline `passmcp` attestation check | Built-in `parse` / `validate` / `covers` / `verdict_for` | Custom SHA-256 + schema glue |

---

## Benchmarks

Micro-benchmarks for JSON-RPC dispatch and SHA-256 / SHA-512 statement
verification are run via `make test` and will be published with hardware notes
at the first tagged release (`v0.0.10`).

---

## Features

- **Server & client symmetry**: build servers that clear `passmcp check` and
  clients that enforce `passmcp` attestations and `readOnlyHint` policies before
  calling tools.
- **Stateless discovery (`server/discover`)**: one-request discovery of protocol
  revision, server identity, capabilities, tools, resources, templates, and
  prompts.
- **Zero-network attestation verification**: verifies `in-toto` statements
  against `passmcp-reporting`'s canonical target descriptor format.

---

## Configuration

Server and client options are passed explicitly via typed constructors (protocol
revision, allowed HTTP `Origin` values, SEP-2549 cache hints, and client
mutation policy) with zero hidden environment-variable magic.

---

## Examples

Run `make example` to execute [`examples/quickstart`](examples/quickstart/main.go),
or build [`examples/stdio-server`](examples/stdio-server/main.go) and run
`make conformance` to verify zero failures and zero warnings under
`passmcp check --stdio`.

---

## When not to use passmcp-sdk-go

- **Diagnosing an existing third-party MCP server from the CLI or CI**: use
  [`passmcp`](https://github.com/sebastienrousseau/passmcp) directly.
- **Verifying DSSE / Sigstore cryptographic signatures**: verify the outer
  envelope with `cosign` or `gh attestation verify` first, then pass the
  verified statement payload to `passmcp-sdk-go`.

---

## Development

```sh
make check
```

See [DEVELOPMENT.md](DEVELOPMENT.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Security

See [SECURITY.md](SECURITY.md) for private vulnerability reporting and security
invariants.

---

## Documentation

- [DEVELOPMENT.md](DEVELOPMENT.md)
- [ADR Index](docs/adr/README.md)
- [passmcp Ecosystem Manual](https://satellion.com/passmcp/docs/)

---

## Stability guarantees

Pre-1.0 versions move in lockstep with `passmcp` by `0.0.1` increments. Any
change to what attestation verification accepts is treated as a breaking change
requiring a tracking issue and ADR update.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
