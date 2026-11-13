// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http"
	"net/url"
	"strings"
)

const maxRequestBodyBytes = 4 << 20

// OriginGuard enforces a strict HTTP Origin allowlist to prevent cross-origin
// browser and DNS-rebinding requests against MCP HTTP endpoints.
type OriginGuard struct {
	allowed map[string]struct{}
}

// NewOriginGuard creates an OriginGuard permitting only the exact normalized
// scheme://host[:port] origins supplied. Wildcard ("*") and "null" entries are
// ignored so a guard can never fail open.
func NewOriginGuard(origins ...string) *OriginGuard {
	allowed := make(map[string]struct{}, len(origins))
	for _, raw := range origins {
		if norm, ok := normalizeOrigin(raw); ok {
			allowed[norm] = struct{}{}
		}
	}
	return &OriginGuard{allowed: allowed}
}

// Allowed reports whether an HTTP Origin header value is permitted. Requests
// without an Origin header (non-browser HTTP clients) are allowed; any present
// Origin header must match an explicit allowlist entry.
func (g *OriginGuard) Allowed(origin string) bool {
	if origin == "" {
		return true
	}
	if g == nil || len(g.allowed) == 0 {
		return false
	}
	norm, ok := normalizeOrigin(origin)
	if !ok {
		return false
	}
	_, exists := g.allowed[norm]
	return exists
}

// Wrap returns an http.Handler that rejects disallowed Origin headers with
// 403 Forbidden before invoking next.
func (g *OriginGuard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.Allowed(r.Header.Get("Origin")) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func normalizeOrigin(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "*" || strings.EqualFold(trimmed, "null") {
		return "", false
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	if u.Path != "" && u.Path != "/" {
		return "", false
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), true
}
