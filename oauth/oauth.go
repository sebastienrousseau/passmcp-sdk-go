// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Package oauth implements OAuth 2.1 S256 PKCE (RFC 7636), WWW-Authenticate
// Bearer challenge formatting and parsing (RFC 6750 / RFC 9728), Protected
// Resource Metadata discovery and resource-binding validation (RFC 9728), and
// Authorization Server Metadata discovery and validation (RFC 8414).
package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// Sentinel errors returned by PKCE, challenge, and metadata validation.
var (
	ErrInvalidVerifier       = errors.New("oauth: invalid PKCE code_verifier")
	ErrInvalidChallenge      = errors.New("oauth: malformed WWW-Authenticate Bearer challenge")
	ErrInvalidResourceURL    = errors.New("oauth: invalid protected resource URL")
	ErrResourceMismatch      = errors.New("oauth: protected resource metadata does not match endpoint")
	ErrInvalidAuthServerMeta = errors.New("oauth: invalid OAuth 2.1 authorization server metadata")
)

// GenerateVerifier generates a 43-character URL-safe base64url (no padding)
// RFC 7636 PKCE code verifier backed by 256 bits from crypto/rand.
func GenerateVerifier() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("oauth: read CSPRNG: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// ComputeS256Challenge validates verifier per RFC 7636 §4.1 (43..128 unreserved
// characters) and computes BASE64URL-NOPAD(SHA256(ASCII(verifier))).
func ComputeS256Challenge(verifier string) (string, error) {
	if err := validateVerifier(verifier); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// VerifyS256 reports whether verifier satisfies the S256 code_challenge in
// constant time.
func VerifyS256(verifier, challenge string) bool {
	if challenge == "" {
		return false
	}
	want, err := ComputeS256Challenge(verifier)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
}

func validateVerifier(v string) error {
	if len(v) < 43 || len(v) > 128 {
		return fmt.Errorf("%w: length %d outside [43, 128]", ErrInvalidVerifier, len(v))
	}
	for i := 0; i < len(v); i++ {
		if !isUnreservedChar(v[i]) {
			return fmt.Errorf("%w: invalid character at index %d", ErrInvalidVerifier, i)
		}
	}
	return nil
}

func isUnreservedChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// BearerChallenge represents parameters carried on a WWW-Authenticate: Bearer header.
type BearerChallenge struct {
	ResourceMetadata string
	Scope            string
	Error            string
	ErrorDescription string
}

// HeaderValue formats a RFC 6750 / RFC 9728 WWW-Authenticate Bearer header value.
func (c BearerChallenge) HeaderValue() string {
	var parts []string
	appendParam := func(k, v string) {
		if v != "" {
			escaped := strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`)
			parts = append(parts, fmt.Sprintf(`%s="%s"`, k, escaped))
		}
	}
	appendParam("resource_metadata", c.ResourceMetadata)
	appendParam("scope", c.Scope)
	appendParam("error", c.Error)
	appendParam("error_description", c.ErrorDescription)
	if len(parts) == 0 {
		return "Bearer"
	}
	return "Bearer " + strings.Join(parts, ", ")
}

// ParseWWWAuthenticate parses a WWW-Authenticate Bearer challenge header.
func ParseWWWAuthenticate(header string) (BearerChallenge, error) {
	trimmed := strings.TrimSpace(header)
	if trimmed == "" {
		return BearerChallenge{}, fmt.Errorf("%w: empty header", ErrInvalidChallenge)
	}
	if strings.EqualFold(trimmed, "Bearer") {
		return BearerChallenge{}, nil
	}
	if len(trimmed) < 7 || !strings.EqualFold(trimmed[:7], "Bearer ") {
		return BearerChallenge{}, fmt.Errorf("%w: scheme is not Bearer", ErrInvalidChallenge)
	}
	params, err := parseAuthParams(strings.TrimSpace(trimmed[7:]))
	if err != nil {
		return BearerChallenge{}, err
	}
	return BearerChallenge{
		ResourceMetadata: params["resource_metadata"],
		Scope:            params["scope"],
		Error:            params["error"],
		ErrorDescription: params["error_description"],
	}, nil
}

func parseAuthParams(rest string) (map[string]string, error) {
	out := make(map[string]string)
	for len(rest) > 0 {
		rest = strings.TrimLeft(rest, " \t,")
		if rest == "" {
			break
		}
		eq := strings.IndexByte(rest, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("%w: missing '=' in %q", ErrInvalidChallenge, rest)
		}
		key := strings.ToLower(strings.TrimSpace(rest[:eq]))
		val, tail, err := consumeParamValue(strings.TrimSpace(rest[eq+1:]))
		if err != nil {
			return nil, err
		}
		out[key] = val
		rest = tail
	}
	return out, nil
}

func consumeParamValue(s string) (string, string, error) {
	if s == "" {
		return "", "", fmt.Errorf("%w: empty parameter value", ErrInvalidChallenge)
	}
	if s[0] != '"' {
		end := strings.IndexByte(s, ',')
		if end < 0 {
			return strings.TrimSpace(s), "", nil
		}
		return strings.TrimSpace(s[:end]), s[end+1:], nil
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		if s[i] == '"' {
			return b.String(), s[i+1:], nil
		}
		b.WriteByte(s[i])
	}
	return "", "", fmt.Errorf("%w: unterminated quoted string", ErrInvalidChallenge)
}

// ProtectedResourceMetadata models RFC 9728 Protected Resource Metadata.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
}

// ProtectedResourceMetadataURLs returns the RFC 9728 §3.1 path-suffixed
// well-known URL and the host-root fallback well-known URL for endpoint.
func ProtectedResourceMetadataURLs(endpoint string) (pathURL string, rootURL string, err error) {
	u, err := parseHTTPSOrLoopback(endpoint, ErrInvalidResourceURL)
	if err != nil {
		return "", "", err
	}
	base := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	rootURL = base + "/.well-known/oauth-protected-resource"
	cleanPath := strings.TrimRight(u.EscapedPath(), "/")
	if cleanPath == "" {
		return rootURL, rootURL, nil
	}
	return rootURL + cleanPath, rootURL, nil
}

// ValidateResourceBinding verifies that meta.Resource canonically matches
// expectedEndpoint and lists at least one authorization server (RFC 9728 §3.3).
func ValidateResourceBinding(meta ProtectedResourceMetadata, expectedEndpoint string) error {
	got, err := canonicalResourceURI(meta.Resource)
	if err != nil {
		return fmt.Errorf("%w: invalid metadata resource: %w", ErrResourceMismatch, err)
	}
	want, err := canonicalResourceURI(expectedEndpoint)
	if err != nil {
		return fmt.Errorf("%w: invalid expected endpoint: %w", ErrResourceMismatch, err)
	}
	if got != want {
		return fmt.Errorf("%w: metadata resource %q != expected %q", ErrResourceMismatch, got, want)
	}
	if len(meta.AuthorizationServers) == 0 {
		return fmt.Errorf("%w: authorization_servers is empty", ErrResourceMismatch)
	}
	return nil
}

func canonicalResourceURI(raw string) (string, error) {
	u, err := parseHTTPSOrLoopback(raw, ErrInvalidResourceURL)
	if err != nil {
		return "", err
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%w: query and fragment forbidden in resource URI", ErrInvalidResourceURL)
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + path, nil
}

// AuthorizationServerMetadata models RFC 8414 Authorization Server Metadata.
type AuthorizationServerMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RegistrationEndpoint          string   `json:"registration_endpoint,omitempty"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
}

// AuthorizationServerMetadataURL derives the RFC 8414 §3 well-known metadata
// URL for an HTTPS issuer URL.
func AuthorizationServerMetadataURL(issuer string) (string, error) {
	u, err := parseHTTPSOnly(issuer)
	if err != nil {
		return "", err
	}
	base := "https://" + strings.ToLower(u.Host)
	cleanPath := strings.TrimRight(u.EscapedPath(), "/")
	return base + "/.well-known/oauth-authorization-server" + cleanPath, nil
}

// ValidateAuthorizationServerMetadata enforces OAuth 2.1 requirements: HTTPS
// issuer matching expectedIssuer (when non-empty), HTTPS authorization and
// token endpoints, and S256 in code_challenge_methods_supported.
func ValidateAuthorizationServerMetadata(meta AuthorizationServerMetadata, expectedIssuer string) error {
	if _, err := parseHTTPSOnly(meta.Issuer); err != nil {
		return fmt.Errorf("%w: issuer: %w", ErrInvalidAuthServerMeta, err)
	}
	if expectedIssuer != "" && strings.TrimRight(meta.Issuer, "/") != strings.TrimRight(expectedIssuer, "/") {
		return fmt.Errorf("%w: issuer %q != expected %q", ErrInvalidAuthServerMeta, meta.Issuer, expectedIssuer)
	}
	if _, err := parseHTTPSOrLoopback(meta.AuthorizationEndpoint, ErrInvalidAuthServerMeta); err != nil {
		return fmt.Errorf("%w: authorization_endpoint: %w", ErrInvalidAuthServerMeta, err)
	}
	if _, err := parseHTTPSOrLoopback(meta.TokenEndpoint, ErrInvalidAuthServerMeta); err != nil {
		return fmt.Errorf("%w: token_endpoint: %w", ErrInvalidAuthServerMeta, err)
	}
	if !slices.Contains(meta.CodeChallengeMethodsSupported, "S256") {
		return fmt.Errorf("%w: code_challenge_methods_supported must contain S256", ErrInvalidAuthServerMeta)
	}
	return nil
}

func parseHTTPSOnly(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("%w: HTTPS URL required, got %q", ErrInvalidAuthServerMeta, raw)
	}
	return u, nil
}

func parseHTTPSOrLoopback(raw string, baseErr error) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("%w: malformed URL %q", baseErr, raw)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if scheme == "https" {
		return u, nil
	}
	if scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
		return u, nil
	}
	return nil, fmt.Errorf("%w: HTTPS or loopback HTTP required, got %q", baseErr, raw)
}
