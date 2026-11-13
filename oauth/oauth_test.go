// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package oauth_test

import (
	"errors"
	"testing"

	"satellion.com/passmcp-sdk-go/oauth"
)

func TestPKCEGenerateComputeAndVerify(t *testing.T) {
	verifier, err := oauth.GenerateVerifier()
	if err != nil {
		t.Fatalf("GenerateVerifier: %v", err)
	}
	if len(verifier) < 43 || len(verifier) > 128 {
		t.Fatalf("verifier length %d outside [43, 128]", len(verifier))
	}

	// RFC 7636 Appendix B test vector.
	const rfcVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	got, err := oauth.ComputeS256Challenge(rfcVerifier)
	if err != nil || got != rfcChallenge {
		t.Fatalf("ComputeS256Challenge = %q, err=%v; want %q", got, err, rfcChallenge)
	}
	if !oauth.VerifyS256(rfcVerifier, rfcChallenge) {
		t.Fatal("VerifyS256 rejected RFC 7636 vector")
	}
	if oauth.VerifyS256(rfcVerifier, "wrong") || oauth.VerifyS256("short", rfcChallenge) || oauth.VerifyS256(rfcVerifier, "") {
		t.Fatal("VerifyS256 accepted invalid input")
	}
	if _, err := oauth.ComputeS256Challenge("too-short"); !errors.Is(err, oauth.ErrInvalidVerifier) {
		t.Fatalf("short verifier: got %v, want ErrInvalidVerifier", err)
	}
	badChar := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX+"
	if _, err := oauth.ComputeS256Challenge(badChar); !errors.Is(err, oauth.ErrInvalidVerifier) {
		t.Fatalf("invalid char verifier: got %v, want ErrInvalidVerifier", err)
	}
}

func TestWWWAuthenticateRoundTripAndErrors(t *testing.T) {
	ch := oauth.BearerChallenge{
		ResourceMetadata: "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
		Scope:            "mcp:tools mcp:read",
		Error:            "invalid_token",
		ErrorDescription: `token "expired"`,
	}
	hdr := ch.HeaderValue()
	parsed, err := oauth.ParseWWWAuthenticate(hdr)
	if err != nil || parsed != ch {
		t.Fatalf("ParseWWWAuthenticate(%q) = %+v, err=%v; want %+v", hdr, parsed, err, ch)
	}

	emptyHeader := (oauth.BearerChallenge{}).HeaderValue()
	if emptyHeader != "Bearer" {
		t.Fatalf("empty challenge header = %q, want Bearer", emptyHeader)
	}
	if _, err := oauth.ParseWWWAuthenticate("Bearer"); err != nil {
		t.Fatalf("bare Bearer failed: %v", err)
	}
	if _, err := oauth.ParseWWWAuthenticate("Bearer realm=api, scope=read"); err != nil {
		t.Fatalf("unquoted param failed: %v", err)
	}

	for _, bad := range []string{"", "Basic realm=\"x\"", `Bearer broken`, `Bearer scope="unterminated`, `Bearer scope=`} {
		if _, err := oauth.ParseWWWAuthenticate(bad); !errors.Is(err, oauth.ErrInvalidChallenge) {
			t.Fatalf("ParseWWWAuthenticate(%q) = %v, want ErrInvalidChallenge", bad, err)
		}
	}
}

func TestProtectedResourceAndAuthServerMetadata(t *testing.T) {
	pathURL, rootURL, err := oauth.ProtectedResourceMetadataURLs("https://MCP.Example.com/mcp/")
	if err != nil {
		t.Fatalf("ProtectedResourceMetadataURLs: %v", err)
	}
	if pathURL != "https://mcp.example.com/.well-known/oauth-protected-resource/mcp" {
		t.Fatalf("pathURL = %q", pathURL)
	}
	if rootURL != "https://mcp.example.com/.well-known/oauth-protected-resource" {
		t.Fatalf("rootURL = %q", rootURL)
	}
	rootOnly, _, err := oauth.ProtectedResourceMetadataURLs("http://127.0.0.1:8080")
	if err != nil || rootOnly != "http://127.0.0.1:8080/.well-known/oauth-protected-resource" {
		t.Fatalf("loopback rootURL = %q, err=%v", rootOnly, err)
	}
	if _, _, err := oauth.ProtectedResourceMetadataURLs("http://remote.example.com/mcp"); !errors.Is(err, oauth.ErrInvalidResourceURL) {
		t.Fatalf("non-HTTPS remote: got %v, want ErrInvalidResourceURL", err)
	}

	prm := oauth.ProtectedResourceMetadata{
		Resource:             "https://mcp.example.com/mcp",
		AuthorizationServers: []string{"https://auth.example.com/tenant"},
	}
	if err := oauth.ValidateResourceBinding(prm, "https://MCP.example.com/mcp/"); err != nil {
		t.Fatalf("ValidateResourceBinding valid: %v", err)
	}
	if err := oauth.ValidateResourceBinding(prm, "https://evil.example.com/mcp"); !errors.Is(err, oauth.ErrResourceMismatch) {
		t.Fatalf("mismatched endpoint: got %v", err)
	}
	if err := oauth.ValidateResourceBinding(oauth.ProtectedResourceMetadata{Resource: "https://mcp.example.com/mcp"}, "https://mcp.example.com/mcp"); !errors.Is(err, oauth.ErrResourceMismatch) {
		t.Fatalf("empty authorization_servers: got %v", err)
	}
	if err := oauth.ValidateResourceBinding(oauth.ProtectedResourceMetadata{Resource: "https://mcp.example.com/mcp?x=1"}, "https://mcp.example.com/mcp"); !errors.Is(err, oauth.ErrResourceMismatch) {
		t.Fatalf("query in resource URI: got %v", err)
	}

	asURL, err := oauth.AuthorizationServerMetadataURL("https://auth.example.com/tenant/")
	if err != nil || asURL != "https://auth.example.com/.well-known/oauth-authorization-server/tenant" {
		t.Fatalf("AuthorizationServerMetadataURL = %q, err=%v", asURL, err)
	}
	if _, err := oauth.AuthorizationServerMetadataURL("http://auth.example.com"); !errors.Is(err, oauth.ErrInvalidAuthServerMeta) {
		t.Fatalf("HTTP issuer: got %v", err)
	}

	asm := oauth.AuthorizationServerMetadata{
		Issuer:                        "https://auth.example.com/tenant",
		AuthorizationEndpoint:         "https://auth.example.com/authorize",
		TokenEndpoint:                 "https://auth.example.com/token",
		CodeChallengeMethodsSupported: []string{"S256"},
	}
	if err := oauth.ValidateAuthorizationServerMetadata(asm, "https://auth.example.com/tenant/"); err != nil {
		t.Fatalf("ValidateAuthorizationServerMetadata valid: %v", err)
	}
	if err := oauth.ValidateAuthorizationServerMetadata(asm, "https://other.example.com"); !errors.Is(err, oauth.ErrInvalidAuthServerMeta) {
		t.Fatalf("issuer mismatch: got %v", err)
	}
	noS256 := asm
	noS256.CodeChallengeMethodsSupported = []string{"plain"}
	if err := oauth.ValidateAuthorizationServerMetadata(noS256, ""); !errors.Is(err, oauth.ErrInvalidAuthServerMeta) {
		t.Fatalf("missing S256: got %v", err)
	}
}
