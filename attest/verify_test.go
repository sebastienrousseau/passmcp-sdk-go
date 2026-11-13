// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package attest_test

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"satellion.com/passmcp-sdk-go/attest"
)

func TestVerifyTargetAndPolicyGates(t *testing.T) {
	raw, err := os.ReadFile("../testdata/statement.json")
	if err != nil {
		t.Fatalf("read statement.json: %v", err)
	}

	st, err := attest.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := st.VerdictFor("missing.check"); !errors.Is(err, attest.ErrNoSuchCheck) {
		t.Fatalf("expected ErrNoSuchCheck, got %v", err)
	}

	verified, err := attest.VerifyTarget(raw, "http", "https://mcp.example.com/mcp", 80, "", "auth")
	if err != nil || verified.Predicate.Score.Grade != "B" {
		t.Fatalf("VerifyTarget valid: st=%+v err=%v", verified, err)
	}

	if _, err := attest.VerifyTarget([]byte(`{bad`), "http", "https://mcp.example.com/mcp", 0); err == nil {
		t.Fatal("expected malformed JSON error")
	}
	if _, err := attest.VerifyTarget(raw, "http", "https://other.example.com/mcp", 80); !errors.Is(err, attest.ErrTargetMismatch) {
		t.Fatalf("wrong target: got %v, want ErrTargetMismatch", err)
	}
	if _, err := attest.VerifyTarget(raw, "http", "https://mcp.example.com/mcp", 95); !errors.Is(err, attest.ErrScoreBelowMinimum) {
		t.Fatalf("low score: got %v, want ErrScoreBelowMinimum", err)
	}
	if _, err := attest.VerifyTarget(raw, "http", "https://mcp.example.com/mcp", 80, "protocol"); !errors.Is(err, attest.ErrDeniedFailure) {
		t.Fatalf("denied phase: got %v, want ErrDeniedFailure", err)
	}
	if _, err := attest.VerifyTarget(raw, "http", "https://mcp.example.com/mcp", 80, "protocol.origin"); !errors.Is(err, attest.ErrDeniedFailure) {
		t.Fatalf("denied check id: got %v, want ErrDeniedFailure", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	delete(doc["predicate"].(map[string]any), "score")
	noScoreRaw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := attest.VerifyTarget(noScoreRaw, "http", "https://mcp.example.com/mcp", 50); !errors.Is(err, attest.ErrMissingScore) {
		t.Fatalf("missing score: got %v, want ErrMissingScore", err)
	}
}
