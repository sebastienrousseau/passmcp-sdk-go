// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Package attest provides thin, offline policy helpers around
// satellion.com/passmcp-reporting/attestation for MCP client and gateway
// admission checks.
package attest

import (
	"errors"
	"fmt"
	"strings"

	"satellion.com/passmcp-reporting/attestation"
)

// Statement aliases passmcp-reporting's verified in-toto evaluation statement.
type Statement = attestation.Statement

// Verdict aliases a single passmcp check verdict inside a Statement.
type Verdict = attestation.Verdict

// Sentinel errors returned by VerifyTarget policy evaluation.
var (
	ErrNoSuchCheck       = attestation.ErrNoSuchCheck
	ErrTargetMismatch    = errors.New("attest: statement does not cover target")
	ErrMissingScore      = errors.New("attest: statement carries no score")
	ErrScoreBelowMinimum = errors.New("attest: statement score below minimum")
	ErrDeniedFailure     = errors.New("attest: statement carries a denied failing check")
)

// Parse decodes and structurally validates an in-toto MCP evaluation statement.
func Parse(raw []byte) (*Statement, error) {
	return attestation.Parse(raw)
}

// VerifyTarget parses raw, confirms its subject digest covers transport and
// endpoint, enforces minScore when > 0, and rejects failing verdicts matching
// any check ID or phase name listed in denyFailIn.
func VerifyTarget(raw []byte, transport, endpoint string, minScore float64, denyFailIn ...string) (*Statement, error) {
	st, err := attestation.Parse(raw)
	if err != nil {
		return nil, err
	}
	if !st.Covers(transport, endpoint) {
		return nil, fmt.Errorf("%w: %s %s", ErrTargetMismatch, transport, strings.TrimSpace(endpoint))
	}
	if err := checkScore(st, minScore); err != nil {
		return nil, err
	}
	if err := checkDeniedFailures(st, denyFailIn); err != nil {
		return nil, err
	}
	return st, nil
}

func checkScore(st *Statement, minScore float64) error {
	if minScore <= 0 {
		return nil
	}
	if st.Predicate.Score == nil {
		return fmt.Errorf("%w: minimum %.2f required", ErrMissingScore, minScore)
	}
	if st.Predicate.Score.Total < minScore {
		return fmt.Errorf("%w: got %.2f, want >= %.2f",
			ErrScoreBelowMinimum, st.Predicate.Score.Total, minScore)
	}
	return nil
}

func checkDeniedFailures(st *Statement, denyFailIn []string) error {
	for _, selector := range denyFailIn {
		sel := strings.TrimSpace(selector)
		if sel == "" {
			continue
		}
		for _, v := range st.Predicate.Verdicts {
			if v.Status == "fail" && matchesSelector(v, sel) {
				return fmt.Errorf("%w: %s (phase %s)", ErrDeniedFailure, v.ID, v.Phase)
			}
		}
	}
	return nil
}

func matchesSelector(v Verdict, selector string) bool {
	return v.ID == selector || v.Phase == selector || strings.HasPrefix(v.ID, selector+".")
}
