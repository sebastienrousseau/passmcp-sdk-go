// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"math"
	"strings"
)

func validateToolArgs(schema map[string]any, args map[string]any) *RPCError {
	if len(schema) == 0 {
		return nil
	}
	for _, reqName := range extractRequiredNames(schema["required"]) {
		val, exists := args[reqName]
		if !exists || val == nil {
			return &RPCError{
				Code:    CodeInvalidParams,
				Message: fmt.Sprintf("missing required argument %q", reqName),
			}
		}
	}
	props, _ := schema["properties"].(map[string]any)
	if disallowExtra, ok := schema["additionalProperties"].(bool); ok && !disallowExtra {
		for key := range args {
			if _, declared := props[key]; !declared {
				return &RPCError{
					Code:    CodeInvalidParams,
					Message: fmt.Sprintf("unexpected argument %q is not permitted by inputSchema", key),
				}
			}
		}
	}
	return validatePropertyTypes(props, args)
}

func extractRequiredNames(raw any) []string {
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func validatePropertyTypes(props map[string]any, args map[string]any) *RPCError {
	if len(props) == 0 {
		return nil
	}
	for key, val := range args {
		spec, ok := props[key].(map[string]any)
		if !ok {
			continue
		}
		wantType, ok := spec["type"].(string)
		if !ok || wantType == "" {
			continue
		}
		if !matchesJSONType(wantType, val) {
			return &RPCError{
				Code:    CodeInvalidParams,
				Message: fmt.Sprintf("argument %q must be of type %s", key, wantType),
			}
		}
	}
	return nil
}

func matchesJSONType(want string, val any) bool {
	if val == nil {
		return false
	}
	switch want {
	case "string":
		_, ok := val.(string)
		return ok
	case "boolean":
		_, ok := val.(bool)
		return ok
	case "number":
		_, ok := val.(float64)
		return ok
	case "integer":
		return isJSONInteger(val)
	case "object":
		_, ok := val.(map[string]any)
		return ok
	case "array":
		_, ok := val.([]any)
		return ok
	default:
		return true
	}
}

func isJSONInteger(val any) bool {
	switch n := val.(type) {
	case float64:
		return !math.IsNaN(n) && !math.IsInf(n, 0) && math.Trunc(n) == n
	case int, int64:
		return true
	default:
		return false
	}
}

func validatePromptArgs(declared []PromptArgument, args map[string]string) *RPCError {
	for _, arg := range declared {
		if arg.Required && strings.TrimSpace(args[arg.Name]) == "" {
			return &RPCError{
				Code:    CodeInvalidParams,
				Message: fmt.Sprintf("missing required prompt argument %q", arg.Name),
			}
		}
	}
	return nil
}
