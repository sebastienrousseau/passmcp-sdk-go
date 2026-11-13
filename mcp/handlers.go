// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

func (s *Server) dispatchCatalog(ctx context.Context, method string, params json.RawMessage) (any, *RPCError) {
	switch method {
	case "tools/list":
		return s.handleToolsList()
	case "tools/call":
		return s.handleToolsCall(ctx, params)
	case "resources/list":
		return s.handleResourcesList()
	case "resources/templates/list":
		return s.handleTemplatesList()
	case "resources/read":
		return s.handleResourcesRead(ctx, params)
	case "prompts/list":
		return s.handlePromptsList()
	case "prompts/get":
		return s.handlePromptsGet(ctx, params)
	default:
		return nil, &RPCError{Code: CodeMethodNotFound, Message: "method not found: " + method}
	}
}

func (s *Server) handleInitialize() InitializeResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return InitializeResult{
		ProtocolVersion: s.revision,
		Capabilities:    s.capabilitiesLocked(),
		ServerInfo:      s.info,
		Instructions:    s.instructions,
	}
}

func (s *Server) listHintsLocked() (int, string, bool, *RPCError) {
	if s.revision != Revision20260728 || s.cacheHints == nil {
		return 0, "", false, nil
	}
	ttlMs, scope, err := s.cacheHints.Effective()
	if err != nil {
		return 0, "", false, &RPCError{Code: CodeInternalError, Message: err.Error()}
	}
	return ttlMs, scope, true, nil
}

func (s *Server) handleDiscover() (DiscoverResult, *RPCError) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.revision != Revision20260728 {
		return DiscoverResult{}, &RPCError{Code: CodeMethodNotFound, Message: "method not found: server/discover"}
	}
	ttlMs, scope, hasHints, rpcErr := s.listHintsLocked()
	if rpcErr != nil {
		return DiscoverResult{}, rpcErr
	}
	infoCopy := s.info
	var meta *DiscoverMeta
	if hasHints {
		meta = &DiscoverMeta{ServerInfo: &infoCopy, TTLMs: ttlMs, CacheScope: scope}
	}
	out := DiscoverResult{
		ResultType:        "discover",
		ProtocolVersion:   s.revision,
		SupportedVersions: []string{Revision20260728, Revision20251125, Revision20250618},
		ServerInfo:        s.info,
		Capabilities:      s.capabilitiesLocked(),
		Instructions:      s.instructions,
		Meta:              meta,
	}
	s.populateDiscoverListsLocked(&out)
	return out, nil
}

func (s *Server) populateDiscoverListsLocked(out *DiscoverResult) {
	if len(s.tools) > 0 {
		out.Tools = s.collectToolsLocked()
	}
	if len(s.resources) > 0 {
		out.Resources = s.collectResourcesLocked()
	}
	if len(s.templates) > 0 {
		out.ResourceTemplates = s.collectTemplatesLocked()
	}
	if len(s.prompts) > 0 {
		out.Prompts = s.collectPromptsLocked()
	}
}

func (s *Server) collectToolsLocked() []Tool {
	list := make([]Tool, 0, len(s.toolOrder))
	for _, name := range s.toolOrder {
		list = append(list, s.tools[name].tool)
	}
	return list
}

func (s *Server) collectResourcesLocked() []Resource {
	list := make([]Resource, 0, len(s.resourceOrder))
	for _, uri := range s.resourceOrder {
		list = append(list, s.resources[uri].resource)
	}
	return list
}

func (s *Server) collectTemplatesLocked() []ResourceTemplate {
	list := make([]ResourceTemplate, 0, len(s.templates))
	for _, entry := range s.templates {
		list = append(list, entry.template)
	}
	return list
}

func (s *Server) collectPromptsLocked() []Prompt {
	list := make([]Prompt, 0, len(s.promptOrder))
	for _, name := range s.promptOrder {
		list = append(list, s.prompts[name].prompt)
	}
	return list
}

func listEnvelope(key string, items any, ttlMs int, scope string, stateless bool) map[string]any {
	out := map[string]any{key: items}
	if stateless {
		out["resultType"] = "complete"
		out["ttlMs"] = ttlMs
		out["cacheScope"] = scope
		out["_meta"] = map[string]any{"ttlMs": ttlMs, "cacheScope": scope}
	}
	return out
}

func (s *Server) handleToolsList() (any, *RPCError) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.tools) == 0 {
		return nil, &RPCError{Code: CodeMethodNotFound, Message: "capability not declared: tools"}
	}
	ttlMs, scope, stateless, rpcErr := s.listHintsLocked()
	if rpcErr != nil {
		return nil, rpcErr
	}
	return listEnvelope("tools", s.collectToolsLocked(), ttlMs, scope, stateless), nil
}

func (s *Server) handleToolsCall(ctx context.Context, params json.RawMessage) (any, *RPCError) {
	s.mu.RLock()
	hasTools := len(s.tools) > 0
	s.mu.RUnlock()
	if !hasTools {
		return nil, &RPCError{Code: CodeMethodNotFound, Message: "capability not declared: tools"}
	}
	var req struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if len(params) == 0 || json.Unmarshal(params, &req) != nil || strings.TrimSpace(req.Name) == "" {
		return nil, &RPCError{Code: CodeInvalidParams, Message: "invalid tools/call params: name is required"}
	}
	s.mu.RLock()
	entry, ok := s.tools[req.Name]
	s.mu.RUnlock()
	if !ok || entry.handler == nil {
		return nil, &RPCError{Code: CodeInvalidParams, Message: "unknown tool: " + req.Name}
	}
	if rpcErr := validateToolArgs(entry.tool.InputSchema, req.Arguments); rpcErr != nil {
		return nil, rpcErr
	}
	res, err := entry.handler(ctx, req.Arguments)
	if err != nil {
		var rpcErr *RPCError
		if errors.As(err, &rpcErr) {
			return nil, rpcErr
		}
		return ErrorTextResult(err.Error()), nil
	}
	return res, nil
}

func (s *Server) handleResourcesList() (any, *RPCError) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.resources) == 0 && len(s.templates) == 0 {
		return nil, &RPCError{Code: CodeMethodNotFound, Message: "capability not declared: resources"}
	}
	ttlMs, scope, stateless, rpcErr := s.listHintsLocked()
	if rpcErr != nil {
		return nil, rpcErr
	}
	return listEnvelope("resources", s.collectResourcesLocked(), ttlMs, scope, stateless), nil
}

func (s *Server) handleTemplatesList() (any, *RPCError) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.resources) == 0 && len(s.templates) == 0 {
		return nil, &RPCError{Code: CodeMethodNotFound, Message: "capability not declared: resources"}
	}
	ttlMs, scope, stateless, rpcErr := s.listHintsLocked()
	if rpcErr != nil {
		return nil, rpcErr
	}
	return listEnvelope("resourceTemplates", s.collectTemplatesLocked(), ttlMs, scope, stateless), nil
}

func (s *Server) handleResourcesRead(ctx context.Context, params json.RawMessage) (any, *RPCError) {
	s.mu.RLock()
	hasResources := len(s.resources) > 0 || len(s.templates) > 0
	revision := s.revision
	s.mu.RUnlock()
	if !hasResources {
		return nil, &RPCError{Code: CodeMethodNotFound, Message: "capability not declared: resources"}
	}
	var req struct {
		URI string `json:"uri"`
	}
	if len(params) == 0 || json.Unmarshal(params, &req) != nil || strings.TrimSpace(req.URI) == "" {
		return nil, &RPCError{Code: CodeInvalidParams, Message: "invalid resources/read params: uri is required"}
	}
	handler := s.lookupResourceHandler(req.URI)
	if handler == nil {
		return nil, missingResourceError(revision, req.URI)
	}
	contents, err := handler(ctx, req.URI)
	if err != nil {
		return nil, &RPCError{Code: CodeInternalError, Message: err.Error()}
	}
	return ReadResourceResult{Contents: []ResourceContents{contents}}, nil
}

func (s *Server) lookupResourceHandler(uri string) ResourceHandler {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if entry, ok := s.resources[uri]; ok {
		return entry.handler
	}
	for _, entry := range s.templates {
		if matchesTemplatePrefix(entry.template.URITemplate, uri) {
			return entry.handler
		}
	}
	return nil
}

func matchesTemplatePrefix(uriTemplate, uri string) bool {
	prefix, _, hasVar := strings.Cut(uriTemplate, "{")
	if !hasVar {
		return uriTemplate == uri
	}
	return prefix != "" && strings.HasPrefix(uri, prefix) && len(uri) > len(prefix)
}

func (s *Server) handlePromptsList() (any, *RPCError) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.prompts) == 0 {
		return nil, &RPCError{Code: CodeMethodNotFound, Message: "capability not declared: prompts"}
	}
	ttlMs, scope, stateless, rpcErr := s.listHintsLocked()
	if rpcErr != nil {
		return nil, rpcErr
	}
	return listEnvelope("prompts", s.collectPromptsLocked(), ttlMs, scope, stateless), nil
}

func (s *Server) handlePromptsGet(ctx context.Context, params json.RawMessage) (any, *RPCError) {
	s.mu.RLock()
	hasPrompts := len(s.prompts) > 0
	s.mu.RUnlock()
	if !hasPrompts {
		return nil, &RPCError{Code: CodeMethodNotFound, Message: "capability not declared: prompts"}
	}
	var req struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if len(params) == 0 || json.Unmarshal(params, &req) != nil || strings.TrimSpace(req.Name) == "" {
		return nil, &RPCError{Code: CodeInvalidParams, Message: "invalid prompts/get params: name is required"}
	}
	s.mu.RLock()
	entry, ok := s.prompts[req.Name]
	s.mu.RUnlock()
	if !ok || entry.handler == nil {
		return nil, &RPCError{Code: CodeInvalidParams, Message: "unknown prompt: " + req.Name}
	}
	if rpcErr := validatePromptArgs(entry.prompt.Arguments, req.Arguments); rpcErr != nil {
		return nil, rpcErr
	}
	res, err := entry.handler(ctx, req.Arguments)
	if err != nil {
		return nil, &RPCError{Code: CodeInternalError, Message: err.Error()}
	}
	return res, nil
}
