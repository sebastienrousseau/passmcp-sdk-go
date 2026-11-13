// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
)

type writeFlusher interface {
	Flush() error
}

// ServeStdio serves newline-delimited UTF-8 JSON-RPC 2.0 messages read from r
// and writes single-line UTF-8 JSON-RPC 2.0 responses followed by '\n' to w,
// flushing after every response. Notifications produce no output line, and
// malformed lines emit a -32700 Parse error without terminating the loop.
func (s *Server) ServeStdio(ctx context.Context, r io.Reader, w io.Writer) error {
	reader := bufio.NewReader(r)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, readErr := reader.ReadBytes('\n')
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			if err := s.handleStdioLine(ctx, trimmed, w); err != nil {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

func (s *Server) handleStdioLine(ctx context.Context, line []byte, w io.Writer) error {
	resp, err := s.HandleJSON(ctx, line)
	if err != nil {
		return err
	}
	if len(resp) == 0 {
		return nil
	}
	frame := append(bytes.TrimRight(resp, "\r\n"), '\n')
	if _, err := w.Write(frame); err != nil {
		return err
	}
	if flusher, ok := w.(writeFlusher); ok {
		return flusher.Flush()
	}
	return nil
}

// StdioTransport implements Dispatcher over newline-delimited JSON-RPC 2.0
// streams or a spawned child process.
type StdioTransport struct {
	mu     sync.Mutex
	reader *bufio.Reader
	writer io.Writer
	closer io.Closer
	cmd    *exec.Cmd
	stderr bytes.Buffer
}

// NewStdioStreamTransport wraps an in-memory or pipe reader/writer pair as a
// client StdioTransport. If w implements io.Closer, Close closes it.
func NewStdioStreamTransport(r io.Reader, w io.Writer) *StdioTransport {
	var closer io.Closer
	if c, ok := w.(io.Closer); ok {
		closer = c
	}
	return &StdioTransport{
		reader: bufio.NewReader(r),
		writer: w,
		closer: closer,
	}
}

// NewStdioCommandTransport spawns command with args connected over stdin/stdout
// pipes for full client-server stdio sessions without network sockets.
func NewStdioCommandTransport(ctx context.Context, command string, args ...string) (*StdioTransport, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp: stdio stdin pipe: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdinPipe.Close()
		return nil, fmt.Errorf("mcp: stdio stdout pipe: %w", err)
	}
	t := &StdioTransport{
		reader: bufio.NewReader(stdoutPipe),
		writer: stdinPipe,
		closer: stdinPipe,
		cmd:    cmd,
	}
	cmd.Stderr = &t.stderr
	if err := cmd.Start(); err != nil {
		_ = stdinPipe.Close()
		return nil, fmt.Errorf("mcp: start stdio command %q: %w", command, err)
	}
	return t, nil
}

// Stderr returns any diagnostic output written by a spawned child to stderr.
func (t *StdioTransport) Stderr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stderr.String()
}

// Close closes the outbound stdin stream and waits for any spawned child
// process to exit cleanly.
func (t *StdioTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	var closeErr error
	if t.closer != nil {
		closeErr = t.closer.Close()
		t.closer = nil
	}
	if t.cmd != nil {
		if waitErr := t.cmd.Wait(); waitErr != nil && closeErr == nil {
			closeErr = waitErr
		}
		t.cmd = nil
	}
	return closeErr
}

// HandleJSON writes one newline-delimited JSON-RPC frame and reads the
// single-line response (unless raw is a JSON-RPC notification without id).
func (t *StdioTransport) HandleJSON(ctx context.Context, raw []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.writeFrameLocked(raw); err != nil {
		return nil, err
	}
	if isNotificationPayload(raw) {
		return nil, nil
	}
	return t.readFrameLocked(ctx)
}

func (t *StdioTransport) writeFrameLocked(raw []byte) error {
	clean := bytes.ReplaceAll(bytes.TrimSpace(raw), []byte{'\n'}, []byte{' '})
	clean = bytes.ReplaceAll(clean, []byte{'\r'}, nil)
	if _, err := t.writer.Write(append(clean, '\n')); err != nil {
		return fmt.Errorf("mcp: write stdio frame: %w", err)
	}
	if flusher, ok := t.writer.(writeFlusher); ok {
		if err := flusher.Flush(); err != nil {
			return fmt.Errorf("mcp: flush stdio frame: %w", err)
		}
	}
	return nil
}

func (t *StdioTransport) readFrameLocked(ctx context.Context) ([]byte, error) {
	type readResult struct {
		line []byte
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		for {
			line, err := t.reader.ReadBytes('\n')
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) > 0 {
				ch <- readResult{line: trimmed}
				return
			}
			if err != nil {
				ch <- readResult{err: err}
				return
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.err != nil {
			return nil, fmt.Errorf("mcp: read stdio response: %w", res.err)
		}
		return res.line, nil
	}
}

func isNotificationPayload(raw []byte) bool {
	var peek struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	return json.Unmarshal(raw, &peek) == nil && peek.Method != "" && len(peek.ID) == 0
}
