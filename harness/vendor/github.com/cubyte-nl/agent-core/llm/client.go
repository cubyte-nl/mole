// Package llm is a minimal client for OpenAI-compatible chat-completions
// endpoints with function calling. The endpoint, API key and model come from
// the environment under a per-agent prefix: <PREFIX>_LLM_BASE_URL,
// <PREFIX>_LLM_API_KEY, <PREFIX>_LLM_MODEL. The model runs entirely outside the
// harness; it only ever acts through the tools the registry exposes.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Function is one model-requested tool invocation. Arguments is raw JSON.
type Function struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ToolCall identifies a function call in an assistant message.
type ToolCall struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Function Function `json:"function"`
}

// Message is one chat message in any role.
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// FunctionSpec describes a tool for the model.
type FunctionSpec struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// ToolSpec is the wire format of a tool definition.
type ToolSpec struct {
	Type     string       `json:"type"`
	Function FunctionSpec `json:"function"`
}

type chatRequest struct {
	Model    string     `json:"model"`
	Messages []Message  `json:"messages"`
	Tools    []ToolSpec `json:"tools,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message      Message `json:"message"`
		FinishReason string  `json:"finish_reason"`
	} `json:"choices"`
}

// Client talks to one OpenAI-compatible endpoint.
type Client struct {
	baseURL string
	apiKey  string
	model   string
	http    *http.Client
}

// New builds a client from the <prefix>_LLM_* environment variables, e.g.
// New("COLLIE") reads COLLIE_LLM_BASE_URL / COLLIE_LLM_API_KEY / COLLIE_LLM_MODEL.
func New(prefix string) (*Client, error) {
	base := os.Getenv(prefix + "_LLM_BASE_URL")
	model := os.Getenv(prefix + "_LLM_MODEL")
	if base == "" || model == "" {
		return nil, fmt.Errorf("set %[1]s_LLM_BASE_URL and %[1]s_LLM_MODEL (optionally %[1]s_LLM_API_KEY)", prefix)
	}
	return NewClient(base, os.Getenv(prefix+"_LLM_API_KEY"), model), nil
}

// NewClient builds a client for an explicit endpoint.
func NewClient(baseURL, apiKey, model string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		model:   model,
		http:    &http.Client{Timeout: 10 * time.Minute},
	}
}

// Model returns the configured model name (for transcripts and reports).
func (c *Client) Model() string { return c.model }

// maxChatAttempts bounds how many times Chat retries a transient failure
// (network error, timeout, 429, or 5xx) before giving up.
const maxChatAttempts = 4

// Chat sends the conversation and returns the assistant's reply together with
// the choice's finish_reason ("stop", "tool_calls", "length", ...). A single
// transient failure — network error, 429, or 5xx — is retried with backoff
// rather than aborting the whole run; the context bounds the wait.
func (c *Client) Chat(ctx context.Context, msgs []Message, tools []ToolSpec) (*Message, string, error) {
	body, err := json.Marshal(chatRequest{Model: c.model, Messages: msgs, Tools: tools})
	if err != nil {
		return nil, "", err
	}
	var lastErr error
	for attempt := 1; attempt <= maxChatAttempts; attempt++ {
		msg, finish, retryable, err := c.chatOnce(ctx, body)
		if err == nil {
			return msg, finish, nil
		}
		lastErr = err
		if !retryable || attempt == maxChatAttempts || ctx.Err() != nil {
			break
		}
		backoff := time.Duration(attempt) * 500 * time.Millisecond
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-time.After(backoff):
		}
	}
	return nil, "", lastErr
}

// chatOnce performs a single request. retryable reports whether err is worth
// retrying (transport error, timeout, 429, or 5xx); a 4xx is permanent.
func (c *Client) chatOnce(ctx context.Context, body []byte) (msg *Message, finish string, retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, "", false, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// Transport errors (connection refused, timeout, reset) are transient;
		// a cancelled context is not.
		return nil, "", ctx.Err() == nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, "", ctx.Err() == nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, "", retryable, fmt.Errorf("LLM endpoint returned %s: %s", resp.Status, snippet(raw, 512))
	}
	var cr chatResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return nil, "", false, fmt.Errorf("decoding LLM response: %w", err)
	}
	if len(cr.Choices) == 0 {
		return nil, "", false, fmt.Errorf("LLM endpoint returned no choices")
	}
	return &cr.Choices[0].Message, cr.Choices[0].FinishReason, false, nil
}

func snippet(raw []byte, n int) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > n {
		s = s[:n] + "…"
	}
	if s == "" {
		s = "(empty body)"
	}
	return s
}
