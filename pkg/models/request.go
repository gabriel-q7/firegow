package models

import (
	"net/http"
	"time"
)

// FilterRequest wraps an HTTP request with additional context
type FilterRequest struct {
	Request   *http.Request
	Body      []byte         // Cached body for multiple reads
	ClientIP  string         // Real client IP (handles proxies)
	UserAgent string         // User-Agent header
	Timestamp time.Time      // When request was received
	Metadata  map[string]any // Additional context data
}

// FilterResponse represents the result of filtering
type FilterResponse struct {
	Action      Action         `json:"action"`
	RuleMatched string         `json:"rule_matched,omitempty"`
	Reason      string         `json:"reason,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	BlockTime   time.Duration  `json:"block_time,omitempty"`
}

// Action defines what to do with the request
type Action int

const (
	ActionAllow     Action = iota // Let request through
	ActionBlock                   // Block request
	ActionLog                     // Log but allow
	ActionChallenge               // Present challenge (future: CAPTCHA)
)
