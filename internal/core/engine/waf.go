package engine

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gabriel-q7/firegow/pkg/models"
)

// WAFEngine is the main component that processes HTTP requests
type WAFEngine struct {
	filterManager *FilterManager
	maxBodySize   int64
	timeout       time.Duration
}

func NewWAFEngine(maxBodySize int64, timeout time.Duration) *WAFEngine {
	return &WAFEngine{
		filterManager: NewFilterManager(),
		maxBodySize:   maxBodySize,
		timeout:       timeout,
	}
}

func (w *WAFEngine) AddFilter(filter Filter) {
	w.filterManager.AddFilter(filter)
}

// ProcessRequest is the main entry point for request analysis
func (w *WAFEngine) ProcessRequest(r *http.Request) (*models.FilterResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), w.timeout)
	defer cancel()

	// Convert HTTP request to our internal format
	filterReq, err := w.prepareFilterRequest(r)
	if err != nil {
		return nil, err
	}

	// Run through all filters
	return w.filterManager.ProcessRequest(ctx, filterReq)
}

func (w *WAFEngine) prepareFilterRequest(r *http.Request) (*models.FilterRequest, error) {
	var body []byte
	var err error

	// Read and cache request body (if present and not too large)
	if r.Body != nil {
		body, err = w.readBody(r.Body, w.maxBodySize)
		if err != nil {
			return nil, err
		}

		// Restore body for subsequent readers
		r.Body = io.NopCloser(bytes.NewBuffer(body))
	}

	return &models.FilterRequest{
		Request:   r,
		Body:      body,
		ClientIP:  w.extractClientIP(r),
		UserAgent: r.Header.Get("User-Agent"),
		Timestamp: time.Now(),
		Metadata:  make(map[string]any),
	}, nil
}

func (w *WAFEngine) readBody(body io.ReadCloser, maxSize int64) ([]byte, error) {
	defer body.Close()

	// Use LimitReader to prevent memory exhaustion
	limitedReader := io.LimitReader(body, maxSize)
	return io.ReadAll(limitedReader)
}

// extractClientIP gets the real client IP, handling proxies
func (w *WAFEngine) extractClientIP(r *http.Request) string {

	// Check common proxy headers
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		if parts := strings.Split(ip, ","); len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}

	// Fall back to remote address
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}
