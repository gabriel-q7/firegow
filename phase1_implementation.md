# Phase 1: Core WAF Engine Implementation Guide

## Learning Objectives

By the end of Phase 1, you'll understand:
- How HTTP reverse proxies work
- Request/response interception patterns
- Filter chain design patterns
- Rule-based processing systems
- Concurrent request handling
- Basic security vulnerability detection

## Core Concepts Overview

### 1. Web Application Firewall Fundamentals

A WAF sits between clients and your web application, analyzing HTTP requests/responses:

```
Client → WAF → Backend Server
       ↓
   [Analysis & Filtering]
   - SQL Injection Check
   - XSS Detection  
   - Rate Limiting
   - etc.
```

**Key Concept**: WAFs are **reverse proxies** with security analysis capabilities.

### 2. Filter Chain Pattern

The filter chain is a behavioral design pattern where requests pass through multiple filters:

```go
// Core Filter Interface - Every security check implements this
type Filter interface {
    Process(ctx context.Context, req *FilterRequest) (*FilterResponse, error)
    Name() string
    Priority() int // Lower number = higher priority
}
```

**Why This Pattern?**
- **Modularity**: Each filter handles one security concern
- **Composability**: Easy to add/remove security checks
- **Testability**: Test each filter independently
- **Performance**: Short-circuit on first match

## Step-by-Step Implementation

### Step 1: Project Setup and Core Types

First, let's establish the foundation:

```go
// pkg/models/request.go
package models

import (
    "context"
    "net/http"
    "time"
)

// FilterRequest wraps an HTTP request with additional context
type FilterRequest struct {
    Request   *http.Request
    Body      []byte          // Cached body for multiple reads
    ClientIP  string          // Real client IP (handles proxies)
    UserAgent string          // User-Agent header
    Timestamp time.Time       // When request was received
    Metadata  map[string]any  // Additional context data
}

// FilterResponse represents the result of filtering
type FilterResponse struct {
    Action      Action            `json:"action"`
    RuleMatched string           `json:"rule_matched,omitempty"`
    Reason      string           `json:"reason,omitempty"`
    Metadata    map[string]any   `json:"metadata,omitempty"`
    BlockTime   time.Duration    `json:"block_time,omitempty"`
}

// Action defines what to do with the request
type Action int

const (
    ActionAllow Action = iota  // Let request through
    ActionBlock               // Block request
    ActionLog                // Log but allow
    ActionChallenge          // Present challenge (future: CAPTCHA)
)
```

**Learning Point**: We separate the HTTP request from our internal representation. This gives us control over what data filters can access and allows for caching expensive operations (like reading the request body).

### Step 2: Core Filter Interface and Manager

```go
// internal/core/engine/filter.go
package engine

import (
    "context"
    "sort"
    "sync"
    
    "your-project/pkg/models"
)

// Filter interface that all security checks implement
type Filter interface {
    Process(ctx context.Context, req *models.FilterRequest) (*models.FilterResponse, error)
    Name() string
    Priority() int
}

// FilterManager orchestrates all filters
type FilterManager struct {
    filters []Filter
    mu      sync.RWMutex
}

func NewFilterManager() *FilterManager {
    return &FilterManager{
        filters: make([]Filter, 0),
    }
}

// AddFilter adds a filter and maintains priority order
func (fm *FilterManager) AddFilter(filter Filter) {
    fm.mu.Lock()
    defer fm.mu.Unlock()
    
    fm.filters = append(fm.filters, filter)
    
    // Sort by priority (lower number = higher priority)
    sort.Slice(fm.filters, func(i, j int) bool {
        return fm.filters[i].Priority() < fm.filters[j].Priority()
    })
}

// ProcessRequest runs request through all filters
func (fm *FilterManager) ProcessRequest(ctx context.Context, req *models.FilterRequest) (*models.FilterResponse, error) {
    fm.mu.RLock()
    defer fm.mu.RUnlock()
    
    // Process through each filter until one blocks or all pass
    for _, filter := range fm.filters {
        select {
        case <-ctx.Done():
            return nil, ctx.Err()
        default:
        }
        
        response, err := filter.Process(ctx, req)
        if err != nil {
            return nil, err
        }
        
        // If filter wants to block or log, return immediately
        if response.Action != models.ActionAllow {
            return response, nil
        }
    }
    
    // All filters passed
    return &models.FilterResponse{Action: models.ActionAllow}, nil
}
```

**Learning Points**:
- **Thread Safety**: Multiple goroutines will process requests simultaneously
- **Priority Ordering**: Critical filters (like rate limiting) run first
- **Short-Circuit Evaluation**: Stop processing on first block
- **Context Cancellation**: Respect timeouts and cancellations

### Step 3: SQL Injection Filter (Core Security Logic)

Now let's implement our first security filter:

```go
// internal/core/filters/sql_injection.go
package filters

import (
    "context"
    "regexp"
    "strings"
    
    "your-project/pkg/models"
)

// SQLInjectionFilter detects SQL injection attempts
type SQLInjectionFilter struct {
    patterns []*regexp.Regexp
}

func NewSQLInjectionFilter() *SQLInjectionFilter {
    // Common SQL injection patterns
    patterns := []string{
        `(?i)(\s|^)(union|select|insert|update|delete|drop|create|alter)\s`,
        `(?i)(\s|^)(or|and)\s+\d+\s*=\s*\d+`,
        `(?i)(\s|^)(or|and)\s+['"][^'"]*['"]\s*=\s*['"][^'"]*['"]`,
        `(?i)(--|#|/\*|\*/|;)`,
        `(?i)(\s|^)(exec|execute|sp_|xp_)`,
        `(?i)(information_schema|sysobjects|systables)`,
    }
    
    compiled := make([]*regexp.Regexp, len(patterns))
    for i, pattern := range patterns {
        compiled[i] = regexp.MustCompile(pattern)
    }
    
    return &SQLInjectionFilter{
        patterns: compiled,
    }
}

func (f *SQLInjectionFilter) Name() string {
    return "sql_injection"
}

func (f *SQLInjectionFilter) Priority() int {
    return 100 // High priority security filter
}

func (f *SQLInjectionFilter) Process(ctx context.Context, req *models.FilterRequest) (*models.FilterResponse, error) {
    // Check URL parameters
    if matched, pattern := f.checkString(req.Request.URL.RawQuery); matched {
        return &models.FilterResponse{
            Action:      models.ActionBlock,
            RuleMatched: f.Name(),
            Reason:      "SQL injection detected in URL parameters",
            Metadata: map[string]any{
                "pattern": pattern,
                "location": "url_params",
            },
        }, nil
    }
    
    // Check request body (for POST requests)
    if len(req.Body) > 0 {
        if matched, pattern := f.checkString(string(req.Body)); matched {
            return &models.FilterResponse{
                Action:      models.ActionBlock,
                RuleMatched: f.Name(),
                Reason:      "SQL injection detected in request body",
                Metadata: map[string]any{
                    "pattern": pattern,
                    "location": "body",
                },
            }, nil
        }
    }
    
    // Check headers (some attacks hide in custom headers)
    for name, values := range req.Request.Header {
        for _, value := range values {
            if matched, pattern := f.checkString(value); matched {
                return &models.FilterResponse{
                    Action:      models.ActionBlock,
                    RuleMatched: f.Name(),
                    Reason:      "SQL injection detected in headers",
                    Metadata: map[string]any{
                        "pattern": pattern,
                        "location": "header",
                        "header_name": name,
                    },
                }, nil
            }
        }
    }
    
    return &models.FilterResponse{Action: models.ActionAllow}, nil
}

// checkString tests a string against all SQL injection patterns
func (f *SQLInjectionFilter) checkString(s string) (bool, string) {
    s = strings.ToLower(s)
    
    for _, pattern := range f.patterns {
        if pattern.MatchString(s) {
            return true, pattern.String()
        }
    }
    
    return false, ""
}
```

**Learning Points**:
- **Regular Expressions**: Pattern matching for attack detection
- **Multiple Check Points**: URL, body, headers all need checking  
- **Metadata**: Provide context about why request was blocked
- **Case Insensitive**: Attackers use case to bypass filters
- **Performance**: Compile regexes once, reuse many times

### Step 4: XSS Filter

```go
// internal/core/filters/xss.go
package filters

import (
    "context"
    "html"
    "regexp"
    "strings"
    
    "your-project/pkg/models"
)

type XSSFilter struct {
    patterns []*regexp.Regexp
}

func NewXSSFilter() *XSSFilter {
    patterns := []string{
        `(?i)<script[^>]*>.*?</script>`,
        `(?i)javascript:`,
        `(?i)on\w+\s*=`,
        `(?i)<iframe[^>]*>`,
        `(?i)(eval|alert|confirm|prompt)\s*\(`,
        `(?i)document\.(cookie|write|domain)`,
    }
    
    compiled := make([]*regexp.Regexp, len(patterns))
    for i, pattern := range patterns {
        compiled[i] = regexp.MustCompile(pattern)
    }
    
    return &XSSFilter{patterns: compiled}
}

func (f *XSSFilter) Name() string {
    return "xss_protection"
}

func (f *XSSFilter) Priority() int {
    return 200 // After SQL injection but still high priority
}

func (f *XSSFilter) Process(ctx context.Context, req *models.FilterRequest) (*models.FilterResponse, error) {
    // Check URL parameters for XSS
    if matched, pattern := f.checkString(req.Request.URL.RawQuery); matched {
        return &models.FilterResponse{
            Action:      models.ActionBlock,
            RuleMatched: f.Name(),
            Reason:      "XSS attack detected in URL parameters",
            Metadata: map[string]any{
                "pattern": pattern,
                "location": "url_params",
            },
        }, nil
    }
    
    // Check request body
    if len(req.Body) > 0 {
        if matched, pattern := f.checkString(string(req.Body)); matched {
            return &models.FilterResponse{
                Action:      models.ActionBlock,
                RuleMatched: f.Name(),
                Reason:      "XSS attack detected in request body",
                Metadata: map[string]any{
                    "pattern": pattern,
                    "location": "body",
                },
            }, nil
        }
    }
    
    return &models.FilterResponse{Action: models.ActionAllow}, nil
}

func (f *XSSFilter) checkString(s string) (bool, string) {
    // HTML decode first (attackers often encode malicious scripts)
    decoded := html.UnescapeString(s)
    decoded = strings.ToLower(decoded)
    
    for _, pattern := range f.patterns {
        if pattern.MatchString(decoded) {
            return true, pattern.String()
        }
    }
    
    return false, ""
}
```

**Learning Point**: XSS attacks often use HTML encoding to bypass filters, so we decode first before checking.

### Step 5: Rate Limiting Filter (Stateful Filter)

This demonstrates a more complex filter that maintains state:

```go
// internal/core/filters/rate_limit.go
package filters

import (
    "context"
    "sync"
    "time"
    
    "your-project/pkg/models"
)

// RateLimitFilter implements token bucket rate limiting per IP
type RateLimitFilter struct {
    buckets       map[string]*TokenBucket
    mu            sync.RWMutex
    requestsPerMin int
    burstSize     int
    cleanupTicker *time.Ticker
}

type TokenBucket struct {
    tokens    int
    lastRefill time.Time
}

func NewRateLimitFilter(requestsPerMin, burstSize int) *RateLimitFilter {
    filter := &RateLimitFilter{
        buckets:       make(map[string]*TokenBucket),
        requestsPerMin: requestsPerMin,
        burstSize:     burstSize,
        cleanupTicker: time.NewTicker(5 * time.Minute),
    }
    
    // Clean up old buckets periodically
    go filter.cleanupRoutine()
    
    return filter
}

func (f *RateLimitFilter) Name() string {
    return "rate_limit"
}

func (f *RateLimitFilter) Priority() int {
    return 50 // Very high priority - block before expensive operations
}

func (f *RateLimitFilter) Process(ctx context.Context, req *models.FilterRequest) (*models.FilterResponse, error) {
    clientIP := req.ClientIP
    
    f.mu.Lock()
    defer f.mu.Unlock()
    
    bucket, exists := f.buckets[clientIP]
    if !exists {
        bucket = &TokenBucket{
            tokens:    f.burstSize,
            lastRefill: time.Now(),
        }
        f.buckets[clientIP] = bucket
    }
    
    // Refill tokens based on time passed
    now := time.Now()
    timePassed := now.Sub(bucket.lastRefill)
    tokensToAdd := int(timePassed.Minutes()) * f.requestsPerMin
    
    if tokensToAdd > 0 {
        bucket.tokens += tokensToAdd
        if bucket.tokens > f.burstSize {
            bucket.tokens = f.burstSize
        }
        bucket.lastRefill = now
    }
    
    // Check if request is allowed
    if bucket.tokens <= 0 {
        return &models.FilterResponse{
            Action:      models.ActionBlock,
            RuleMatched: f.Name(),
            Reason:      "Rate limit exceeded",
            BlockTime:   time.Minute,
            Metadata: map[string]any{
                "client_ip": clientIP,
                "limit": f.requestsPerMin,
            },
        }, nil
    }
    
    // Consume a token
    bucket.tokens--
    
    return &models.FilterResponse{Action: models.ActionAllow}, nil
}

func (f *RateLimitFilter) cleanupRoutine() {
    for range f.cleanupTicker.C {
        f.mu.Lock()
        now := time.Now()
        
        for ip, bucket := range f.buckets {
            // Remove buckets not used in 10 minutes
            if now.Sub(bucket.lastRefill) > 10*time.Minute {
                delete(f.buckets, ip)
            }
        }
        f.mu.Unlock()
    }
}
```

**Learning Points**:
- **Token Bucket Algorithm**: Classic rate limiting approach
- **Stateful Filtering**: Some filters need to remember past requests
- **Memory Management**: Clean up old data to prevent memory leaks
- **Goroutines**: Background cleanup runs independently

### Step 6: WAF Engine (Orchestrating Everything)

```go
// internal/core/engine/waf.go
package engine

import (
    "bytes"
    "context"
    "io"
    "net"
    "net/http"
    "strings"
    "time"
    
    "your-project/pkg/models"
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
```

**Learning Points**:
- **Request Body Handling**: Must cache body for multiple filter reads
- **Resource Limits**: Prevent DoS attacks via large request bodies
- **IP Extraction**: Handle various proxy configurations
- **Context Timeouts**: Prevent slow filters from blocking server

### Step 7: HTTP Server with WAF Integration

```go
// cmd/waf/main.go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "net/http/httputil"
    "net/url"
    "time"
    
    "your-project/internal/core/engine"
    "your-project/internal/core/filters"
    "your-project/pkg/models"
)

func main() {
    // Create WAF engine
    waf := engine.NewWAFEngine(10*1024*1024, 5*time.Second) // 10MB max body, 5s timeout
    
    // Add security filters
    waf.AddFilter(filters.NewRateLimitFilter(60, 10)) // 60 requests/min, burst of 10
    waf.AddFilter(filters.NewSQLInjectionFilter())
    waf.AddFilter(filters.NewXSSFilter())
    
    // Create proxy to backend server
    backendURL, _ := url.Parse("http://localhost:8081") // Your actual backend
    proxy := httputil.NewSingleHostReverseProxy(backendURL)
    
    // WAF middleware
    wafHandler := func(w http.ResponseWriter, r *http.Request) {
        // Process request through WAF
        result, err := waf.ProcessRequest(r)
        if err != nil {
            http.Error(w, "Internal server error", http.StatusInternalServerError)
            log.Printf("WAF processing error: %v", err)
            return
        }
        
        // Handle WAF decision
        switch result.Action {
        case models.ActionBlock:
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusForbidden)
            
            response := map[string]any{
                "error":   "Request blocked by WAF",
                "reason":  result.Reason,
                "rule":    result.RuleMatched,
            }
            json.NewEncoder(w).Encode(response)
            
            // Log the blocked request
            log.Printf("Blocked request from %s: %s", r.RemoteAddr, result.Reason)
            return
            
        case models.ActionLog:
            // Log but continue processing
            log.Printf("Suspicious request from %s: %s", r.RemoteAddr, result.Reason)
            fallthrough
            
        case models.ActionAllow:
            // Forward to backend
            proxy.ServeHTTP(w, r)
        }
    }
    
    http.HandleFunc("/", wafHandler)
    
    fmt.Println("WAF server starting on :8080")
    fmt.Println("Backend server should be running on :8081")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

**Learning Points**:
- **Reverse Proxy Pattern**: Forward legitimate requests to backend
- **Decision Handling**: Different actions require different responses
- **Logging**: Essential for monitoring and debugging
- **Error Handling**: Graceful degradation on WAF errors

## Testing Your Implementation

Create a simple test backend and test various attack scenarios:

```go
// test/backend/main.go - Simple test backend
package main

import (
    "fmt"
    "net/http"
)

func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "Backend received: %s %s\n", r.Method, r.URL.Path)
        fmt.Fprintf(w, "Headers: %v\n", r.Header)
    })
    
    fmt.Println("Test backend running on :8081")
    http.ListenAndServe(":8081", nil)
}
```

### Test Scenarios

1. **Normal Request**: `curl http://localhost:8080/api/users`
2. **SQL Injection**: `curl "http://localhost:8080/api/users?id=1' OR '1'='1"`
3. **XSS Attack**: `curl -d "comment=<script>alert('xss')</script>" http://localhost:8080/api/comments`
4. **Rate Limiting**: Run multiple rapid requests

## Key Concepts Summary

1. **Filter Chain Pattern**: Modular, composable security checks
2. **Request Interception**: Analyze before reaching backend
3. **Stateful vs Stateless**: Rate limiting needs state, pattern matching doesn't
4. **Performance Considerations**: Regex compilation, memory management, timeouts
5. **Security Depth**: Check multiple attack vectors (URL, body, headers)

## Next Learning Steps

After mastering Phase 1, you'll be ready to explore:
- Configuration management (YAML-based rules)
- Logging and monitoring systems
- More advanced attack detection algorithms
- Performance optimization techniques

This foundation gives you a working WAF that demonstrates core security engineering principles!