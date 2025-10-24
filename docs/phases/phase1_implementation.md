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

pkg/models/request.go

**Learning Point**: We separate the HTTP request from our internal representation. This gives us control over what data filters can access and allows for caching expensive operations (like reading the request body).

### Step 2: Core Filter Interface and Manager

- internal/core/engine/filter.go

**Learning Points**:
- **Thread Safety**: Multiple goroutines will process requests simultaneously
- **Priority Ordering**: Critical filters (like rate limiting) run first
- **Short-Circuit Evaluation**: Stop processing on first block
- **Context Cancellation**: Respect timeouts and cancellations

### Step 3: SQL Injection Filter (Core Security Logic)

Now let's implement our first security filter:

- internal/core/filters/sql_injection.go


**Learning Points**:
- **Regular Expressions**: Pattern matching for attack detection
- **Multiple Check Points**: URL, body, headers all need checking  
- **Metadata**: Provide context about why request was blocked
- **Case Insensitive**: Attackers use case to bypass filters
- **Performance**: Compile regexes once, reuse many times

### Step 4: XSS Filter

- internal/core/filters/xss.go

**Learning Point**: XSS attacks often use HTML encoding to bypass filters, so we decode first before checking.

### Step 5: Rate Limiting Filter (Stateful Filter)

This demonstrates a more complex filter that maintains state:

- internal/core/filters/rate_limit.go

**Learning Points**:
- **Token Bucket Algorithm**: Classic rate limiting approach
- **Stateful Filtering**: Some filters need to remember past requests
- **Memory Management**: Clean up old data to prevent memory leaks
- **Goroutines**: Background cleanup runs independently

### Step 6: WAF Engine (Orchestrating Everything)

- internal/core/engine/waf.go

**Learning Points**:
- **Request Body Handling**: Must cache body for multiple filter reads
- **Resource Limits**: Prevent DoS attacks via large request bodies
- **IP Extraction**: Handle various proxy configurations
- **Context Timeouts**: Prevent slow filters from blocking server

### Step 7: HTTP Server with WAF Integration

- cmd/waf/main.go

**Learning Points**:
- **Reverse Proxy Pattern**: Forward legitimate requests to backend
- **Decision Handling**: Different actions require different responses
- **Logging**: Essential for monitoring and debugging
- **Error Handling**: Graceful degradation on WAF errors

## Testing Your Implementation

Create a simple test backend and test various attack scenarios:

- test/backend/main.go - Simple test backend


### Test Scenarios

1. **Normal Request**: `curl http://localhost:8080/api/users`
2. **SQL Injection**: `curl "http://localhost:8080/api/users?id=1\' OR \'1\'=\'1\'"`
 - `curl "http://localhost:8080/api/users?id=1%27%20OR%20%271%27%3D%271"`
 - `curl -X POST \
     -H "Content-Type: application/json" \
     -d '{ "username": "admin", "password": "password\' OR \'1\'=\'1" }' \
     http://localhost:8080/api/login`
 - `curl -X POST \
     -d "username=admin&password=password%27+OR+%271%27%3D%271" \
     http://localhost:8080/api/login`
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