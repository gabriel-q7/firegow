package filters

import (
	"context"
	"sync"
	"time"

	"github.com/gabriel-q7/firegow/pkg/models"
)

// RateLimitFilter implements token bucket rate limiting per IP
type RateLimitFilter struct {
	buckets        map[string]*TokenBucket
	mu             sync.RWMutex
	requestsPerMin int
	burstSize      int
	cleanupTicker  *time.Ticker
}

type TokenBucket struct {
	tokens     int
	lastRefill time.Time
}

func NewRateLimitFilter(requestsPerMin, burstSize int) *RateLimitFilter {
	filter := &RateLimitFilter{
		buckets:        make(map[string]*TokenBucket),
		requestsPerMin: requestsPerMin,
		burstSize:      burstSize,
		cleanupTicker:  time.NewTicker(5 * time.Minute),
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
			tokens:     f.burstSize,
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
				"limit":     f.requestsPerMin,
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
