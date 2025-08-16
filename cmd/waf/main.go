package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/gabriel-q7/firegow/internal/core/engine"
	"github.com/gabriel-q7/firegow/internal/core/filters"
	"github.com/gabriel-q7/firegow/pkg/models"
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
				"error":  "Request blocked by WAF",
				"reason": result.Reason,
				"rule":   result.RuleMatched,
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
