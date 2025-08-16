package filters

import (
	"context"
	"regexp"
	"strings"

	"github.com/gabriel-q7/firegow/pkg/models"
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
				"pattern":  pattern,
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
					"pattern":  pattern,
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
						"pattern":     pattern,
						"location":    "header",
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
