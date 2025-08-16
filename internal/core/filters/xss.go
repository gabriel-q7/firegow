package filters

import (
	"context"
	"html"
	"regexp"
	"strings"

	"github.com/gabriel-q7/firegow/pkg/models"
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
				"pattern":  pattern,
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
					"pattern":  pattern,
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
