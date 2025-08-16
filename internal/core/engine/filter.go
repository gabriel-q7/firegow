package engine

import (
	"context"
	"sort"
	"sync"

	"github.com/gabriel-q7/firegow/pkg/models"
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
