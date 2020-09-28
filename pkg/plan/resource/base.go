package resource

import (
	"context"

	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan"
)

// Base can be embedded into a struct to provide a default implementation of
// plan.Resource.
type Base struct{}

var _ plan.Resource = plan.RegisterResource(&Base{})

// State implements plan.Resource.
func (b *Base) State() plan.State {
	return plan.EmptyState
}

// QueryState implements plan.Resource.
func (b *Base) QueryState(ctx context.Context, runner plan.Runner) (plan.State, error) {
	return plan.EmptyState, nil
}

// Apply implements plan.Resource.
func (b *Base) Apply(ctx context.Context, runner plan.Runner, diff plan.Diff) (bool, error) {
	return true, nil
}

// Undo implements plan.Resource.
func (b *Base) Undo(ctx context.Context, runner plan.Runner, current plan.State) error {
	return nil
}
