package resource

import (
	"context"
	"fmt"

	ot "github.com/opentracing/opentracing-go"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan"
)

// Deb represents a .deb package.
type Deb struct {
	Name string `structs:"name"`
	// Suffix is either "=" followed by the version, or "/" followed by the release stream (stable|testing|unstable).
	// Examples:
	//   Name: "busybox"
	//   Name: "busybox", Suffix: "/stable"
	//   Name: "busybox", Suffix: "=1:1.27.2-2ubuntu3.2"
	Suffix string `structs:"suffix"`
}

var _ plan.Resource = plan.RegisterResource(&Deb{})

func (d *Deb) State() plan.State {
	return ToState(d)
}

func (d *Deb) QueryState(ctx context.Context, runner plan.Runner) (plan.State, error) {
	span, ctx := ot.StartSpanFromContext(ctx, "Deb.QueryState", ot.Tag{Key: "name", Value: d.Name})
	defer span.Finish()
	q := dpkgQuerier{Runner: runner}
	installed, err := q.ShowInstalled(ctx, d.Name)

	if err != nil {
		return nil, err
	}

	if len(installed) == 0 {
		return plan.EmptyState, nil
	}

	return DebResourceFromPackage(installed[0]).State(), nil
}

func (d *Deb) Apply(ctx context.Context, runner plan.Runner, diff plan.Diff) (propagate bool, err error) {
	span, ctx := ot.StartSpanFromContext(ctx, "Deb.Apply", ot.Tag{Key: "name", Value: d.Name})
	defer span.Finish()
	a := aptInstaller{Runner: runner}
	if err := a.UpdateCache(ctx); err != nil {
		return false, fmt.Errorf("update cache failed: %v", err)
	}

	if err := a.Install(ctx, d.Name, d.Suffix); err != nil {
		return false, err
	}

	return true, nil
}

func (d *Deb) Undo(ctx context.Context, runner plan.Runner, current plan.State) error {
	span, ctx := ot.StartSpanFromContext(ctx, "Deb.Undo", ot.Tag{Key: "name", Value: d.Name})
	defer span.Finish()
	a := aptInstaller{Runner: runner}
	return a.Purge(ctx, d.Name)
}

func DebResourceFromPackage(p debPkgInfo) *Deb {
	return &Deb{
		Name:   p.Name,
		Suffix: "=" + p.Version,
	}
}

// WouldChangeState returns false if it's guaranteed that a call to Apply() wouldn't change the package installed, and true otherwise.
func (d *Deb) WouldChangeState(ctx context.Context, r plan.Runner) (bool, error) {
	current, err := d.QueryState(ctx, r)
	if err != nil {
		return false, err
	}
	return !current.Equal(d.State()), nil
}
