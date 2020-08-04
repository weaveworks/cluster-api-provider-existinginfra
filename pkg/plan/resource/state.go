package resource

import (
	"github.com/twelho/capi-existinginfra/pkg/plan"

	"github.com/fatih/structs"
)

// toState creates a new State using reflection on v.
func toState(v interface{}) plan.State {
	return structs.Map(v)
}
