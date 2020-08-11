package resource

import (
	"github.com/twelho/capi-existinginfra/pkg/plan"

	"github.com/fatih/structs"
)

// ToState creates a new State using reflection on v.
func ToState(v interface{}) plan.State {
	return structs.Map(v)
}
