package resource

import (
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan"

	"github.com/fatih/structs"
)

// ToState creates a new State using reflection on v.
func ToState(v interface{}) plan.State {
	return structs.Map(v)
}
