package resource

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan"
)

func TestToState(t *testing.T) {
	rpm := &RPM{
		Name:    "make",
		Version: "3.83",
	}
	expected := plan.State(map[string]interface{}{
		"name":    "make",
		"version": "3.83",
	})
	assert.Equal(t, expected, ToState(rpm))
	assert.Equal(t, expected, rpm.State())
}
