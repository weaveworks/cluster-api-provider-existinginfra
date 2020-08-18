package version_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/version"
)

func TestVersionLessthanWithBothVs(t *testing.T) {
	lt, err := version.LessThan("v1.14.7", "v1.15.0")
	assert.NoError(t, err)
	assert.True(t, lt)
}

func TestVersionLessthanWithFormerV(t *testing.T) {
	lt, err := version.LessThan("v1.14.7", "1.15.0")
	assert.NoError(t, err)
	assert.True(t, lt)
}

func TestVersionLessthanWithLatterV(t *testing.T) {
	lt, err := version.LessThan("1.14.7", "v1.15.0")
	assert.NoError(t, err)
	assert.True(t, lt)
}

func TestVersionLessthanWithOutV(t *testing.T) {
	lt, err := version.LessThan("1.14.7", "1.15.0")
	assert.NoError(t, err)
	assert.True(t, lt)
}
