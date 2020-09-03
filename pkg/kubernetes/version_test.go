package kubernetes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/version"
)

func TestMatchesRangeDefaultVersion(t *testing.T) {
	matches, err := version.MatchesRange(DefaultVersion, DefaultVersionsRange)
	assert.NoError(t, err)
	assert.True(t, matches)
}
