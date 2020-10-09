// +build dev

package manifests

import (
	"net/http"

	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/fixeddate"
)

// Manifests contains existinginfra manifests.
var Manifests http.FileSystem = fixeddate.Dir("yaml")
