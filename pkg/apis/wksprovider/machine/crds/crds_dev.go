// +build dev

package crds

import (
	"net/http"

	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/fixeddate"
)

// CRDs contains cluster-api-provider-existinginfra's crds.
var CRDs http.FileSystem = fixeddate.Dir("../../../../../config/crd")
