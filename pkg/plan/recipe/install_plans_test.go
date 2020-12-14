package recipe

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/flavors/eksd"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/resource"
)

func TestBinInstallerPkgResouce(t *testing.T) {
	rpm := resource.RPM{Name: "goo", Version: "v2.3", DisableExcludes: "kubernetes"}
	deb := resource.Deb{Name: "goo", Suffix: "=v2.3-00"}
	tests := []struct {
		pkg resource.PkgType
		bin string
		ver string
		exp plan.Resource
	}{
		{resource.PkgTypeRPM, "goo", "v2.3", &rpm},
		{resource.PkgTypeRHEL, "goo", "v2.3", &rpm},
		{resource.PkgTypeDeb, "goo", "v2.3", &deb},
	}
	for _, test := range tests {
		f, err := BinInstaller(test.pkg, nil)
		assert.NoError(t, err)
		assert.NotNil(t, f)
		assert.NoError(t, err)
		assert.Equal(t, test.exp, f(test.bin, test.ver))

	}
}
func TestBinInstallerFlavor(t *testing.T) {
	cf, err := eksd.New("https://distro.eks.amazonaws.com/kubernetes-1-18/kubernetes-1-18-eks-1.yaml")
	assert.NoError(t, err)

	f, err := BinInstaller(resource.PkgTypeRHEL, cf)
	assert.NoError(t, err)
	assert.NotNil(t, f)
	res, ok := f("kubelet", "v2.3").(*resource.Run)
	assert.True(t, ok)
	assert.Contains(t, res.Script, "curl -o /bin/kubelet https")
	assert.Contains(t, res.Script, "chmod 755 /bin/kubelet")

	res, ok = f("kubectl", "v2.3").(*resource.Run)
	assert.True(t, ok)
	assert.Contains(t, res.Script, "curl -o /bin/kubectl https")
	assert.Contains(t, res.Script, "chmod 755 /bin/kubectl")

}
