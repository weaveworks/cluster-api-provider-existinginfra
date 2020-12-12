package recipe

import (
	"testing"

	"github.com/stretchr/testify/assert"
	existinginfrav1 "github.com/weaveworks/cluster-api-provider-existinginfra/apis/cluster.weave.works/v1alpha3"

	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/resource"
)

func TestBinInstallerPkgResouce(t *testing.T) {
	rpm := resource.RPM{Name: "goo", Version: "v2.3", DisableExcludes: "kubernetes"}

	f := BinInstaller(resource.PkgTypeRHEL, nil)
	assert.NotNil(t, f)
	assert.Equal(t, &rpm, f("goo", "v2.3"))

	f = BinInstaller(resource.PkgTypeRPM, nil)
	assert.NotNil(t, f)
	assert.Equal(t, &rpm, f("goo", "v2.3"))

	f = BinInstaller(resource.PkgTypeDeb, nil)
	assert.NotNil(t, f)
	assert.Equal(t, &resource.Deb{Name: "goo", Suffix: "=v2.3-00"}, f("goo", "v2.3"))
}
func TestBinInstallerFlavor(t *testing.T) {
	cf := existinginfrav1.ClusterFlavor{Name: "eks-d", ManifestURL: "foo"}
	f := BinInstaller(resource.PkgTypeRHEL, &cf)
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
