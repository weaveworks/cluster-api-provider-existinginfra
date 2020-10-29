package specs

import (
	"io/ioutil"
	"testing"

	"github.com/tj/assert"
	"github.com/weaveworks/cluster-api-provider-existinginfra/apis/cluster.weave.works/v1alpha3"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1alpha3"
)

func TestClusterManifestHandling(t *testing.T) {
	name := "foo"
	c := clusterv1.Cluster{}
	eic := v1alpha3.ExistingInfraCluster{}

	cfile, err := ioutil.TempFile("", "")
	assert.NoError(t, err)
	c.ObjectMeta.Name = name
	c.APIVersion = "cluster.x-k8s.io/v1alpha3"
	c.Kind = "Cluster"

	eic.ObjectMeta.Name = name
	eic.APIVersion = "cluster.weave.works/v1alpha3"
	eic.Kind = "ExistingInfraCluster"
	err = WriteManifest(&c, &eic, cfile.Name())
	assert.NoError(t, err)
	c2, eic2, err := ParseClusterManifest(cfile.Name())
	assert.NoError(t, err)
	assert.Equal(t, c.ObjectMeta.Name, c2.ObjectMeta.Name)
	assert.Equal(t, eic.ObjectMeta.Name, eic2.ObjectMeta.Name)
}
