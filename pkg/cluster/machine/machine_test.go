package machine

import (
	"io/ioutil"
	"testing"

	"github.com/tj/assert"
	"github.com/weaveworks/cluster-api-provider-existinginfra/apis/cluster.weave.works/v1alpha3"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1alpha3"
)

func TestMachineManifestHandling(t *testing.T) {
	name := "foo"
	m := clusterv1.Machine{}
	eim := v1alpha3.ExistingInfraMachine{}

	cfile, err := ioutil.TempFile("", "")
	assert.NoError(t, err)
	m.ObjectMeta.Name = name
	m.APIVersion = "cluster.x-k8s.io/v1alpha3"
	m.Kind = "Machine"

	eim.ObjectMeta.Name = name
	eim.APIVersion = "cluster.weave.works/v1alpha3"
	eim.Kind = "ExistingInfraMachine"
	ms := []*clusterv1.Machine{&m}
	eims := []*v1alpha3.ExistingInfraMachine{&eim}

	err = WriteManifest(ms, eims, cfile.Name())
	assert.NoError(t, err)
	m2, eim2, err := ParseManifest(cfile.Name())
	assert.NoError(t, err)
	assert.Equal(t, m.ObjectMeta.Name, m2[0].ObjectMeta.Name)
	assert.Equal(t, eim.ObjectMeta.Name, eim2[0].ObjectMeta.Name)
}
