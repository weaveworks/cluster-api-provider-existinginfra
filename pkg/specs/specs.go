package specs

import (
	log "github.com/sirupsen/logrus"
	existinginfrav1 "github.com/weaveworks/cluster-api-provider-existinginfra/apis/cluster.weave.works/v1alpha3"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/cluster/machine"
	"k8s.io/apimachinery/pkg/util/validation/field"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1alpha3"
)

// Utilities for managing cluster and machine specs.
// Common code for commands that need to run ssh commands on master cluster nodes.

type Specs struct {
	Cluster      *clusterv1.Cluster
	ClusterSpec  *existinginfrav1.ClusterSpec
	MasterSpec   *existinginfrav1.MachineSpec
	machineCount int
	masterCount  int
}

// Get a "Specs" object that can create an SSHClient (and retrieve useful nested fields)
func New(cluster *clusterv1.Cluster, eic *existinginfrav1.ExistingInfraCluster, machines []*clusterv1.Machine, bl []*existinginfrav1.ExistingInfraMachine) *Specs {
	_, master := machine.FirstMaster(machines, bl)
	if master == nil {
		log.Fatal("No master provided in manifest.")
	}
	masterCount := 0
	for _, m := range machines {
		if m.Labels["set"] == "master" {
			masterCount++
		}
	}
	return &Specs{
		Cluster:     cluster,
		ClusterSpec: &eic.Spec,
		MasterSpec:  &master.Spec,

		machineCount: len(machines),
		masterCount:  masterCount,
	}
}

// Getters for nested fields needed externally
func (s *Specs) GetClusterName() string {
	return s.Cluster.ObjectMeta.Name
}

func (s *Specs) GetKubernetesVersion() string {
	return s.ClusterSpec.KubernetesVersion
}

func (s *Specs) GetMasterPublicAddress() string {
	return s.MasterSpec.Public.Address
}

func (s *Specs) GetMasterPrivateAddress() string {
	return s.MasterSpec.Private.Address
}

func (s *Specs) GetCloudProvider() string {
	return s.ClusterSpec.CloudProvider
}

func (s *Specs) GetKubeletArguments() map[string]string {
	return TranslateServerArgumentsToStringMap(s.ClusterSpec.KubeletArguments)
}

func (s *Specs) GetMachineCount() int {
	return s.machineCount
}

func (s *Specs) GetMasterCount() int {
	return s.masterCount
}

func TranslateServerArgumentsToStringMap(args []existinginfrav1.ServerArgument) map[string]string {
	result := map[string]string{}
	for _, arg := range args {
		result[arg.Name] = arg.Value
	}
	return result
}

func PrintErrors(errors field.ErrorList) {
	for _, e := range errors {
		log.Errorf("%v\n", e)
	}
}

// populateCluster mutates the cluster manifest:
//   - fill in default values
//   - expand ~ and resolve relative path in SSH key path
func populateCluster(cluster *clusterv1.Cluster) {
	populateNetwork(cluster)
}
func populateNetwork(cluster *clusterv1.Cluster) {
	if cluster.Spec.ClusterNetwork.ServiceDomain == "" {
		cluster.Spec.ClusterNetwork.ServiceDomain = "cluster.local"
	}
}
