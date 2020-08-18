package machine

import (
	log "github.com/sirupsen/logrus"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/kubernetes"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1alpha3"
)

// GetKubernetesVersion reads the Kubernetes version of the provided machine,
// or if missing, returns the default version.
func GetKubernetesVersion(machine *clusterv1.Machine) string {
	if machine == nil {
		return kubernetes.DefaultVersion
	}
	return getKubernetesVersion(machine)
}

func getKubernetesVersion(machine *clusterv1.Machine) string {
	if machine.Spec.Version != nil {
		return *machine.Spec.Version
	}
	log.WithField("machine", machine.Name).WithField("defaultVersion", kubernetes.DefaultVersion).Debug("No kubernetes version configured in manifest, falling back to default")
	return kubernetes.DefaultVersion
}
