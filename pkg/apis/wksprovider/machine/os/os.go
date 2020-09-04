package os

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	existinginfrav1 "github.com/weaveworks/cluster-api-provider-existinginfra/apis/cluster.weave.works/v1alpha3"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/config"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/recipe"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/resource"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/runners/sudo"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/envcfg"
	v1 "k8s.io/api/core/v1"
)

const (
	PemDestDir    = "/etc/pki/weaveworks/wksctl/pem"
	ConfigDestDir = "/etc/pki/weaveworks/wksctl"
)

var (
	ErrNoConfigData = errors.New("no config data for filespec")
	ErrUnknownOS    = errors.New("unknown operating system")
)

// OS represents an operating system and exposes the operations required to
// install Kubernetes on a machine setup with that OS.
type OS struct {
	Name    string
	Runner  plan.Runner
	PkgType resource.PkgType
}

// Identifiers groups the various pieces of data usable to uniquely identify a
// machine in a cluster.
type Identifiers struct {
	MachineID  string
	SystemUUID string
}

// IDs returns this machine's ID and system UUID.
func (o OS) IDs() (*Identifiers, error) {
	osres, err := resource.NewOS(o.Runner)
	if err != nil {
		return nil, err
	}
	return &Identifiers{MachineID: osres.MachineID, SystemUUID: osres.SystemUUID}, nil
}

func CreateConfigFileResourcesFromConfigMaps(fileSpecs []existinginfrav1.FileSpec, configMaps map[string]*v1.ConfigMap) ([]*resource.File, error) {
	fileResources := make([]*resource.File, len(fileSpecs))
	for idx, file := range fileSpecs {
		source := &file.Source
		fileResource := &resource.File{Destination: file.Destination}
		fileContents, ok := configMaps[source.ConfigMap].Data[source.Key]
		if ok {
			fileResource.Content = fileContents
			fileResources[idx] = fileResource
			continue
		}
		// if not in Data, check BinaryData
		binaryContents, ok := configMaps[source.ConfigMap].BinaryData[source.Key]
		if !ok {
			return nil, fmt.Errorf("%q: %w", file, ErrNoConfigData)
		}
		fileResource.Content = string(binaryContents)
		fileResources[idx] = fileResource
	}
	return fileResources, nil
}

// NodeParams groups required inputs to configure a Kubernetes node.
type NodeParams struct {
	IsMaster                 bool // true if this node is a master, false else.
	MasterIP                 string
	MasterPort               int
	Token                    string // kubeadm's --token
	DiscoveryTokenCaCertHash string // kubeadm's --discovery-token-ca-cert-hash
	CertificateKey           string // kubeadm's --certificate-key
	KubeletConfig            config.KubeletConfig
	KubernetesVersion        string
	CRI                      existinginfrav1.ContainerRuntime
	ConfigFileSpecs          []existinginfrav1.FileSpec
	ProviderConfigMaps       map[string]*v1.ConfigMap
	AuthConfigMap            *v1.ConfigMap
	Secrets                  map[string]resource.SecretData // kind of auth -> names/values as-in v1.Secret
	Namespace                string
	ControlPlaneEndpoint     string // used instead of MasterIP if existed
	AddonNamespaces          map[string]string
}

// Validate generally validates this NodeParams struct, e.g. ensures it
// contains mandatory values, that these are well-formed, etc.
func (params NodeParams) Validate() error {
	if len(params.KubeletConfig.NodeIP) == 0 {
		return errors.New("empty kubelet node IP")
	}
	return nil
}

// SetupNode installs Kubernetes on this machine and configures it based on the
// manifests stored during the initialization of the cluster, when
// SetupSeedNode was called.
func (o OS) SetupNode(p *plan.Plan) error {
	// We don't know the state of the machine so undo at the beginning
	//nolint:errcheck
	p.Undo(o.Runner, plan.EmptyState) // TODO: Implement error checking

	_, err := p.Apply(o.Runner, plan.EmptyDiff())
	if err != nil {
		log.Errorf("Apply of Plan failed:\n%s\n", err)
	}
	return err
}

// CreateNodeSetupPlan creates the plan that will be used to set up a node.
func (o OS) CreateNodeSetupPlan(params NodeParams) (*plan.Plan, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}

	cfg, err := envcfg.GetEnvSpecificConfig(o.PkgType, params.Namespace, params.KubeletConfig.CloudProvider, o.Runner)
	if err != nil {
		return nil, err
	}

	configFileResources, err := CreateConfigFileResourcesFromConfigMaps(params.ConfigFileSpecs, params.ProviderConfigMaps)
	if err != nil {
		return nil, err
	}

	b := plan.NewBuilder()

	baseRsrc := recipe.BuildBasePlan(o.PkgType)
	b.AddResource("install:base", baseRsrc)
	authConfigMap := params.AuthConfigMap
	if authConfigMap != nil && params.IsMaster {
		for _, authType := range []string{"authentication", "authorization"} {
			if err := addAuthConfigResources(b, authConfigMap, params.Secrets[authType], authType); err != nil {
				return nil, err
			}
		}
	}

	configRes := recipe.BuildConfigPlan(configFileResources)
	b.AddResource("install:config", configRes, plan.DependOn("install:base"))
	instCriRsrc := recipe.BuildCRIPlan(&params.CRI, cfg, o.PkgType)
	b.AddResource("install.cri", instCriRsrc, plan.DependOn("install:config"))

	instK8sRsrc := recipe.BuildK8SPlan(params.KubernetesVersion, params.KubeletConfig.NodeIP, cfg.SELinuxInstalled, cfg.SetSELinuxPermissive, cfg.DisableSwap, cfg.LockYUMPkgs, o.PkgType, params.KubeletConfig.CloudProvider, params.KubeletConfig.ExtraArguments)

	b.AddResource("install:k8s", instK8sRsrc, plan.DependOn("install.cri"))

	kadmPJRsrc := recipe.BuildKubeadmPrejoinPlan(params.KubernetesVersion, cfg.UseIPTables)
	b.AddResource("kubeadm:prejoin", kadmPJRsrc, plan.DependOn("install:k8s"))

	kadmJoinRsrc := &resource.KubeadmJoin{
		IsMaster:                 params.IsMaster,
		NodeIP:                   params.KubeletConfig.NodeIP,
		NodeName:                 cfg.HostnameOverride,
		MasterIP:                 params.MasterIP,
		MasterPort:               params.MasterPort,
		Token:                    params.Token,
		DiscoveryTokenCaCertHash: params.DiscoveryTokenCaCertHash,
		CertificateKey:           params.CertificateKey,
		IgnorePreflightErrors:    cfg.IgnorePreflightErrors,
		KubernetesVersion:        params.KubernetesVersion,
	}
	b.AddResource("kubeadm:join", kadmJoinRsrc, plan.DependOn("kubeadm:prejoin"))
	return CreatePlan(b)
}

func addAuthConfigResources(b *plan.Builder, authConfigMap *v1.ConfigMap, secretData resource.SecretData, authType string) error {
	secretName := authConfigMap.Data[authType+"-secret-name"]
	if secretName != "" {
		authPemRsrc, err := resource.NewKubeSecretResource(secretName, secretData, filepath.Join(PemDestDir, secretName),
			func(s string) string {
				return s + ".pem"
			})
		if err != nil {
			return err
		}
		b.AddResource("install:"+authType+"-pem-files", authPemRsrc, plan.DependOn("install:base"))
		b.AddResource("install:"+authType+"-config", &resource.File{Content: authConfigMap.Data[authType+"-config"], Destination: filepath.Join(ConfigDestDir, secretName+".yaml")})
	}
	return nil
}

const (
	CentOS = "centos"
	Ubuntu = "ubuntu"
	RHEL   = "rhel"
)

// Identify uses the provided SSH client to identify the operating system of
// the machine it is configured to talk to.
func Identify(sshClient plan.Runner) (*OS, error) {
	osID, err := fetchOSID(sshClient)
	if err != nil {
		return nil, err
	}
	switch osID {
	case CentOS:
		return &OS{Name: osID, Runner: &sudo.Runner{Runner: sshClient}, PkgType: resource.PkgTypeRPM}, nil
	case RHEL:
		return &OS{Name: osID, Runner: &sudo.Runner{Runner: sshClient}, PkgType: resource.PkgTypeRHEL}, nil
	case Ubuntu:
		return &OS{Name: osID, Runner: &sudo.Runner{Runner: sshClient}, PkgType: resource.PkgTypeDeb}, nil
	default:
		return nil, fmt.Errorf("%q: %w", osID, ErrUnknownOS)
	}
}

var osIDRegexp = regexp.MustCompile("(?m)^ID=(.+)")

const (
	numExpectedMatches = 2
	idxOSID            = 1
)

func fetchOSID(sshClient plan.Runner) (string, error) {
	stdOut, err := sshClient.RunCommand("cat /etc/*release", nil)
	if err != nil {
		return "", errors.Wrap(err, "failed to fetch operating system ID")
	}
	matches := osIDRegexp.FindStringSubmatch(stdOut)
	if len(matches) != numExpectedMatches {
		return "", errors.New("failed to identify operating system")
	}
	return strings.Trim(matches[idxOSID], ` "`), nil
}

// CreatePlan generates a plan from a plan builder
func CreatePlan(b *plan.Builder) (*plan.Plan, error) {
	p, err := b.Plan()
	if err != nil {
		log.Infof("Plan creation failed:\n%s\n", err)
		return nil, err
	}
	return &p, nil
}
