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
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/object"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubeadmapi "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm/v1beta1"
	"sigs.k8s.io/yaml"
)

const (
	PemDestDir                = "/etc/pki/weaveworks/wksctl/pem"
	ConfigDestDir             = "/etc/pki/weaveworks/wksctl"
	sealedSecretVersion       = "v0.11.0"
	sealedSecretKeySecretName = "sealed-secrets-key"
	fluxSecretTemplate        = `apiVersion: v1
{{ if .SecretValue }}
data:
  identity: {{.SecretValue}}
{{ end }}
kind: Secret
metadata:
  name: flux-git-deploy
  namespace: {{.Namespace}}
type: Opaque`
)

// OS represents an operating system and exposes the operations required to
// install Kubernetes on a machine setup with that OS.
type OS struct {
	Name    string
	Runner  plan.Runner
	PkgType resource.PkgType
}

var (
	pemKeys = []string{"certificate-authority", "client-certificate", "client-key"}
)

type crdFile struct {
	fname string
	data  []byte
}

// // Retrieve all CRD definitions needed for cluster API
// func getCRDs() ([]crdFile, error) {
//  crddir, err := crds.CRDs.Open(".")
//  if err != nil {
//      return nil, errors.Wrap(err, "failed to list cluster API CRDs")
//  }
//  crdFiles := make([]crdFile, 0)
//  for {
//      entry, err := crddir.Readdir(1)
//      if err != nil && err != io.EOF {
//          return nil, errors.Wrap(err, "failed to open cluster API CRD directory")
//      }
//      if entry == nil {
//          break
//      }
//      fname := entry[0].Name()
//      crd, err := crds.CRDs.Open(fname)
//      if err != nil {
//          return nil, errors.Wrap(err, "failed to open cluster API CRD")
//      }
//      data, err := ioutil.ReadAll(crd)
//      if err != nil {
//          return nil, errors.Wrap(err, "failed to read cluster API CRD")
//      }
//      crdFiles = append(crdFiles, crdFile{fname, data})
//  }
//  return crdFiles, nil
// }

// GitParams are all SeedNodeParams related to the user's Git(Hub) repo
type GitParams struct {
	GitURL           string
	GitBranch        string
	GitPath          string
	GitDeployKeyPath string
}

// ControllerParams are all SeedNodeParams related to the WKS controller
type ControllerParams struct {
	// ImageOverride will override the WKS controller image if set. It will do so
	// whether the controller manifest comes from a git repository or is the
	// built-in one.
	ImageOverride string
	// ImageBuiltin is the WKS controller image to use when generating the WKS
	// controller manifest from in-memory data.
	ImageBuiltin string
}

// // Retrieve all CRD definitions needed for cluster API
// func getCRDs() ([]crdFile, error) {
//  crddir, err := crds.CRDs.Open(".")
//  if err != nil {
//      return nil, errors.Wrap(err, "failed to list cluster API CRDs")
//  }
//  crdFiles := make([]crdFile, 0)
//  for {
//      entry, err := crddir.Readdir(1)
//      if err != nil && err != io.EOF {
//          return nil, errors.Wrap(err, "failed to open cluster API CRD directory")
//      }
//      if entry == nil {
//          break
//      }
//      fname := entry[0].Name()
//      crd, err := crds.CRDs.Open(fname)
//      if err != nil {
//          return nil, errors.Wrap(err, "failed to open cluster API CRD")
//      }
//      data, err := ioutil.ReadAll(crd)
//      if err != nil {
//          return nil, errors.Wrap(err, "failed to read cluster API CRD")
//      }
//      crdFiles = append(crdFiles, crdFile{fname, data})
//  }
//  return crdFiles, nil
// }

// SeedNodeParams groups required inputs to configure a "seed" Kubernetes node.
type SeedNodeParams struct {
	PublicIP             string
	PrivateIP            string
	ServicesCIDRBlocks   []string
	PodsCIDRBlocks       []string
	ClusterManifestPath  string
	MachinesManifestPath string
	SSHKeyPath           string
	// BootstrapToken is the token used by kubeadm init and kubeadm join
	// to safely form new clusters.
	BootstrapToken       *kubeadmapi.BootstrapTokenString
	KubeletConfig        config.KubeletConfig
	Controller           ControllerParams
	GitData              GitParams
	SealedSecretKeyPath  string
	SealedSecretCertPath string
	ConfigDirectory      string
	Namespace            string
	ImageRepository      string
	ControlPlaneEndpoint string
	AdditionalSANs       []string
	AddonNamespaces      map[string]string
}

// Validate generally validates this SeedNodeParams struct, e.g. ensures it
// contains mandatory values, that these are well-formed, etc.
func (params SeedNodeParams) Validate() error {
	if len(params.KubeletConfig.NodeIP) == 0 {
		return errors.New("empty kubelet node IP")
	}
	if len(params.PublicIP) == 0 {
		return errors.New("empty API server public IP")
	}
	if len(params.PrivateIP) == 0 {
		return errors.New("empty API server private IP")
	}
	return nil
}

func (params SeedNodeParams) GetAddonNamespace(name string) string {
	if ns, ok := params.AddonNamespaces[name]; ok {
		return ns
	}
	return params.Namespace
}

// SetupSeedNode installs Kubernetes on this machine, and store the provided
// manifests in the API server, so that the rest of the cluster can then be
// set up by the WKS controller.
func SetupSeedNode(o *OS, params SeedNodeParams) error {
	p, err := CreateSeedNodeSetupPlan(o, params)
	if err != nil {
		return err
	}
	return applySeedNodePlan(o, p)
}

// CreateSeedNodeSetupPlan constructs the seed node plan used to setup the initial node
// prior to turning control over to wks-controller
func CreateSeedNodeSetupPlan(o *OS, params SeedNodeParams) (*plan.Plan, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	cfg, err := envcfg.GetEnvSpecificConfig(o.PkgType, params.Namespace, params.KubeletConfig.CloudProvider, o.Runner)
	if err != nil {
		return nil, err
	}
	//	kubernetesVersion, kubernetesNamespace, err := machine.GetKubernetesVersionFromManifest(params.MachinesManifestPath)
	kubernetesVersion, _, err := getMachineKubernetesVersion()
	if err != nil {
		return nil, err
	}
	// Get cluster from system
	cluster, err := getCluster() // XXX
	if err != nil {
		return nil, err
	}

	b := plan.NewBuilder()

	baseRes := recipe.BuildBasePlan(o.PkgType)
	b.AddResource("install:base", baseRes)

	// // Get configuration file resources from config map manifests referenced by the cluster spec
	// configMapManifests, configMaps, configFileResources, err := createConfigFileResourcesFromFiles(&cluster.Spec, params.ConfigDirectory, params.Namespace)
	// if err != nil {
	//  return nil, err
	// }

	// configRes := recipe.BuildConfigPlan(configFileResources)
	// b.AddResource("install:config", configRes, plan.DependOn("install:base"))

	// pemSecretResources, authConfigMap, authConfigManifest, err := processPemFilesIfAny(b, &cluster.Spec, params.ConfigDirectory, params.Namespace, params.SealedSecretKeyPath, params.SealedSecretCertPath)
	// if err != nil {
	//  return nil, err
	// }

	criRes := recipe.BuildCRIPlan(&cluster.Spec.CRI, cfg, o.PkgType)
	b.AddResource("install:cri", criRes, plan.DependOn("install:base"))

	k8sRes := recipe.BuildK8SPlan(kubernetesVersion, params.KubeletConfig.NodeIP, cfg.SELinuxInstalled, cfg.SetSELinuxPermissive, cfg.DisableSwap, cfg.LockYUMPkgs, o.PkgType, params.KubeletConfig.CloudProvider, params.KubeletConfig.ExtraArguments)
	b.AddResource("install:k8s", k8sRes, plan.DependOn("install:cri"))

	//	apiServerArgs := getAPIServerArgs(&cluster.Spec, pemSecretResources)

	// Backwards-compatibility: fall back if not specified
	controlPlaneEndpoint := params.ControlPlaneEndpoint
	if controlPlaneEndpoint == "" {
		// TODO: dynamically inject the API server's port.
		controlPlaneEndpoint = params.PrivateIP + ":6443"
	}

	kubeadmInitResource :=
		&resource.KubeadmInit{
			PublicIP:              params.PublicIP,
			PrivateIP:             params.PrivateIP,
			KubeletConfig:         &params.KubeletConfig,
			ConntrackMax:          cfg.ConntrackMax,
			UseIPTables:           cfg.UseIPTables,
			SSHKeyPath:            params.SSHKeyPath,
			BootstrapToken:        params.BootstrapToken,
			ControlPlaneEndpoint:  controlPlaneEndpoint,
			IgnorePreflightErrors: cfg.IgnorePreflightErrors,
			KubernetesVersion:     kubernetesVersion,
			CloudProvider:         params.KubeletConfig.CloudProvider,
			ImageRepository:       params.ImageRepository,
			AdditionalSANs:        params.AdditionalSANs,
			Namespace:             object.String(params.Namespace),
			NodeName:              cfg.HostnameOverride,
			ExtraAPIServerArgs:    map[string]string{},
			// kubeadm currently accepts a single subnet for services and pods
			// ref: https://godoc.org/k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm/v1beta1#Networking
			// this should be ensured in the validation step in pkg.specs.validation.validateCIDRBlocks()
			ServiceCIDRBlock: params.ServicesCIDRBlocks[0],
			PodCIDRBlock:     params.PodsCIDRBlocks[0],
		}
	b.AddResource("kubeadm:init", kubeadmInitResource, plan.DependOn("install:k8s"))
	return CreatePlan(b)
}

func getCluster() (eic *existinginfrav1.ExistingInfraCluster, err error) {
	return nil, nil
}

func getMachineKubernetesVersion() (string, string, error) {
	return "", "", nil
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
			return nil, fmt.Errorf("No config data for filespec: %v", file)
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
		return nil, fmt.Errorf("unknown operating system %q", osID)
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

//  ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
//  "github.com/bitnami-labs/sealed-secrets/pkg/crypto"
//  "github.com/pkg/errors"
//  log "github.com/sirupsen/logrus"
//  existinginfrav1 "github.com/weaveworks/cluster-api-provider-existinginfra/apis/cluster.weave.works/v1alpha3"
//  "github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/config"
//  capeios "github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/os"
//  "github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan"
//  capeirecipe "github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/recipe"
//  capeiresource "github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/resource"
//  "github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/envcfg"
//  "github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/manifest"
//  "github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/object"
//  "github.com/weaveworks/libgitops/pkg/serializer"
//  "github.com/weaveworks/wksctl/pkg/addons"
//  "github.com/weaveworks/wksctl/pkg/apis/wksprovider/controller/manifests"
//  "github.com/weaveworks/wksctl/pkg/apis/wksprovider/machine/crds"
//  "github.com/weaveworks/wksctl/pkg/cluster/machine"
//  "github.com/weaveworks/wksctl/pkg/plan/recipe"
//  "github.com/weaveworks/wksctl/pkg/plan/resource"
//  "github.com/weaveworks/wksctl/pkg/scheme"
//  "github.com/weaveworks/wksctl/pkg/specs"
//  appsv1 "k8s.io/api/apps/v1"
//  "k8s.io/api/apps/v1beta2"
//  v1 "k8s.io/api/core/v1"
//  metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
//  "k8s.io/apimachinery/pkg/runtime"
//  "k8s.io/client-go/tools/clientcmd"
//  clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
//  "k8s.io/client-go/util/keyutil"
//  kubeadmapi "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm/v1beta1"
//  "sigs.k8s.io/yaml"
// )

// Finds container in the list by name, adds an env var, fails if env var exists with different value
func injectEnvVarToContainer(
	containers []v1.Container, name string, newEnvVar v1.EnvVar) error {
	var targetContainer v1.Container
	containerFound := false
	var idx int
	var container v1.Container

	for idx, container = range containers {
		if container.Name == name {
			targetContainer = container
			containerFound = true
			break
		}
	}
	if !containerFound {
		return errors.New(fmt.Sprintf("did not find container %s in manifest", name))
	}

	envVars := targetContainer.Env
	for _, envVar := range envVars {
		if envVar.Name == newEnvVar.Name {
			if envVar.Value != newEnvVar.Value {
				return errors.New(
					fmt.Sprintf("manifest already contains env var %s, and cannot overwrite", newEnvVar.Name))
			}
			return nil
		}
	}
	targetContainer.Env = append(envVars, newEnvVar)
	containers[idx] = targetContainer

	return nil
}

// Returns a daemonset manifest from a list
func findDaemonSet(manifest *v1.List) (int, *appsv1.DaemonSet, error) {
	if manifest == nil {
		return -1, nil, errors.New("manifest is nil")
	}
	daemonSet := &appsv1.DaemonSet{}
	var err error
	var idx int
	var item runtime.RawExtension
	for idx, item = range manifest.Items {
		err := yaml.Unmarshal(item.Raw, daemonSet)
		if err == nil && daemonSet.Kind == "DaemonSet" {
			break
		}
	}

	if err != nil {
		return -1, nil, errors.Wrap(err, "failed to unmarshal manifest list")
	}
	if daemonSet.Kind != "DaemonSet" {
		return -1, nil, errors.New("daemonset not found in manifest list")
	}

	return idx, daemonSet, nil
}

type secretResourceSpec struct {
	secretName string
	decrypted  resource.SecretData
	resource   plan.Resource
}

func storeIfNotEmpty(vals map[string]string, key, value string) {
	if value != "" {
		vals[key] = value
	}
}

func getAPIServerArgs(providerSpec *existinginfrav1.ClusterSpec, pemSecretResources map[string]*secretResourceSpec) map[string]string {
	result := map[string]string{}
	authnResourceSpec := pemSecretResources["authentication"]
	if authnResourceSpec != nil {
		storeIfNotEmpty(result, "authentication-token-webhook-config-file", filepath.Join(ConfigDestDir, authnResourceSpec.secretName+".yaml"))
		storeIfNotEmpty(result, "authentication-token-webhook-cache-ttl", providerSpec.Authentication.CacheTTL)
	}
	authzResourceSpec := pemSecretResources["authorization"]
	if authzResourceSpec != nil {
		result["authorization-mode"] = "Webhook"
		storeIfNotEmpty(result, "authorization-webhook-config-file", filepath.Join(ConfigDestDir, authzResourceSpec.secretName+".yaml"))
		storeIfNotEmpty(result, "authorization-webhook-cache-unauthorized-ttl", providerSpec.Authorization.CacheUnauthorizedTTL)
		storeIfNotEmpty(result, "authorization-webhook-cache-authorized-ttl", providerSpec.Authorization.CacheAuthorizedTTL)
	}

	// Also add any explicit api server arguments from the generic section
	for _, arg := range providerSpec.APIServer.ExtraArguments {
		result[arg.Name] = arg.Value
	}
	return result
}

// func addClusterAPICRDs(b *plan.Builder) ([]string, error) {
//  crds, err := getCRDs()
//  if err != nil {
//      return nil, errors.Wrap(err, "failed to list cluster API CRDs")
//  }
//  crdIDs := make([]string, 0)
//  for _, crdFile := range crds {
//      id := fmt.Sprintf("kubectl:apply:%s", crdFile.fname)
//      crdIDs = append(crdIDs, id)
//      rsrc := &resource.KubectlApply{Filename: object.String(crdFile.fname), Manifest: crdFile.data, WaitCondition: "condition=Established"}
//      b.AddResource(id, rsrc, plan.DependOn("kubeadm:init"))
//  }
//  return crdIDs, nil
// }

func seedNodeSetupPlan(o *OS, params SeedNodeParams, providerSpec *existinginfrav1.ClusterSpec, kubernetesVersion, kubernetesNamespace string) (*plan.Plan, error) {
	// secrets := map[string]resource.SecretData{}
	// for k, v := range secretResources {
	//  secrets[k] = v.decrypted
	// }
	nodeParams := NodeParams{
		IsMaster:          true,
		MasterIP:          params.PrivateIP,
		MasterPort:        6443, // See TODO in machine_actuator.go
		KubeletConfig:     params.KubeletConfig,
		KubernetesVersion: kubernetesVersion,
		CRI:               providerSpec.CRI,
		//		ConfigFileSpecs:      providerSpec.OS.Files,
		Namespace:            params.Namespace,
		ControlPlaneEndpoint: providerSpec.ControlPlaneEndpoint,
	}
	return o.CreateNodeSetupPlan(nodeParams)
}

func applySeedNodePlan(o *OS, p *plan.Plan) error {
	err := p.Undo(o.Runner, plan.EmptyState)
	if err != nil {
		log.Infof("Pre-plan cleanup failed:\n%s\n", err)
		return err
	}

	_, err = p.Apply(o.Runner, plan.EmptyDiff())
	if err != nil {
		log.Errorf("Apply of Plan failed:\n%s\n", err)
		return err
	}
	return err
}

// func parseCluster(clusterManifestPath string) (eic *existinginfrav1.ExistingInfraCluster, err error) {
//  f, err := os.Open(clusterManifestPath)
//  if err != nil {
//      return nil, err
//  }
//  _, b, err := specs.ParseCluster(f)
//  return b, err
// }

// func createConfigFileResourcesFromFiles(providerSpec *existinginfrav1.ClusterSpec, configDir, namespace string) (map[string][]byte, map[string]*v1.ConfigMap, []*resource.File, error) {
//  fileSpecs := providerSpec.OS.Files
//  configMapManifests, err := getConfigMapManifests(fileSpecs, configDir, namespace)
//  if err != nil {
//      return nil, nil, nil, err
//  }
//  configMaps := make(map[string]*v1.ConfigMap)
//  for name, manifest := range configMapManifests {
//      cmap, err := getConfigMap(manifest)
//      if err != nil {
//          return nil, nil, nil, err
//      }
//      configMaps[name] = cmap
//  }
//  resources, err := CreateConfigFileResourcesFromConfigMaps(fileSpecs, configMaps)
//  if err != nil {
//      return nil, nil, nil, err
//  }
//  return configMapManifests, configMaps, resources, nil
// }

// func getConfigMapManifests(fileSpecs []existinginfrav1.FileSpec, configDir, namespace string) (map[string][]byte, error) {
//  configMapManifests := map[string][]byte{}
//  for _, fileSpec := range fileSpecs {
//      mapName := fileSpec.Source.ConfigMap
//      if _, ok := configMapManifests[mapName]; !ok {
//          manifest, err := getConfigMapManifest(configDir, mapName, namespace)
//          if err != nil {
//              return nil, err
//          }
//          configMapManifests[mapName] = manifest
//      }
//  }
//  return configMapManifests, nil
// }

func getConfigMap(manifest []byte) (*v1.ConfigMap, error) {
	configMap := &v1.ConfigMap{}
	if err := yaml.Unmarshal(manifest, configMap); err != nil {
		return nil, errors.Wrapf(err, "failed to parse config:\n%s", manifest)
	}
	return configMap, nil
}

// getConfigMapManifest reads a config map manifest from a file in the config directory. The file should be named:
// "<mapName>-config.yaml"
// func getConfigMapManifest(configDir, mapName, namespace string) ([]byte, error) {
//  bytes, err := getConfigFileContents(configDir, mapName+"-config.yaml")
//  if err != nil {
//      return nil, err
//  }
//  content, err := manifest.WithNamespace(serializer.FromBytes(bytes), namespace)
//  if err != nil {
//      return nil, err
//  }
//  return content, nil
// }

// // getConfigFileContents reads a config manifest from a file in the config directory.
// func getConfigFileContents(fileNameComponent ...string) ([]byte, error) {
//  return ioutil.ReadFile(filepath.Join(fileNameComponent...))
// }
