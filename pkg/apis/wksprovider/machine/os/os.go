package os

import (
	// "bytes"
	// "crypto/rsa"
	//	"encoding/base64"
	//	"encoding/json"
	"fmt"
	//	"io"
	//	"io/ioutil"
	//	"net/http"
	// "os"
	"path/filepath"
	"regexp"
	"strings"
	// "text/template"

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

// SeedNodeParams groups required inputs to configure a "seed" Kubernetes node.
type SeedNodeParams struct {
	PublicIP             string
	PrivateIP            string
	ServicesCIDRBlocks   []string
	PodsCIDRBlocks       []string
	ExistingInfraCluster existinginfrav1.ExistingInfraCluster
	ClusterManifest      string
	MachinesManifest     string
	SSHKey               string
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
	log.Info("Validated params")
	cfg, err := envcfg.GetEnvSpecificConfig(o.PkgType, params.Namespace, params.KubeletConfig.CloudProvider, o.Runner)
	if err != nil {
		return nil, err
	}
	log.Info("Got environment config")

	// Get cluster
	cluster := params.ExistingInfraCluster
	log.Infof("Got cluster: %v", cluster)

	//	kubernetesVersion, kubernetesNamespace, err := machine.GetKubernetesVersionFromManifest(params.MachinesManifest)
	kubernetesVersion := getKubernetesVersion(&cluster)
	log.Info("Got Kubernetes version")

	b := plan.NewBuilder()

	baseRes := recipe.BuildBasePlan(o.PkgType)
	b.AddResource("install:base", baseRes)

	// Get configuration file resources from config map manifests referenced by the cluster spec
	configMapManifests, configMaps, configFileResources, err := createConfigFileResourcesFromClusterSpec(&cluster.Spec)
	if err != nil {
		return nil, err
	}

	log.Info("Extracted config maps")

	configRes := recipe.BuildConfigPlan(configFileResources)
	b.AddResource("install:config", configRes, plan.DependOn("install:base"))

	log.Info("Built config plan")

	criRes := recipe.BuildCRIPlan(&cluster.Spec.CRI, cfg, o.PkgType)
	b.AddResource("install:cri", criRes, plan.DependOn("install:config"))

	log.Info("Built cri plan")

	k8sRes := recipe.BuildK8SPlan(kubernetesVersion, params.KubeletConfig.NodeIP, cfg.SELinuxInstalled, cfg.SetSELinuxPermissive, cfg.DisableSwap, cfg.LockYUMPkgs, o.PkgType, params.KubeletConfig.CloudProvider, params.KubeletConfig.ExtraArguments)
	b.AddResource("install:k8s", k8sRes, plan.DependOn("install:cri"))

	log.Info("Built k8s plan")

	//	apiServerArgs := getAPIServerArgs(&cluster.Spec, pemSecretResources)

	// Backwards-compatibility: fall back if not specified
	controlPlaneEndpoint := params.ControlPlaneEndpoint
	if controlPlaneEndpoint == "" {
		// TODO: dynamically inject the API server's port.
		controlPlaneEndpoint = params.PrivateIP + ":6443"
	}

	log.Info("Got control plane endpoint")

	kubeadmInitResource :=
		&resource.KubeadmInit{
			PublicIP:              params.PublicIP,
			PrivateIP:             params.PrivateIP,
			KubeletConfig:         &params.KubeletConfig,
			ConntrackMax:          cfg.ConntrackMax,
			UseIPTables:           cfg.UseIPTables,
			SSHKey:                params.SSHKey,
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

	log.Info("Got init resource")

	// TODO(damien): Add a CNI section in cluster.yaml once we support more than one CNI plugin.
	const cni = "weave-net"

	// cniRsc := recipe.BuildCNIPlan(cni, manifests)

	var manifest string
	fetchRsc := &resource.Run{Script: object.String("kubectl version | base64 | tr -d '\n'"), Output: &manifest}
	b.AddResource("fetch:cni", fetchRsc, plan.DependOn("kubeadm:init"))
	cniRsc := &resource.KubectlApply{
		ManifestURL: plan.ParamString("https://cloud.weave.works/k8s/net?k8s-version=%s", &manifest)}
	b.AddResource("install:cni", cniRsc, plan.DependOn("fetch:cni"))
	log.Info("Got cni resource")

	kubectlApplyDeps := []string{"install:cni"}

	// Set plan as an annotation on node, just like controller does
	seedNodePlan, err := seedNodeSetupPlan(o, params, &cluster.Spec, configMaps, map[string]*secretResourceSpec{}, kubernetesVersion, params.Namespace)
	if err != nil {
		return nil, err
	}
	log.Info("Got seed node plan")

	b.AddResource("node:plan", &resource.KubectlAnnotateSingleNode{Key: recipe.PlanKey, Value: seedNodePlan.ToJSON()}, plan.DependOn("kubeadm:init"))

	// Add config maps to system so controller can use them
	configMapPlan := recipe.BuildConfigMapPlan(configMapManifests, params.Namespace)
	log.Info("Got config map plan")

	b.AddResource("install:configmaps", configMapPlan, plan.DependOn("node:plan"))

	applyClstrRsc := &resource.KubectlApply{Manifest: []byte(params.ClusterManifest), Namespace: object.String(params.Namespace)}

	b.AddResource("kubectl:apply:cluster", applyClstrRsc, plan.DependOn("install:configmaps"))

	mManRsc := &resource.KubectlApply{Manifest: []byte(params.MachinesManifest), Filename: object.String("machinesmanifest"), Namespace: object.String(params.Namespace)}
	b.AddResource("kubectl:apply:machines", mManRsc, plan.DependOn(kubectlApplyDeps[0], kubectlApplyDeps[1:]...))

	dep := "kubectl:apply:machines"
	{
		capiCtlrManifest, err := capiControllerManifest(params.Controller, params.Namespace, params.ConfigDirectory)
		if err != nil {
			return nil, err
		}
		ctlrRsc := &resource.KubectlApply{Manifest: capiCtlrManifest, Filename: object.String("capi_controller.yaml")}
		b.AddResource("install:capi", ctlrRsc, plan.DependOn("kubectl:apply:cluster", dep))
	}

	wksCtlrManifest, err := wksControllerManifest(params.Controller, params.Namespace, params.ConfigDirectory)
	if err != nil {
		return nil, err
	}

	ctlrRsc := &resource.KubectlApply{Manifest: wksCtlrManifest, Filename: object.String("wks_controller.yaml")}
	b.AddResource("install:wks", ctlrRsc, plan.DependOn("kubectl:apply:cluster", dep))

	return CreatePlan(b)
}

func capiControllerManifest(controller ControllerParams, namespace, configDir string) ([]byte, error) {
	return []byte(capiControllerManifestString), nil
}

func wksControllerManifest(controller ControllerParams, namespace, configDir string) ([]byte, error) {
	manifestbytes := []byte(wksControllerManifestString)
	return manifestbytes, nil
}

func getCluster() (eic *existinginfrav1.ExistingInfraCluster, err error) {
	return nil, nil
}

func getKubernetesVersion(cluster *existinginfrav1.ExistingInfraCluster) string {
	return cluster.Spec.KubernetesVersion
}

// Sets the pod CIDR block in the weave-net manifest
func SetWeaveNetPodCIDRBlock(manifests [][]byte, podsCIDRBlock string) ([][]byte, error) {
	// Weave-Net has a container named weave in its daemonset
	containerName := "weave"
	// The pod CIDR block is set via the IPALLOC_RANGE env var
	podCIDRBlock := &v1.EnvVar{
		Name:  "IPALLOC_RANGE",
		Value: podsCIDRBlock,
	}

	manifestList := &v1.List{}
	err := yaml.Unmarshal(manifests[0], manifestList)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal weave-net manifest")
	}

	// Find and parse the DaemonSet included in the manifest list into an object
	idx, daemonSet, err := findDaemonSet(manifestList)
	if err != nil {
		return nil, errors.New("failed to find daemonset in weave-net manifest")
	}

	err = injectEnvVarToContainer(daemonSet.Spec.Template.Spec.Containers, containerName, *podCIDRBlock)
	if err != nil {
		return nil, errors.Wrap(err, "failed to inject env var to weave container")
	}

	manifestList.Items[idx] = runtime.RawExtension{Object: daemonSet}

	manifests[0], err = yaml.Marshal(manifestList)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal weave-net manifest list")
	}

	return manifests, nil
}

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

func CreateConfigFileResourcesFromConfigMaps(fileSpecs []existinginfrav1.FileSpec, configMaps map[string]*v1.ConfigMap) ([]*resource.File, error) {
	log.Info("Getting resources from config maps")
	for name, val := range configMaps {
		log.Infof("Config map '%s': %#v", name, *val)
	}
	fileResources := make([]*resource.File, len(fileSpecs))
	for idx, file := range fileSpecs {
		source := &file.Source
		fileResource := &resource.File{Destination: file.Destination}
		log.Infof("Getting file contents for: %#v", *source)
		fileContents, ok := configMaps[source.ConfigMap].Data[source.Key]
		if ok {
			log.Info("Got file contents")
			fileResource.Content = fileContents
			fileResources[idx] = fileResource
			continue
		}
		log.Infof("Failed to get file contents")
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

func CreateConfigFileResourcesFromFileSpecs(fileSpecs []existinginfrav1.FileSpec) ([]*resource.File, error) {
	fileResources := make([]*resource.File, len(fileSpecs))
	for idx, file := range fileSpecs {
		source := &file.Source
		fileResource := &resource.File{Destination: file.Destination}
		fileResource.Content = source.Contents
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
	log.Info("Creating node setup plan")
	if err := params.Validate(); err != nil {
		return nil, err
	}
	log.Info("Validated parameters")

	cfg, err := envcfg.GetEnvSpecificConfig(o.PkgType, params.Namespace, params.KubeletConfig.CloudProvider, o.Runner)
	if err != nil {
		return nil, err
	}
	log.Info("Got env config")

	configFileResources, err := CreateConfigFileResourcesFromConfigMaps(params.ConfigFileSpecs, params.ProviderConfigMaps)
	if err != nil {
		return nil, err
	}
	log.Info("Created config file resources")

	b := plan.NewBuilder()

	baseRsrc := recipe.BuildBasePlan(o.PkgType)
	b.AddResource("install:base", baseRsrc)

	log.Info("Built base plan")

	configRes := recipe.BuildConfigPlan(configFileResources)
	b.AddResource("install:config", configRes, plan.DependOn("install:base"))
	log.Info("Built config plan")
	instCriRsrc := recipe.BuildCRIPlan(&params.CRI, cfg, o.PkgType)
	b.AddResource("install.cri", instCriRsrc, plan.DependOn("install:config"))
	log.Info("Built cri plan")

	instK8sRsrc := recipe.BuildK8SPlan(params.KubernetesVersion, params.KubeletConfig.NodeIP, cfg.SELinuxInstalled, cfg.SetSELinuxPermissive, cfg.DisableSwap, cfg.LockYUMPkgs, o.PkgType, params.KubeletConfig.CloudProvider, params.KubeletConfig.ExtraArguments)
	log.Info("Built k8s plan")

	b.AddResource("install:k8s", instK8sRsrc, plan.DependOn("install.cri"))

	kadmPJRsrc := recipe.BuildKubeadmPrejoinPlan(params.KubernetesVersion, cfg.UseIPTables)
	b.AddResource("kubeadm:prejoin", kadmPJRsrc, plan.DependOn("install:k8s"))

	log.Info("Built join plan")

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

func seedNodeSetupPlan(o *OS, params SeedNodeParams, providerSpec *existinginfrav1.ClusterSpec, providerConfigMaps map[string]*v1.ConfigMap, secretResources map[string]*secretResourceSpec, kubernetesVersion, kubernetesNamespace string) (*plan.Plan, error) {
	nodeParams := NodeParams{
		IsMaster:             true,
		MasterIP:             params.PrivateIP,
		MasterPort:           6443, // See TODO in machine_actuator.go
		KubeletConfig:        params.KubeletConfig,
		KubernetesVersion:    kubernetesVersion,
		CRI:                  providerSpec.CRI,
		ConfigFileSpecs:      providerSpec.OS.Files,
		ProviderConfigMaps:   providerConfigMaps,
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

func createConfigFileResourcesFromClusterSpec(providerSpec *existinginfrav1.ClusterSpec) (map[string][]byte, map[string]*v1.ConfigMap, []*resource.File, error) {
	log.Info("Extracting config files")
	fileSpecs := providerSpec.OS.Files
	log.Info("Got configs")

	configMaps := map[string]*v1.ConfigMap{}
	configMapManifests := map[string][]byte{}

	log.Info("XXX 1")
	for _, fspec := range fileSpecs {
		log.Infof("fspec: %#v", fspec)
		configMap := configMaps[fspec.Source.ConfigMap]
		if configMap == nil {
			configMap = &v1.ConfigMap{}
			configMaps[fspec.Source.ConfigMap] = configMap
		}
		configMap.TypeMeta.APIVersion = "v1"
		configMap.TypeMeta.Kind = "ConfigMap"
		log.Info("XXX 2")
		configMap.Name = fspec.Source.ConfigMap
		log.Info("XXX 3")
		configMap.Namespace = "system"
		log.Info("XXX 4")
		if configMap.Data == nil {
			configMap.Data = map[string]string{}
		}
		configMap.Data[fspec.Source.Key] = fspec.Source.Contents
		log.Info("XXX 5")
		log.Infof("cmap: %#v", configMap)
		log.Info("XXX 6")
		manifest, err := yaml.Marshal(*configMap)
		if err != nil {
			return nil, nil, nil, err
		}
		log.Info("XXX 7")
		configMapManifests[configMap.Name] = manifest
	}
	log.Info("XXX 8")
	resources, err := CreateConfigFileResourcesFromFileSpecs(fileSpecs)
	if err != nil {
		return nil, nil, nil, err
	}
	log.Info("Got config resources")
	return configMapManifests, configMaps, resources, nil
}

func getConfigMapManifests(fileSpecs []existinginfrav1.FileSpec) (map[string][]byte, error) {
	configMapManifests := map[string][]byte{}
	for _, fileSpec := range fileSpecs {
		mapName := fileSpec.Source.ConfigMap
		if _, ok := configMapManifests[mapName]; !ok {
			configMapManifests[mapName] = []byte(fileSpec.Source.Contents)
		}
	}
	return configMapManifests, nil
}

func getConfigMap(manifest []byte) (*v1.ConfigMap, error) {
	configMap := &v1.ConfigMap{}
	if err := yaml.Unmarshal(manifest, configMap); err != nil {
		return nil, errors.Wrapf(err, "failed to parse config:\n%s", manifest)
	}
	return configMap, nil
}

const capiControllerManifestString = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: capi-controller
  namespace: system
  labels:
    name: capi-controller
spec:
  replicas: 1
  selector:
    matchLabels:
      name: capi-controller
  template:
    metadata:
      labels:
        name: capi-controller
    spec:
      tolerations:
      # Allow scheduling on master nodes; required during bootstrapping.
      - effect: NoSchedule
        key: node-role.kubernetes.io/master
        operator: Exists
      # Mark this as a critical addon:
      - key: CriticalAddonsOnly
        operator: Exists
      containers:
      - name: controller
        image: us.gcr.io/k8s-artifacts-prod/cluster-api/cluster-api-controller:v0.3.5
        resources:
          requests:
            cpu: 100m
            memory: 20Mi
`

const wksControllerManifestString = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wks-controller
  namespace: system
  labels:
    name: wks-controller
    control-plane: wks-controller
    controller-tools.k8s.io: "1.0"
spec:
  replicas: 1
  selector:
    matchLabels:
      name: wks-controller
  template:
    metadata:
      labels:
        name: wks-controller
        control-plane: wks-controller
        controller-tools.k8s.io: "1.0"
    spec:
      nodeSelector:
        node-role.kubernetes.io/master: ""
      tolerations:
      # Allow scheduling on master nodes. This is required because during
      # bootstrapping of the cluster, we may initially have just one master,
      # and would then need to deploy this controller there to set the entire
      # cluster up.
      - effect: NoSchedule
        key: node-role.kubernetes.io/master
        operator: Exists
      # Mark this as a critical addon:
      - key: CriticalAddonsOnly
        operator: Exists
      # Only schedule on nodes which are ready and reachable:
      - effect: NoExecute
        key: node.alpha.kubernetes.io/notReady
        operator: Exists
      - effect: NoExecute
        key: node.alpha.kubernetes.io/unreachable
        operator: Exists
      containers:
      - name: controller
        image: weaveworks/cluster-api-existinginfra-controller:v0.0.2
        args:
        - --verbose
        resources:
          limits:
            cpu: 100m
            memory: 30Mi
          requests:
            cpu: 100m
            memory: 20Mi
`
