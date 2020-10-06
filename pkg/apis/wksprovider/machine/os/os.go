package os

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	"github.com/bitnami-labs/sealed-secrets/pkg/crypto"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	existinginfrav1 "github.com/weaveworks/cluster-api-provider-existinginfra/apis/cluster.weave.works/v1alpha3"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/config"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/crds"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/recipe"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/resource"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/runners/sudo"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/scheme"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/envcfg"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/manifest"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/object"
	"github.com/weaveworks/libgitops/pkg/serializer"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/api/apps/v1beta2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/util/keyutil"
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

type CRDFile struct {
	Fname string
	Data  []byte
}

// Retrieve all CRD definitions needed for cluster API
func GetCRDs(fs http.FileSystem) ([]CRDFile, error) {
	log.Info("Getting CRDs")
	crddir, err := fs.Open(".")
	if err != nil {
		return nil, errors.Wrap(err, "failed to list cluster API CRDs")
	}
	log.Info("Opened CRDs")
	crdFiles := make([]CRDFile, 0)
	for {
		entry, err := crddir.Readdir(1)
		if err != nil && err != io.EOF {
			return nil, errors.Wrap(err, "failed to open cluster API CRD directory")
		}
		if entry == nil {
			break
		}
		if entry[0].IsDir() || !strings.HasPrefix(entry[0].Name(), "cluster") {
			continue
		}
		fname := entry[0].Name()
		crd, err := fs.Open(fname)
		if err != nil {
			return nil, errors.Wrap(err, "failed to open cluster API CRD")
		}
		data, err := ioutil.ReadAll(crd)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read cluster API CRD")
		}
		crdFiles = append(crdFiles, CRDFile{fname, data})
	}
	log.Info("Got CRDs")
	return crdFiles, nil
}

// GitParams are all SeedNodeParams related to the user's Git(Hub) repo
type GitParams struct {
	GitURL           string
	GitBranch        string
	GitPath          string
	GitDeployKeyPath string
}

// AuthParams are parameters used to configure authn and authz for the cluster
type AuthParams struct {
	PEMSecretResources map[string]*secretResourceSpec
	AuthConfigMap      *v1.ConfigMap
	AuthConfigManifest []byte
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
	AuthInfo             *AuthParams
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

// SetupSeedNode installs Kubernetes on this machine, and store the provided
// manifests in the API server, so that the rest of the cluster can then be
// set up by the WKS controller.
func SetupSeedNode(o *OS, params SeedNodeParams) error {
	p, err := CreateSeedNodeSetupPlan(o, params)
	if err != nil {
		return err
	}
	return ApplyPlan(o, p)
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
	log.Infof("Got cluster")

	//	kubernetesVersion, kubernetesNamespace, err := machine.GetKubernetesVersionFromManifest(params.MachinesManifest)
	kubernetesVersion := getKubernetesVersion(&cluster)
	log.Info("Got Kubernetes version")

	// Get configuration file resources from config map manifests referenced by the cluster spec
	configMapManifests, configMaps, configFileResources, err := createConfigFileResourcesFromClusterSpec(&cluster.Spec, params.Namespace)
	if err != nil {
		return nil, err
	}

	log.Info("Extracted config maps")

	b := plan.NewBuilder()

	baseRes := recipe.BuildBasePlan(o.PkgType)
	b.AddResource("install:base", baseRes)

	configRes := recipe.BuildConfigPlan(configFileResources)
	b.AddResource("install:config", configRes, plan.DependOn("install:base"))

	log.Info("Built config plan")

	criRes := recipe.BuildCRIPlan(&cluster.Spec.CRI, cfg, o.PkgType)
	b.AddResource("install:cri", criRes, plan.DependOn("install:config"))

	log.Info("Built cri plan")

	k8sRes := recipe.BuildK8SPlan(kubernetesVersion, params.KubeletConfig.NodeIP, cfg.SELinuxInstalled, cfg.SetSELinuxPermissive, cfg.DisableSwap, cfg.LockYUMPkgs, o.PkgType, params.KubeletConfig.CloudProvider, params.KubeletConfig.ExtraArguments)
	b.AddResource("install:k8s", k8sRes, plan.DependOn("install:cri"))

	log.Info("Built k8s plan")

	apiServerArgs := GetAPIServerArgs(&cluster.Spec)
	if params.AuthInfo != nil {
		addAuthArgs(apiServerArgs, params.AuthInfo.PEMSecretResources, &cluster.Spec)
	}

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
			ExtraAPIServerArgs:    apiServerArgs,
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

	var manifest string
	fetchRsc := &resource.Run{Script: object.String("kubectl version | base64 | tr -d '\n'"), Output: &manifest}
	b.AddResource("fetch:cni", fetchRsc, plan.DependOn("kubeadm:init"))

	cniRsc := &resource.KubectlApply{ManifestURL: plan.ParamString("https://cloud.weave.works/k8s/net?k8s-version=%s",
		&manifest)}
	if len(params.PodsCIDRBlocks) > 0 && params.PodsCIDRBlocks[0] != "" {
		cniRsc = &resource.KubectlApply{
			ManifestURL: plan.ParamString("https://cloud.weave.works/k8s/net?k8s-version=%s&env.IPALLOC_RANGE=%s",
				&manifest, &params.PodsCIDRBlocks[0])}
	}

	b.AddResource("install:cni", cniRsc, plan.DependOn("fetch:cni"))
	log.Info("Got cni resource")

	// Add resources to apply the cluster API's CRDs so that Kubernetes
	// understands objects like Cluster, Machine, etc.

	crdIDs, err := AddClusterAPICRDs(b, crds.CRDs)
	if err != nil {
		return nil, err
	}

	kubectlApplyDeps := append([]string{"kubeadm:init"}, crdIDs...)

	// If we're pulling data out of GitHub, we install sealed secrets and any auth secrets stored in sealed secrets
	configDeps := kubectlApplyDeps
	if params.AuthInfo != nil {
		configDeps, err = addSealedSecretResourcesIfNecessary(b, kubectlApplyDeps, params.AuthInfo.PEMSecretResources, sealedSecretVersion, params.SealedSecretKeyPath, params.SealedSecretCertPath, params.Namespace)
		if err != nil {
			return nil, err
		}
	}

	// Set plan as an annotation on node, just like controller does
	seedNodePlan, err := seedNodeSetupPlan(o, params, &cluster.Spec, configMaps, kubernetesVersion)
	if err != nil {
		return nil, err
	}
	log.Info("Got seed node plan")

	b.AddResource("node:plan", &resource.KubectlAnnotateSingleNode{Key: recipe.PlanKey, Value: seedNodePlan.ToJSON()}, plan.DependOn("kubeadm:init"))

	if params.AuthInfo != nil {
		addAuthConfigMapIfNecessary(configMapManifests, params.AuthInfo.AuthConfigManifest)
	}

	// Add config maps to system so controller can use them
	configMapPlan := recipe.BuildConfigMapPlan(configMapManifests, params.Namespace)
	log.Info("Got config map plan")

	b.AddResource("install:configmaps", configMapPlan, plan.DependOn(configDeps[0], configDeps[1:]...))

	applyClstrRsc := &resource.KubectlApply{Manifest: []byte(params.ClusterManifest), Namespace: object.String(params.Namespace)}

	b.AddResource("kubectl:apply:cluster", applyClstrRsc, plan.DependOn("install:configmaps", kubectlApplyDeps...))

	mManRsc := &resource.KubectlApply{Manifest: []byte(params.MachinesManifest), Filename: object.String("machinesmanifest"), Namespace: object.String(params.Namespace)}
	b.AddResource("kubectl:apply:machines", mManRsc, plan.DependOn(kubectlApplyDeps[0], kubectlApplyDeps[1:]...))

	dep := addSealedSecretWaitIfNecessary(b, params.SealedSecretKeyPath, params.SealedSecretCertPath)
	{
		capiCtlrManifest, err := capiControllerManifest(params.Controller, params.Namespace)
		if err != nil {
			return nil, err
		}
		ctlrRsc := &resource.KubectlApply{Manifest: capiCtlrManifest, Filename: object.String("capi_controller.yaml")}
		b.AddResource("install:capi", ctlrRsc, plan.DependOn("kubectl:apply:cluster", dep))
	}

	wksCtlrManifest, err := wksControllerManifest(params.Controller, params.Namespace)
	if err != nil {
		return nil, err
	}

	ctlrRsc := &resource.KubectlApply{Manifest: wksCtlrManifest, Filename: object.String("wks_controller.yaml")}
	b.AddResource("install:wks", ctlrRsc, plan.DependOn("kubectl:apply:cluster", dep))

	return CreatePlan(b)
}

func ApplyPlan(o *OS, p *plan.Plan) error {
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

func addSealedSecretWaitIfNecessary(b *plan.Builder, keyPath, certPath string) string {
	if keyPath != "" && certPath != "" {
		b.AddResource("wait:sealed-secrets-controller",
			&resource.KubectlWait{WaitNamespace: "kube-system", WaitType: "pods", WaitSelector: "name=sealed-secrets-controller",
				WaitCondition: "condition=Ready", WaitTimeout: "300s"},
			plan.DependOn("kubectl:apply:machines"))
		return "wait:sealed-secrets-controller"
	}
	return "kubectl:apply:machines"
}

func addSealedSecretResourcesIfNecessary(b *plan.Builder, kubectlApplyDeps []string, pemSecretResources map[string]*secretResourceSpec, sealedSecretVersion, keyPath, certPath, ns string) ([]string, error) {
	if keyPath != "" && certPath != "" {
		privateKeyBytes, err := getConfigFileContents(keyPath)
		if err != nil {
			return nil, errors.Wrap(err, "Could not read private key")
		}
		certBytes, err := getConfigFileContents(certPath)
		if err != nil {
			return nil, errors.Wrap(err, "Could not read cert")
		}
		keyManifest, err := createSealedSecretKeySecretManifest(string(privateKeyBytes), string(certBytes), ns)
		if err != nil {
			return nil, err
		}
		crdManifest, err := sealedSecretCRDManifest(ns)
		if err != nil {
			return nil, err
		}
		controllerManifest, err := sealedSecretControllerManifest(ns)
		if err != nil {
			return nil, err
		}
		sealedSecretRsc := recipe.BuildSealedSecretPlan(sealedSecretVersion, ns, crdManifest, keyManifest, controllerManifest)
		b.AddResource("install:sealed-secrets", sealedSecretRsc, plan.DependOn(kubectlApplyDeps[0], kubectlApplyDeps[1:]...))

		// Now that the cluster is up, if auth is configured, create a secret containing the data for use by the machine actuator
		for _, resourceSpec := range pemSecretResources {
			b.AddResource(fmt.Sprintf("install:pem-secret-%s", resourceSpec.secretName), resourceSpec.resource, plan.DependOn("install:sealed-secrets"))
		}
		return []string{"install:sealed-secrets"}, nil
	}
	return kubectlApplyDeps, nil
}

func addAuthArgs(apiServerArgs map[string]string, pemSecretResources map[string]*secretResourceSpec, providerSpec *existinginfrav1.ClusterSpec) {
	authnResourceSpec := pemSecretResources["authentication"]
	if authnResourceSpec != nil {
		storeIfNotEmpty(apiServerArgs, "authentication-token-webhook-config-file", filepath.Join(ConfigDestDir, authnResourceSpec.secretName+".yaml"))
		storeIfNotEmpty(apiServerArgs, "authentication-token-webhook-cache-ttl", providerSpec.Authentication.CacheTTL)
	}
	authzResourceSpec := pemSecretResources["authorization"]
	if authzResourceSpec != nil {
		apiServerArgs["authorization-mode"] = "Webhook"
		storeIfNotEmpty(apiServerArgs, "authorization-webhook-config-file", filepath.Join(ConfigDestDir, authzResourceSpec.secretName+".yaml"))
		storeIfNotEmpty(apiServerArgs, "authorization-webhook-cache-unauthorized-ttl", providerSpec.Authorization.CacheUnauthorizedTTL)
		storeIfNotEmpty(apiServerArgs, "authorization-webhook-cache-authorized-ttl", providerSpec.Authorization.CacheAuthorizedTTL)
	}
}

func addAuthConfigMapIfNecessary(configMapManifests map[string][]byte, authConfigManifest []byte) {
	if authConfigManifest != nil {
		configMapManifests["auth-config"] = authConfigManifest
	}
}

func capiControllerManifest(controller ControllerParams, namespace string) ([]byte, error) {
	return getManifest(capiControllerManifestString, namespace)
}

func wksControllerManifest(controller ControllerParams, namespace string) ([]byte, error) {
	content, err := getManifest(wksControllerManifestString, namespace)
	if err != nil {
		return nil, err
	}
	return updateControllerImage(content, controller.ImageOverride)
}

func sealedSecretCRDManifest(namespace string) ([]byte, error) {
	return getManifest(sealedSecretCRDManifestString, namespace)
}

func sealedSecretControllerManifest(namespace string) ([]byte, error) {
	return getManifest(sealedSecretControllerManifestString, namespace)
}

func getManifest(manifestString, namespace string) ([]byte, error) {
	return manifest.WithNamespace(serializer.FromBytes([]byte(manifestString)), namespace)
}

const deployment = "Deployment"

// updateControllerImage replaces the controller image in the manifest and
// returns the updated manifest
func updateControllerImage(manifest []byte, controllerImageOverride string) ([]byte, error) {
	if controllerImageOverride == "" {
		return manifest, nil
	}
	d := &v1beta2.Deployment{}
	if err := yaml.Unmarshal(manifest, d); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal WKS controller's manifest")
	}
	if d.Kind != deployment {
		return nil, fmt.Errorf("invalid kind for WKS controller's manifest: expected %q but got %q", deployment, d.Kind)
	}
	var updatedController bool
	for i := 0; i < len(d.Spec.Template.Spec.Containers); i++ {
		if d.Spec.Template.Spec.Containers[i].Name == "controller" {
			d.Spec.Template.Spec.Containers[i].Image = controllerImageOverride
			env := d.Spec.Template.Spec.Containers[i].Env
			env = append(env, v1.EnvVar{Name: "EXISTINGINFRA_CONTROLLER_IMAGE", Value: controllerImageOverride})
			d.Spec.Template.Spec.Containers[i].Env = env
			updatedController = true
		}
	}
	if !updatedController {
		return nil, errors.New("failed to update WKS controller's manifest: container not found")
	}
	return yaml.Marshal(d)
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
	fileResources := make([]*resource.File, len(fileSpecs))
	for idx, file := range fileSpecs {
		source := &file.Source
		fileResource := &resource.File{Destination: file.Destination}
		log.Info("Getting file contents")
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

	authConfigMap := params.AuthConfigMap
	if authConfigMap != nil && params.IsMaster {
		for _, authType := range []string{"authentication", "authorization"} {
			if err := addAuthConfigResources(b, authConfigMap, params.Secrets[authType], authType); err != nil {
				return nil, err
			}
		}
	}

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

func GetAPIServerArgs(providerSpec *existinginfrav1.ClusterSpec) map[string]string {
	result := map[string]string{}
	// Also add any explicit api server arguments from the generic section
	for _, arg := range providerSpec.APIServer.ExtraArguments {
		result[arg.Name] = arg.Value
	}
	return result
}

func AddClusterAPICRDs(b *plan.Builder, fs http.FileSystem) ([]string, error) {
	crds, err := GetCRDs(fs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list cluster API CRDs")
	}
	crdIDs := make([]string, 0)
	for _, crdFile := range crds {
		id := fmt.Sprintf("kubectl:apply:%s", crdFile.Fname)
		crdIDs = append(crdIDs, id)
		rsrc := &resource.KubectlApply{Filename: object.String(crdFile.Fname), Manifest: crdFile.Data, WaitCondition: "condition=Established"}
		b.AddResource(id, rsrc, plan.DependOn("install:cni"))
	}
	return crdIDs, nil
}

func seedNodeSetupPlan(o *OS, params SeedNodeParams, providerSpec *existinginfrav1.ClusterSpec, providerConfigMaps map[string]*v1.ConfigMap, kubernetesVersion string) (*plan.Plan, error) {
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
	if params.AuthInfo != nil {
		nodeParams.AuthConfigMap = params.AuthInfo.AuthConfigMap
		secrets := map[string]resource.SecretData{}
		for k, v := range params.AuthInfo.PEMSecretResources {
			secrets[k] = v.decrypted
		}
	}
	return o.CreateNodeSetupPlan(nodeParams)
}

// processPemFilesIfAny reads the SealedSecret from the config
// directory, decrypts it using the GitHub deploy key, creates file
// resources for .pem files stored in the secret, and creates a SealedSecret resource
// for them that can be used by the machine actuator
func processPemFilesIfAny(builder *plan.Builder, providerSpec *existinginfrav1.ClusterSpec, configDir string, ns, privateKeyPath, certPath string) (map[string]*secretResourceSpec, *v1.ConfigMap, []byte, error) {
	if err := checkPemValues(providerSpec, privateKeyPath, certPath); err != nil {
		return nil, nil, nil, err
	}
	if providerSpec.Authentication == nil && providerSpec.Authorization == nil {
		// no auth specified
		return nil, nil, nil, nil
	}
	b := plan.NewBuilder()
	b.AddResource("create:pem-dir", &resource.Dir{Path: object.String(PemDestDir)})
	b.AddResource("set-perms:pem-dir", &resource.Run{Script: object.String(fmt.Sprintf("chmod 600 %s", PemDestDir))}, plan.DependOn("create:pem-dir"))
	privateKey, err := getPrivateKey(privateKeyPath)
	if err != nil {
		return nil, nil, nil, err
	}
	var authenticationSecretFileName, authorizationSecretFileName, authenticationSecretName, authorizationSecretName string
	var authenticationSecretManifest, authorizationSecretManifest, authenticationConfig, authorizationConfig []byte
	var decrypted map[string][]byte
	secretResources := map[string]*secretResourceSpec{}
	if providerSpec.Authentication != nil {
		authenticationSecretFileName = providerSpec.Authentication.SecretFile
		authenticationSecretManifest, decrypted, authenticationSecretName, authenticationConfig, err = processSecret(
			b, privateKey, configDir, authenticationSecretFileName, providerSpec.Authentication.URL)
		if err != nil {
			return nil, nil, nil, err
		}
		secretResources["authentication"] = &secretResourceSpec{
			secretName: authenticationSecretName,
			decrypted:  decrypted,
			resource:   &resource.KubectlApply{Namespace: object.String(ns), Manifest: authenticationSecretManifest, Filename: object.String(authenticationSecretName)}}
	}
	if providerSpec.Authorization != nil {
		authorizationSecretFileName = providerSpec.Authorization.SecretFile
		authorizationSecretManifest, decrypted, authorizationSecretName, authorizationConfig, err = processSecret(
			b, privateKey, configDir, authorizationSecretFileName, providerSpec.Authorization.URL)
		if err != nil {
			return nil, nil, nil, err
		}
		secretResources["authorization"] = &secretResourceSpec{
			secretName: authorizationSecretName,
			decrypted:  decrypted,
			resource:   &resource.KubectlApply{Namespace: object.String(ns), Manifest: authorizationSecretManifest, Filename: object.String(authorizationSecretName)}}
	}
	filePlan, err := b.Plan()
	if err != nil {
		log.Infof("Plan creation failed:\n%s\n", err)
		return nil, nil, nil, err
	}
	builder.AddResource("install:pem-files", &filePlan, plan.DependOn("install:config"))
	authConfigMap, authConfigMapManifest, err := createAuthConfigMapManifest(authenticationSecretName, authorizationSecretName,
		authenticationConfig, authorizationConfig)
	if err != nil {
		return nil, nil, nil, err
	}
	return secretResources, authConfigMap, authConfigMapManifest, nil
}

func getPrivateKey(privateKeyPath string) (*rsa.PrivateKey, error) {
	privateKeyBytes, err := getConfigFileContents(privateKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, "Could not read private key")
	}
	privateKeyData, err := keyutil.ParsePrivateKeyPEM(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	privateKey, ok := privateKeyData.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Private key file %q did not contain valid private key", privateKeyPath)
	}
	return privateKey, nil
}

// getConfigFileContents reads a config manifest from a file in the config directory.
func getConfigFileContents(fileNameComponent ...string) ([]byte, error) {
	return ioutil.ReadFile(filepath.Join(fileNameComponent...))
}

func checkPemValues(providerSpec *existinginfrav1.ClusterSpec, privateKeyPath, certPath string) error {
	if privateKeyPath == "" || certPath == "" {
		if providerSpec.Authentication != nil || providerSpec.Authorization != nil {
			return errors.New("Encryption keys not specified; cannot process authentication and authorization specifications.")
		}
	}
	if (providerSpec.Authentication != nil && providerSpec.Authentication.SecretFile == "") ||
		(providerSpec.Authorization != nil && providerSpec.Authorization.SecretFile == "") {
		return errors.New("A secret must be specified to configure an authentication or authorization specification.")
	}
	return nil
}

func createAuthConfigMapManifest(authnSecretName, authzSecretName string, authnConfig, authzConfig []byte) (*v1.ConfigMap, []byte, error) {
	data := map[string]string{}
	storeIfNotEmpty(data, "authentication-secret-name", authnSecretName)
	storeIfNotEmpty(data, "authorization-secret-name", authzSecretName)
	storeIfNotEmpty(data, "authentication-config", string(authnConfig))
	storeIfNotEmpty(data, "authorization-config", string(authzConfig))
	cm := v1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "auth-config"},
		Data:       data,
	}
	manifest, err := yaml.Marshal(cm)
	if err != nil {
		return nil, nil, err
	}
	return &cm, manifest, nil
}

// Decrypts secret, adds plan resources to install files found inside, plus a kubeconfig file pointing to them.
// returns the sealed file contents, decrypted contents, secret name, kubeconfig, error if any
func processSecret(b *plan.Builder, key *rsa.PrivateKey, configDir, secretFileName, URL string) ([]byte, map[string][]byte, string, []byte, error) {
	// Read the file contents at configDir/secretFileName
	contents, err := getConfigFileContents(configDir, secretFileName)
	if err != nil {
		return nil, nil, "", nil, err
	}

	// Create a new YAML FrameReader from the given bytes
	fr := serializer.NewYAMLFrameReader(serializer.FromBytes(contents))
	// Create the secret to decode into
	ss := &ssv1alpha1.SealedSecret{}
	// Decode the Sealed Secret into the object
	// In the future, if we wish to support other kinds of secrets than SealedSecrets, we
	// can just change this to do .Decode(fr), and switch on the type
	if err := scheme.Serializer.Decoder().DecodeInto(fr, ss); err != nil {
		return nil, nil, "", nil, errors.Wrapf(err, "couldn't decode the file %q into a sealed secret", secretFileName)
	}

	fingerprint, err := crypto.PublicKeyFingerprint(&key.PublicKey)
	if err != nil {
		return nil, nil, "", nil, err
	}
	keys := map[string]*rsa.PrivateKey{fingerprint: key}

	codecs := scheme.Serializer.Codecs()
	if codecs == nil {
		return nil, nil, "", nil, fmt.Errorf("codecs must not be nil")
	}
	secret, err := ss.Unseal(*codecs, keys)
	if err != nil {
		return nil, nil, "", nil, errors.Wrap(err, "Could not unseal auth secret")
	}
	decrypted := map[string][]byte{}
	secretName := secret.Name
	for _, key := range pemKeys {
		fileContents, ok := secret.Data[key]
		if !ok {
			return nil, nil, "", nil, fmt.Errorf("Missing auth config value for: %q in secret %q", key, secretName)
		}
		resName := secretName + "-" + key
		fileName := filepath.Join(PemDestDir, secretName, key+".pem")
		b.AddResource("install:"+resName, &resource.File{Content: string(fileContents), Destination: fileName}, plan.DependOn("set-perms:pem-dir"))
		decrypted[key] = fileContents
	}
	contextName := secretName + "-webhook"
	userName := secretName + "-api-server"
	config := &clientcmdapi.Config{
		Kind:       "Config",
		APIVersion: "v1",
		Clusters: map[string]*clientcmdapi.Cluster{
			secretName: {
				CertificateAuthority: filepath.Join(PemDestDir, secretName, "certificate-authority.pem"),
				Server:               URL,
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			userName: {
				ClientCertificate: filepath.Join(PemDestDir, secretName, "client-certificate.pem"),
				ClientKey:         filepath.Join(PemDestDir, secretName, "client-key.pem"),
			},
		},
		CurrentContext: contextName,
		Contexts: map[string]*clientcmdapi.Context{
			contextName: {
				Cluster:  secretName,
				AuthInfo: userName,
			},
		},
	}
	authConfig, err := clientcmd.Write(*config)
	if err != nil {
		return nil, nil, "", nil, err
	}
	configResource := &resource.File{Content: string(authConfig), Destination: filepath.Join(ConfigDestDir, secretName+".yaml")}
	b.AddResource("install:"+secretName, configResource, plan.DependOn("set-perms:pem-dir"))

	return contents, decrypted, secretName, authConfig, nil
}

func createSealedSecretKeySecretManifest(privateKey, cert, ns string) ([]byte, error) {
	secret := &v1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: sealedSecretKeySecretName, Namespace: "kube-system"},
		Type:       v1.SecretTypeOpaque,
	}
	secret.Data = map[string][]byte{}
	secret.StringData = map[string]string{}
	secret.StringData[v1.TLSPrivateKeyKey] = privateKey
	secret.StringData[v1.TLSCertKey] = cert
	return yaml.Marshal(secret)
}

// processDeployKey adds the encoded deploy key to the set of parameters used to configure flux
func processDeployKey(params map[string]string, gitDeployKeyPath string) error {
	if gitDeployKeyPath == "" {
		return nil
	}
	b64Key, err := readAndBase64EncodeKey(gitDeployKeyPath)
	if err != nil {
		return err
	}
	params["gitDeployKey"] = b64Key
	return nil
}

func readAndBase64EncodeKey(keypath string) (string, error) {
	content, err := ioutil.ReadFile(keypath)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(content), nil
}

// func configureFlux(b *plan.Builder, params SeedNodeParams) error {
//  gitData := params.GitData
//  if gitData.GitURL == "" {
//      return nil
//  }
//  fluxManifestPath, err := findFluxManifest(params.ConfigDirectory)
//  if err != nil {
//      // We haven't found a flux.yaml manifest in the git repository, use the flux addon.
//      gitParams := map[string]string{"gitURL": gitData.GitURL, "gitBranch": gitData.GitBranch, "gitPath": gitData.GitPath}
//      err := processDeployKey(gitParams, gitData.GitDeployKeyPath)
//      if err != nil {
//          return errors.Wrap(err, "failed to process the git deploy key")
//      }
//      fluxAddon := existinginfrav1.Addon{Name: "flux", Params: gitParams}
//      manifests, err := buildAddon(fluxAddon, params.ImageRepository, params.ClusterManifestPath, params.GetAddonNamespace("flux"))
//      if err != nil {
//          return errors.Wrap(err, "failed to generate manifests for flux")
//      }
//      for i, m := range manifests {
//          resName := fmt.Sprintf("%s-%02d", "flux", i)
//          fluxRsc := &resource.KubectlApply{Manifest: m, Filename: object.String(resName + ".yaml")}
//          b.AddResource("install:flux:"+resName, fluxRsc, plan.DependOn("kubectl:apply:cluster", "kubectl:apply:machines"))
//      }
//      return nil
//  }

//  // Use flux.yaml from the git repository.
//  manifest, err := createFluxSecretFromGitData(gitData, params)
//  if err != nil {
//      return errors.Wrap(err, "failed to generate git deploy secret manifest for flux")
//  }
//  secretResName := "flux-git-deploy-secret"
//  fluxSecretRsc := &resource.KubectlApply{OpaqueManifest: manifest, Filename: object.String(secretResName + ".yaml")}
//  b.AddResource("install:flux:"+secretResName, fluxSecretRsc, plan.DependOn("kubectl:apply:cluster", "kubectl:apply:machines"))

//  fluxRsc := &resource.KubectlApply{ManifestPath: object.String(fluxManifestPath)}
//  b.AddResource("install:flux:main", fluxRsc, plan.DependOn("install:flux:flux-git-deploy-secret"))
//  return nil
// }

func createConfigFileResourcesFromClusterSpec(providerSpec *existinginfrav1.ClusterSpec, ns string) (map[string][]byte, map[string]*v1.ConfigMap, []*resource.File, error) {
	log.Info("Extracting config files")
	fileSpecs := providerSpec.OS.Files
	log.Info("Got configs")

	configMaps := map[string]*v1.ConfigMap{}
	configMapManifests := map[string][]byte{}

	for _, fspec := range fileSpecs {
		configMap := configMaps[fspec.Source.ConfigMap]
		if configMap == nil {
			configMap = &v1.ConfigMap{}
			configMaps[fspec.Source.ConfigMap] = configMap
		}
		configMap.TypeMeta.APIVersion = "v1"
		configMap.TypeMeta.Kind = "ConfigMap"
		configMap.Name = fspec.Source.ConfigMap
		configMap.Namespace = ns
		if configMap.Data == nil {
			configMap.Data = map[string]string{}
		}
		configMap.Data[fspec.Source.Key] = fspec.Source.Contents
		manifest, err := yaml.Marshal(*configMap)
		if err != nil {
			return nil, nil, nil, err
		}
		configMapManifests[configMap.Name] = manifest
	}
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
        imagePullPolicy: Always
        image: weaveworks/cluster-api-existinginfra-controller:v0.0.6"
        env:
        - name: EXISTINGINFRA_CONTROLLER_IMAGE
          value: weaveworks/cluster-api-existinginfra-controller:v0.0.6"
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
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

const sealedSecretCRDManifestString = `
apiVersion: apiextensions.k8s.io/v1beta1
kind: CustomResourceDefinition
metadata:
  name: sealedsecrets.bitnami.com
spec:
  group: bitnami.com
  names:
    kind: SealedSecret
    listKind: SealedSecretList
    plural: sealedsecrets
    singular: sealedsecret
  scope: Namespaced
  version: v1alpha1
`

const sealedSecretControllerManifestString = `
apiVersion: v1
kind: Service
metadata:
  annotations: {}
  labels:
    name: sealed-secrets-controller
  name: sealed-secrets-controller
  namespace: kube-system
spec:
  ports:
  - port: 8080
    targetPort: 8080
  selector:
    name: sealed-secrets-controller
  type: ClusterIP
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  annotations: {}
  labels:
    name: sealed-secrets-service-proxier
  name: sealed-secrets-service-proxier
  namespace: kube-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: sealed-secrets-service-proxier
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: system:authenticated
---
apiVersion: apps/v1
kind: Deployment
metadata:
  annotations: {}
  labels:
    name: sealed-secrets-controller
  name: sealed-secrets-controller
  namespace: kube-system
spec:
  minReadySeconds: 30
  replicas: 1
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      name: sealed-secrets-controller
  strategy:
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 25%
    type: RollingUpdate
  template:
    metadata:
      annotations: {}
      labels:
        name: sealed-secrets-controller
    spec:
      tolerations:
      # Allow scheduling on master nodes. This is required because during
      # bootstrapping of the cluster, we may initially have just one master,
      # and would then need to deploy this controller there to set the entire
      # cluster up.
      - effect: NoSchedule
        key: node-role.kubernetes.io/master
        operator: Exists
      containers:
      - args: []
        command:
        - controller
        env: []
        image: quay.io/bitnami/sealed-secrets-controller:v0.11.0
        imagePullPolicy: Always
        livenessProbe:
          httpGet:
            path: /healthz
            port: http
        name: sealed-secrets-controller
        ports:
        - containerPort: 8080
          name: http
        readinessProbe:
          httpGet:
            path: /healthz
            port: http
        securityContext:
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1001
        stdin: false
        tty: false
        volumeMounts:
        - mountPath: /tmp
          name: tmp
      imagePullSecrets: []
      initContainers: []
      securityContext:
        fsGroup: 65534
      serviceAccountName: sealed-secrets-controller
      terminationGracePeriodSeconds: 30
      volumes:
      - emptyDir: {}
        name: tmp
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  annotations: {}
  labels:
    name: sealed-secrets-controller
  name: sealed-secrets-controller
  namespace: kube-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: sealed-secrets-key-admin
subjects:
- kind: ServiceAccount
  name: sealed-secrets-controller
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  annotations: {}
  labels:
    name: sealed-secrets-key-admin
  name: sealed-secrets-key-admin
  namespace: kube-system
rules:
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - create
  - list
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  annotations: {}
  labels:
    name: sealed-secrets-controller
  name: sealed-secrets-controller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: secrets-unsealer
subjects:
- kind: ServiceAccount
  name: sealed-secrets-controller
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  annotations: {}
  labels:
    name: secrets-unsealer
  name: secrets-unsealer
rules:
- apiGroups:
  - bitnami.com
  resources:
  - sealedsecrets
  verbs:
  - get
  - list
  - watch
  - update
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - get
  - create
  - update
  - delete
- apiGroups:
  - ""
  resources:
  - events
  verbs:
  - create
  - patch
---
apiVersion: v1
kind: ServiceAccount
metadata:
  annotations: {}
  labels:
    name: sealed-secrets-controller
  name: sealed-secrets-controller
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  annotations: {}
  labels:
    name: sealed-secrets-service-proxier
  name: sealed-secrets-service-proxier
  namespace: kube-system
rules:
- apiGroups:
  - ""
  resourceNames:
  - 'http:sealed-secrets-controller:'
  - sealed-secrets-controller
  resources:
  - services/proxy
  verbs:
  - create
  - get
`
