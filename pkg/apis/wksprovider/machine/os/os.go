package os

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	existinginfrav1 "github.com/weaveworks/cluster-api-provider-existinginfra/apis/cluster.weave.works/v1alpha3"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/config"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/crds"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/recipe"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/resource"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/runners/sudo"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/envcfg"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/manifest"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/object"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/version"
	"github.com/weaveworks/libgitops/pkg/serializer"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/api/apps/v1beta2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubeadmapi "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm/v1beta1"
	"sigs.k8s.io/yaml"
)

// TODO replace wksctl with a more generic term
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
	connectionSecretTemplate = `apiVersion: v1
data:
  config: {{.SecretValue}}
kind: Secret
metadata:
  name: connection-info
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
	PEMSecretResources map[string]*SecretResourceSpec
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

// MachineInfo holds connection information (key, ips, ports) about a machine
type MachineInfo struct {
	SSHUser     string `json:"sshUser"`
	SSHKey      string `json:"sshKey"`
	PublicIP    string `json:"publicIP"`
	PublicPort  string `json:"publicPort"`
	PrivateIP   string `json:"privateIP"`
	PrivatePort string `json:"privatePort"`
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
	ConnectionInfo       []MachineInfo
	// BootstrapToken is the token used by kubeadm init and kubeadm join
	// to safely form new clusters.
	BootstrapToken       *kubeadmapi.BootstrapTokenString
	KubeletConfig        config.KubeletConfig
	Controller           ControllerParams
	GitData              GitParams
	AuthInfo             *AuthParams
	SealedSecretKey      string
	SealedSecretCert     string
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
func SetupSeedNode(ctx context.Context, o *OS, params SeedNodeParams) error {
	p, err := CreateSeedNodeSetupPlan(ctx, o, params)
	if err != nil {
		return err
	}
	return ApplyPlan(ctx, o, p)
}

// CreateSeedNodeSetupPlan constructs the seed node plan used to setup the initial node
// prior to turning control over to wks-controller
func CreateSeedNodeSetupPlan(ctx context.Context, o *OS, params SeedNodeParams) (*plan.Plan, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	log.Info("Validated params")
	cfg, err := envcfg.GetEnvSpecificConfig(ctx, o.PkgType, params.Namespace, params.KubeletConfig.CloudProvider, o.Runner)
	if err != nil {
		return nil, err
	}
	log.Info("Got environment config")

	// Get cluster
	cluster := params.ExistingInfraCluster
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

	criRes := recipe.BuildCRIPlan(ctx, &cluster.Spec.CRI, cfg, o.PkgType)
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
			SSHKey:                params.ConnectionInfo[0].SSHKey,
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
	// const cni = "weave-net"

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
		configDeps, err = addSealedSecretResourcesIfNecessary(b, kubectlApplyDeps, params.AuthInfo.PEMSecretResources, sealedSecretVersion, params.SealedSecretKey, params.SealedSecretCert, params.Namespace)
		if err != nil {
			return nil, err
		}
	}

	// Set plan as an annotation on node, just like controller does
	seedNodePlan, err := seedNodeSetupPlan(ctx, o, params, &cluster.Spec, configMaps, kubernetesVersion)
	if err != nil {
		return nil, err
	}
	log.Info("Got seed node plan")

	b.AddResource("node:plan", &resource.KubectlAnnotateSingleNode{Key: recipe.PlanKey, Value: seedNodePlan.ToState().ToJSON()}, plan.DependOn("kubeadm:init"))

	if params.AuthInfo != nil {
		addAuthConfigMapIfNecessary(configMapManifests, params.AuthInfo.AuthConfigManifest)
	}

	// Add config maps to system so controller can use them
	configMapPlan := recipe.BuildConfigMapPlan(configMapManifests, params.Namespace)
	log.Info("Got config map plan")

	b.AddResource("install:configmaps", configMapPlan, plan.DependOn(configDeps[0], configDeps[1:]...))

	applyClstrRsc := &resource.KubectlApply{Manifest: []byte(params.ClusterManifest), Namespace: object.String(params.Namespace), Filename: object.String("clustermanifest")}
	b.AddResource("kubectl:apply:cluster", applyClstrRsc, plan.DependOn("install:configmaps", kubectlApplyDeps...))

	mManRsc := &resource.KubectlApply{Manifest: []byte(params.MachinesManifest), Filename: object.String("machinesmanifest"), Namespace: object.String(params.Namespace)}
	b.AddResource("kubectl:apply:machines", mManRsc, plan.DependOn(kubectlApplyDeps[0], kubectlApplyDeps[1:]...))

	dep := addSealedSecretWaitIfNecessary(b, params.SealedSecretKey, params.SealedSecretCert)
	connManifest, err := createConnectionSecret(params.Namespace, params.ConnectionInfo)
	if err != nil {
		return nil, err
	}
	b.AddResource("install:connection:info",
		&resource.KubectlApply{
			Manifest: connManifest,
			Filename: object.String("connectionmanifest")},
		plan.DependOn(dep))
	{
		capiCtlrManifest, err := capiControllerManifest(params.Controller, params.Namespace)
		if err != nil {
			return nil, err
		}
		ctlrRsc := &resource.KubectlApply{Manifest: capiCtlrManifest, Filename: object.String("capi_controller.yaml")}
		b.AddResource("install:capi", ctlrRsc, plan.DependOn("kubectl:apply:cluster", "install:connection:info"))
	}

	wksCtlrManifest, err := WksControllerManifest(params.Controller.ImageOverride, params.Namespace)
	if err != nil {
		return nil, err
	}

	ctlrRsc := &resource.KubectlApply{Manifest: wksCtlrManifest, Filename: object.String("wks_controller.yaml")}
	b.AddResource("install:wks", ctlrRsc, plan.DependOn("kubectl:apply:cluster", dep))

	if err := ConfigureFlux(b, params); err != nil {
		return nil, errors.Wrap(err, "Failed to configure flux")
	}

	return CreatePlan(b)
}

func addSealedSecretWaitIfNecessary(b *plan.Builder, key, cert string) string {
	if key != "" && cert != "" {
		b.AddResource("wait:sealed-secrets-controller",
			&resource.KubectlWait{WaitNamespace: "kube-system", WaitType: "pods", WaitSelector: "name=sealed-secrets-controller",
				WaitCondition: "condition=Ready", WaitTimeout: "300s"},
			plan.DependOn("kubectl:apply:machines"))
		return "wait:sealed-secrets-controller"
	}
	return "kubectl:apply:machines"
}

func addSealedSecretResourcesIfNecessary(b *plan.Builder, kubectlApplyDeps []string, pemSecretResources map[string]*SecretResourceSpec, sealedSecretVersion, key, cert, ns string) ([]string, error) {
	log.Info("sealedSecretResources...")
	if key != "" && cert != "" {
		keyManifest, err := createSealedSecretKeySecretManifest(key, cert)
		if err != nil {
			return nil, err
		}
		crdManifest := sealedSecretCRDManifest()
		controllerManifest := sealedSecretControllerManifest()
		sealedSecretRsc := recipe.BuildSealedSecretPlan([]byte(sealedSecretVersion), crdManifest,
			keyManifest, controllerManifest)
		b.AddResource("install:sealed-secrets", sealedSecretRsc, plan.DependOn(kubectlApplyDeps[0], kubectlApplyDeps[1:]...))
		log.Info("sealedSecretResources -- created sealed secret plan...")

		// Now that the cluster is up, if auth is configured, create a secret containing the data for use by the machine actuator
		for _, resourceSpec := range pemSecretResources {
			b.AddResource(fmt.Sprintf("install:pem-secret-%s", resourceSpec.SecretName), resourceSpec.Resource, plan.DependOn("install:sealed-secrets"))
		}
		log.Info("sealedSecretResources -- created pem resources...")
		return []string{"install:sealed-secrets"}, nil
	}
	return kubectlApplyDeps, nil
}

func createSealedSecretKeySecretManifest(privateKey, cert string) ([]byte, error) {
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

func ApplyPlan(ctx context.Context, o *OS, p *plan.Plan) error {
	err := p.Undo(ctx, o.Runner, plan.EmptyState)
	if err != nil {
		log.Infof("Pre-plan cleanup failed:\n%s\n", err)
		return err
	}

	_, err = p.Apply(ctx, o.Runner, plan.EmptyDiff())
	if err != nil {
		log.Errorf("Apply of Plan failed:\n%s\n", err)
		return err
	}
	return err
}

func addAuthConfigMapIfNecessary(configMapManifests map[string][]byte, authConfigManifest []byte) {
	if authConfigManifest != nil {
		configMapManifests["auth-config"] = authConfigManifest
	}
}

func capiControllerManifest(controller ControllerParams, namespace string) ([]byte, error) {
	return getManifest(capiControllerManifestString, namespace)
}

func WksControllerManifest(imageOverride, namespace string) ([]byte, error) {
	content, err := getManifest(wksControllerManifestString, namespace)
	if err != nil {
		return nil, err
	}
	content, err = UpdateControllerImage(content, version.ImageTag)
	if err != nil {
		return nil, errors.Wrap(err, "failed to update controller image with build version")
	}
	return UpdateControllerImage(content, imageOverride)
}

func sealedSecretCRDManifest() []byte {
	return sealedSecretCRDManifestString
}

func sealedSecretControllerManifest() []byte {
	return sealedSecretControllerManifestString
}

func getManifest(manifestString, namespace string) ([]byte, error) {
	return manifest.WithNamespace(serializer.FromBytes([]byte(manifestString)), namespace)
}

const deployment = "Deployment"

// updateControllerImage replaces the controller image in the manifest and
// returns the updated manifest
func UpdateControllerImage(manifest []byte, controllerImageOverride string) ([]byte, error) {
	if controllerImageOverride == "" {
		return manifest, nil
	}
	fullOverride := strings.Contains(controllerImageOverride, ":")
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
			currentImage := d.Spec.Template.Spec.Containers[i].Image
			if !fullOverride {
				controllerImageOverride = currentImage[0:strings.Index(currentImage, ":")+1] + controllerImageOverride
			}
			d.Spec.Template.Spec.Containers[i].Image = controllerImageOverride
			env := d.Spec.Template.Spec.Containers[i].Env
			found := false
			for _, entry := range env {
				if entry.Name == "EXISTINGINFRA_CONTROLLER_IMAGE" {
					entry.Value = controllerImageOverride
					found = true
				}
			}
			if !found {
				env = append(env, v1.EnvVar{Name: "EXISTINGINFRA_CONTROLLER_IMAGE", Value: controllerImageOverride})
			}
			d.Spec.Template.Spec.Containers[i].Env = env
			updatedController = true
		}
	}
	if !updatedController {
		return nil, errors.New("failed to update WKS controller's manifest: container not found")
	}
	return yaml.Marshal(d)
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
	idx, daemonSet, err := FindDaemonSet(manifestList)
	if err != nil {
		return nil, errors.New("failed to find daemonset in weave-net manifest")
	}

	err = InjectEnvVarToContainer(daemonSet.Spec.Template.Spec.Containers, containerName, *podCIDRBlock)
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
func InjectEnvVarToContainer(
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

	for _, envVar := range targetContainer.Env {
		if envVar.Name == newEnvVar.Name {
			if envVar.Value != newEnvVar.Value {
				return errors.New(
					fmt.Sprintf("manifest already contains env var %s, and cannot overwrite", newEnvVar.Name))
			}
			return nil
		}
	}
	targetContainer.Env = append(targetContainer.Env, newEnvVar)
	containers[idx] = targetContainer

	return nil
}

// Returns a daemonset manifest from a list
func FindDaemonSet(manifest *v1.List) (int, *appsv1.DaemonSet, error) {
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
func (o OS) SetupNode(ctx context.Context, p *plan.Plan) error {
	// We don't know the state of the machine so undo at the beginning
	//nolint:errcheck
	p.Undo(ctx, o.Runner, plan.EmptyState) // TODO: Implement error checking

	_, err := p.Apply(ctx, o.Runner, plan.EmptyDiff())
	if err != nil {
		log.Errorf("Apply of Plan failed:\n%s\n", err)
	}
	return err
}

// CreateNodeSetupPlan creates the plan that will be used to set up a node.
func (o OS) CreateNodeSetupPlan(ctx context.Context, params NodeParams) (*plan.Plan, error) {
	log.Info("Creating node setup plan")
	if err := params.Validate(); err != nil {
		return nil, err
	}
	log.Info("Validated parameters")

	cfg, err := envcfg.GetEnvSpecificConfig(ctx, o.PkgType, params.Namespace, params.KubeletConfig.CloudProvider, o.Runner)
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
	instCriRsrc := recipe.BuildCRIPlan(ctx, &params.CRI, cfg, o.PkgType)
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

func addAuthArgs(apiServerArgs map[string]string, pemSecretResources map[string]*SecretResourceSpec, providerSpec *existinginfrav1.ClusterSpec) {
	authnResourceSpec := pemSecretResources["authentication"]
	if authnResourceSpec != nil {
		StoreIfNotEmpty(apiServerArgs, "authentication-token-webhook-config-file", filepath.Join(ConfigDestDir, authnResourceSpec.SecretName+".yaml"))
		StoreIfNotEmpty(apiServerArgs, "authentication-token-webhook-cache-ttl", providerSpec.Authentication.CacheTTL)
	}
	authzResourceSpec := pemSecretResources["authorization"]
	if authzResourceSpec != nil {
		apiServerArgs["authorization-mode"] = "Webhook"
		StoreIfNotEmpty(apiServerArgs, "authorization-webhook-config-file", filepath.Join(ConfigDestDir, authzResourceSpec.SecretName+".yaml"))
		StoreIfNotEmpty(apiServerArgs, "authorization-webhook-cache-unauthorized-ttl", providerSpec.Authorization.CacheUnauthorizedTTL)
		StoreIfNotEmpty(apiServerArgs, "authorization-webhook-cache-authorized-ttl", providerSpec.Authorization.CacheAuthorizedTTL)
	}
}

const (
	CentOS = "centos"
	Ubuntu = "ubuntu"
	RHEL   = "rhel"
)

// Identify uses the provided SSH client to identify the operating system of
// the machine it is configured to talk to.
func Identify(ctx context.Context, sshClient plan.Runner) (*OS, error) {
	osID, err := fetchOSID(ctx, sshClient)
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

func fetchOSID(ctx context.Context, sshClient plan.Runner) (string, error) {
	stdOut, err := sshClient.RunCommand(ctx, "cat /etc/*release", nil)
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

type SecretResourceSpec struct {
	SecretName string
	Decrypted  resource.SecretData
	Resource   plan.Resource
}

func StoreIfNotEmpty(vals map[string]string, key, value string) {
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

func seedNodeSetupPlan(ctx context.Context, o *OS, params SeedNodeParams, providerSpec *existinginfrav1.ClusterSpec, providerConfigMaps map[string]*v1.ConfigMap, kubernetesVersion string) (*plan.Plan, error) {
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
			secrets[k] = v.Decrypted
		}
	}
	return o.CreateNodeSetupPlan(ctx, nodeParams)
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

func ConfigureFlux(b *plan.Builder, params SeedNodeParams) error {
	gitData := params.GitData
	if gitData.GitURL == "" {
		return nil
	}

	t, err := template.New("flux-config").Parse(fluxManifestTemplate)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err = t.Execute(&buf, struct {
		Namespace string
		GitURL    string
		GitBranch string
		GitPath   string
	}{
		params.Namespace,
		gitData.GitURL,
		gitData.GitBranch,
		gitData.GitPath,
	}); err != nil {
		return err
	}

	manifest, err := createFluxSecretFromGitData(gitData, params)
	if err != nil {
		return errors.Wrap(err, "failed to generate git deploy secret manifest for flux")
	}

	secretResName := "flux-git-deploy-secret"
	fluxSecretRsc := &resource.KubectlApply{OpaqueManifest: manifest, Filename: object.String(secretResName + ".yaml")}
	b.AddResource("install:flux:"+secretResName, fluxSecretRsc, plan.DependOn("kubectl:apply:cluster", "kubectl:apply:machines"))

	fluxRsc := &resource.KubectlApply{Manifest: buf.Bytes(), Filename: object.String("flux.yaml")}
	b.AddResource("install:flux:main", fluxRsc, plan.DependOn("install:flux:flux-git-deploy-secret"))
	return nil
}

func createConnectionSecret(namespace string, connInfo []MachineInfo) ([]byte, error) {
	t, err := template.New("local-ip-pool").Parse(connectionSecretTemplate)
	if err != nil {
		return nil, err
	}
	infostr, err := json.Marshal(connInfo)
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(infostr)
	var populated bytes.Buffer
	err = t.Execute(&populated, struct {
		Namespace   string
		SecretValue string
	}{namespace, encoded})
	if err != nil {
		return nil, err
	}
	return populated.Bytes(), nil
}

func createFluxSecretFromGitData(gitData GitParams, params SeedNodeParams) ([]byte, error) {
	gitParams := map[string]string{"namespace": params.Namespace}
	err := processDeployKey(gitParams, gitData.GitDeployKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to process the git deploy key")
	}
	return replaceGitFields(fluxSecretTemplate, gitParams)
}

func replaceGitFields(templateBody string, gitParams map[string]string) ([]byte, error) {
	t, err := template.New("flux-secret").Parse(templateBody)
	if err != nil {
		return nil, err
	}
	var populated bytes.Buffer
	err = t.Execute(&populated, struct {
		Namespace   string
		SecretValue string
	}{gitParams["namespace"], gitParams["gitDeployKey"]})
	if err != nil {
		return nil, err
	}
	return populated.Bytes(), nil
}

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

const capiControllerManifestString = `apiVersion: apps/v1
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

const wksControllerManifestString = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: wks-controller
  namespace: weavek8sops
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
        image: docker.io/weaveworks/cluster-api-existinginfra-controller:v0.0.6
        env:
        - name: EXISTINGINFRA_CONTROLLER_IMAGE
          value: docker.io/weaveworks/cluster-api-existinginfra-controller:v0.0.6
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        args:
        - --verbose
        resources:
          limits:
            cpu: 100m
            memory: 100Mi
          requests:
            cpu: 100m
            memory: 20Mi
`

// weaveworks/cluster-api-existinginfra-controller:v0.0.6
var sealedSecretCRDManifestString = []byte(`apiVersion: apiextensions.k8s.io/v1beta1
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
`)

var sealedSecretControllerManifestString = []byte(`apiVersion: v1
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
`)

const fluxManifestTemplate = `apiVersion: v1
items:
- apiVersion: v1
  kind: ServiceAccount
  metadata:
    labels:
      name: flux
    name: flux
    namespace: {{ .Namespace }}
- apiVersion: rbac.authorization.k8s.io/v1beta1
  kind: ClusterRole
  metadata:
    labels:
      name: flux
    name: flux
    namespace: weavek8sops
  rules:
  - apiGroups:
    - '*'
    resources:
    - '*'
    verbs:
    - '*'
  - nonResourceURLs:
    - '*'
    verbs:
    - '*'
- apiVersion: rbac.authorization.k8s.io/v1beta1
  kind: ClusterRoleBinding
  metadata:
    labels:
      name: flux
    name: flux
    namespace: weavek8sops
  roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: flux
  subjects:
  - kind: ServiceAccount
    name: flux
    namespace: weavek8sops
- apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: memcached
    namespace: weavek8sops
  spec:
    replicas: 1
    selector:
      matchLabels:
        name: memcached
    template:
      metadata:
        labels:
          name: memcached
      spec:
        containers:
        - args:
          - -m 64
          - -p 11211
          image: memcached:1.4.25
          imagePullPolicy: IfNotPresent
          name: memcached
          ports:
          - containerPort: 11211
            name: clients
        tolerations:
        - effect: NoSchedule
          key: node-role.kubernetes.io/master
          operator: Exists
        - key: CriticalAddonsOnly
          operator: Exists
- apiVersion: v1
  kind: Service
  metadata:
    name: memcached
    namespace: weavek8sops
  spec:
    clusterIP: None
    ports:
    - name: memcached
      port: 11211
      targetPort: 11211
    selector:
      name: memcached
- apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: flux
    namespace: weavek8sops
  spec:
    replicas: 1
    selector:
      matchLabels:
        name: flux
    strategy:
      type: Recreate
    template:
      metadata:
        annotations:
          prometheus.io.port: "3031"
        labels:
          name: flux
      spec:
        containers:
        - args:
          - --ssh-keygen-dir=/var/fluxd/keygen
          - --git-url={{ .GitURL }}
          - --git-branch={{ .GitBranch }}
          - --git-poll-interval=30s
          - --git-path={{ .GitPath }}
          - --git-readonly
          - --memcached-hostname=memcached.weavek8sops.svc.cluster.local
          - --memcached-service=memcached
          - --listen-metrics=:3031
          - --sync-garbage-collection
          - --manifest-generation=false
          image: fluxcd/flux:1.14.2
          imagePullPolicy: IfNotPresent
          name: flux
          ports:
          - containerPort: 3030
          volumeMounts:
          - mountPath: /etc/fluxd/ssh
            name: git-key
            readOnly: true
          - mountPath: /var/fluxd/keygen
            name: git-keygen
        serviceAccount: flux
        tolerations:
        - effect: NoSchedule
          key: node-role.kubernetes.io/master
          operator: Exists
        - key: CriticalAddonsOnly
          operator: Exists
        volumes:
        - name: git-key
          secret:
            defaultMode: 256
            secretName: flux-git-deploy
        - emptyDir:
            medium: Memory
          name: git-keygen
kind: List
metadata: {}
`
