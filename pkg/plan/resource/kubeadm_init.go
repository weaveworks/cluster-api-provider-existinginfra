package resource

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/config"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/config/kubeadm"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/config/kubeproxy"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/scripts"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/manifests"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan"
	kubeadmutil "github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/kubeadm"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/manifest"
	capeimanifest "github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/manifest"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/object"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/ssh"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/version"
	"github.com/weaveworks/libgitops/pkg/serializer"
	corev1 "k8s.io/api/core/v1"
	kubeadmapi "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm/v1beta1"
	"sigs.k8s.io/yaml"
)

// KubeadmInit represents an attempt to init a Kubernetes node via kubeadm.
type KubeadmInit struct {
	Base

	// PublicIP is public IP of the master node we are trying to setup here.
	PublicIP string `structs:"publicIP"`
	// PrivateIP is private IP of the master node we are trying to setup here.
	PrivateIP string `structs:"privateIP"`
	// NodeName, if non-empty, will override the default node name guessed by kubeadm.
	NodeName string
	// KubeletConfig groups all options & flags which need to be passed to kubelet.
	KubeletConfig *config.KubeletConfig `structs:"kubeletConfig"`
	// ConntrackMax is the maximum number of NAT connections for kubeproxy to track (0 to leave as-is).
	ConntrackMax int32 `structs:"conntrackMax"`
	// UseIPTables controls whether the following command is called or not:
	//   sysctl net.bridge.bridge-nf-call-iptables=1
	// prior to running kubeadm init.
	UseIPTables bool `structs:"useIPTables"`
	// kubeadmInitScriptPath is the path to the "kubeadm init" script to use.
	KubeadmInitScriptPath string `structs:"kubeadmInitScriptPath"`
	// IgnorePreflightErrors is optionally used to skip kubeadm's preflight checks.
	IgnorePreflightErrors []string `structs:"ignorePreflightErrors"`
	// SSHKeyPath is the path to the private SSH key used by WKS to SSH into
	// nodes to add/remove them to/from the Kubernetes cluster. Only one of SSHKeyPath
	// and SSHKey may be specified
	SSHKeyPath string `structs:"sshKeyPath"`
	// SSHKey is the private SSH key used by WKS to SSH into
	// nodes to add/remove them to/from the Kubernetes cluster. Only one of SSHKeyPath
	// and SSHKey may be specified
	SSHKey string `structs:"-" plan:"hide"`
	// BootstrapToken is the token used by kubeadm init and kubeadm join to
	// safely form new clusters.
	BootstrapToken *kubeadmapi.BootstrapTokenString `structs:"bootstrapToken"`
	// The version of Kubernetes to install
	KubernetesVersion string `structs:"kubernetesVersion"`
	// ControlPlaneEndpoint is the IP:port of the control plane load balancer.
	// Default: localhost:6443
	// See also: https://kubernetes.io/docs/setup/independent/high-availability/#stacked-control-plane-and-etcd-nodes
	ControlPlaneEndpoint string `structs:"controlPlaneEndpoint"`
	// Cloud provider setting which is needed for kubeadm and kubelet
	CloudProvider string `structs:"cloudProvider"`
	// ImageRepository sets the container registry to pull images from. If empty,
	// `k8s.gcr.io` will be used by default.
	ImageRepository string `structs:"imageRepository"`
	// AssetDescriptions specifies the image repository and image tag for each potentially overridden
	// asset (currently, DNS, Etcd, and Kubernetes)
	AssetDescriptions map[string]kubeadmutil.AssetDescription
	// AdditionalSANs can hold additional SANs to add to the API server certificate.
	AdditionalSANs []string
	// The namespace in which to init kubeadm
	Namespace fmt.Stringer
	// Extra arguments to pass to the APIServer
	ExtraAPIServerArgs map[string]string
	// The IP range for service VIPs
	ServiceCIDRBlock string
	// PodCIDRBlock is the subnet used by pods.
	PodCIDRBlock string
}

var _ plan.Resource = plan.RegisterResource(&KubeadmInit{})

// State implements plan.Resource.
func (ki *KubeadmInit) State() plan.State {
	return ToState(ki)
}

func isEKSD(repo string) bool {
	return repo == "public.ecr.aws/eks-distro/kubernetes"
}

// Apply implements plan.Resource.
// TODO: find a way to make this idempotent.
// TODO: should such a resource be split into smaller resources?
func (ki *KubeadmInit) Apply(ctx context.Context, runner plan.Runner, diff plan.Diff) (bool, error) {
	// Can't override two ways
	if ki.ImageRepository != "" && len(ki.AssetDescriptions) != 0 {
		return false, fmt.Errorf("Kubernetes image repository defined twice; you must either define " +
			"a global image repository in the ExistingInfraCluster manifest, or define specific image " +
			"repositories via a flavor specification.")
	}

	log.Debug("Initializing Kubernetes cluster")

	sshKey := []byte(ki.SSHKey)
	var err error

	if ki.SSHKeyPath != "" {
		sshKey, err = ssh.ReadPrivateKey(ki.SSHKeyPath)
		if err != nil {
			return false, err
		}
	}

	namespace := ki.Namespace.String()
	if namespace == "" {
		namespace = manifest.DefaultNamespace
	}

	var dns *kubeadmapi.DNS = nil
	dnsAD, found := ki.AssetDescriptions["DNS"]
	if found {
		dns = &kubeadmapi.DNS{
			Type: "",
			ImageMeta: kubeadmapi.ImageMeta{
				ImageRepository: dnsAD.ImageRepository, //"public.ecr.aws/eks-distro/coredns",
				ImageTag:        dnsAD.ImageTag,        //"v1.7.0-eks-1-18-1",
			},
		}
	}

	var etcd *kubeadmapi.Etcd = nil
	etcdAD, found := ki.AssetDescriptions["Etcd"]
	if found {
		etcd = &kubeadmapi.Etcd{
			Local: &kubeadmapi.LocalEtcd{
				ImageMeta: kubeadmapi.ImageMeta{
					ImageRepository: etcdAD.ImageRepository, //"public.ecr.aws/eks-distro/etcd-io",
					ImageTag:        etcdAD.ImageTag,        //"v3.4.14-eks-1-18-1",
				},
				DataDir:        "",
				ExtraArgs:      nil,
				ServerCertSANs: nil,
				PeerCertSANs:   nil,
			},
		}
	}

	k8sImageTag := ""
	kubeAD, found := ki.AssetDescriptions["Kubernetes"]
	if found {
		k8sImageTag = kubeAD.ImageTag
		ki.ImageRepository = kubeAD.ImageRepository //"public.ecr.aws/eks-distro/kubernetes" // XXXXXXXXXXXXXXXXXX
	}

	clusterConfig, err := yaml.Marshal(kubeadm.NewClusterConfiguration(kubeadm.ClusterConfigurationParams{
		KubernetesVersion:    ki.KubernetesVersion + k8sImageTag,
		NodeIPs:              []string{ki.PublicIP, ki.PrivateIP},
		ControlPlaneEndpoint: ki.ControlPlaneEndpoint,
		CloudProvider:        ki.CloudProvider,
		ImageRepository:      ki.ImageRepository,
		AdditionalSANs:       ki.AdditionalSANs,
		ExtraArgs:            ki.ExtraAPIServerArgs,
		ServiceCIDRBlock:     ki.ServiceCIDRBlock,
		PodCIDRBlock:         ki.PodCIDRBlock,
		DNS:                  dns,
		Etcd:                 etcd,
	}))
	if err != nil {
		return false, errors.Wrap(err, "failed to serialize kubeadm's ClusterConfiguration object")
	}
	kubeadmConfig, err := yaml.Marshal(kubeadm.NewInitConfiguration(kubeadm.InitConfigurationParams{
		NodeName:       ki.NodeName,
		BootstrapToken: ki.BootstrapToken,
		KubeletConfig:  *ki.KubeletConfig,
	}))
	if err != nil {
		return false, errors.Wrap(err, "failed to serialize kubeadm's InitConfiguration object")
	}
	kubeproxyConfig, err := yaml.Marshal(kubeproxy.NewConfig(ki.ConntrackMax))
	if err != nil {
		return false, errors.Wrap(err, "failed to serialize kube-proxy's KubeProxyConfiguration object")
	}

	// Create a temporary buffer for YAML frames, and the corresponding YAML FrameWriter
	buf := new(bytes.Buffer)
	fw := serializer.NewYAMLFrameWriter(buf)

	// Write all three frames into the FrameWriter, and use the output in configBytes
	if err := serializer.WriteFrameList(fw,
		[][]byte{clusterConfig, kubeadmConfig, kubeproxyConfig},
	); err != nil {
		return false, err
	}
	configBytes := buf.Bytes()

	remotePath := "/tmp/wks_kubeadm_init_config.yaml"
	if err = scripts.WriteFile(ctx, configBytes, remotePath, 0660, runner); err != nil {
		return false, errors.Wrap(err, "failed to upload kubeadm's configuration")
	}
	log.WithField("yaml", string(configBytes)).Debug("uploaded kubeadm's configuration")
	//nolint:errcheck
	defer removeFile(ctx, remotePath, runner) // TODO: Deferred error checking

	var stdOutErr string
	p := buildKubeadmInitPlan(
		remotePath,
		strings.Join(ki.IgnorePreflightErrors, ","),
		ki.UseIPTables,
		ki.KubernetesVersion,
		&stdOutErr)
	_, err = p.Apply(ctx, runner, plan.EmptyDiff())
	if err != nil {
		return false, errors.Wrap(err, "failed to initialize Kubernetes cluster with kubeadm")
	}

	// TODO: switch to cluster-info.yaml approach.
	kubeadmJoinCmd, err := kubeadmutil.ExtractJoinCmd(stdOutErr)
	if err != nil {
		return false, err
	}
	log.Debug(kubeadmJoinCmd)
	caCertHash, err := kubeadmutil.ExtractDiscoveryTokenCaCertHash(kubeadmJoinCmd)
	if err != nil {
		return false, err
	}
	certKey, err := kubeadmutil.ExtractCertificateKey(kubeadmJoinCmd)
	if err != nil {
		return false, err
	}

	if err := ki.kubectlApply(ctx, "01_namespace.yaml", namespace, runner); err != nil {
		return false, err
	}

	if err := ki.kubectlApply(ctx, "02_rbac.yaml", namespace, runner); err != nil {
		return false, err
	}
	return true, ki.applySecretWith(ctx, sshKey, caCertHash, certKey, namespace, runner)
}

func (ki *KubeadmInit) updateManifestNamespace(fileName, namespace string) ([]byte, error) {
	content, err := ki.manifestContent(fileName)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to open manifest")
	}
	c, err := capeimanifest.WithNamespace(serializer.FromBytes(content), namespace)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (ki *KubeadmInit) kubectlApply(ctx context.Context, fileName, namespace string, runner plan.Runner) error {
	content, err := ki.updateManifestNamespace(fileName, namespace)
	if err != nil {
		return errors.Wrap(err, "Failed to upate manifest namespace")
	}
	return RunKubectlApply(ctx, runner, KubectlApplyArgs{Content: content}, fileName)
}

func (ki *KubeadmInit) manifestContent(fileName string) ([]byte, error) {
	file, err := manifests.Manifests.Open(fileName)
	if err != nil {
		return nil, err
	}
	content, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func (ki *KubeadmInit) applySecretWith(ctx context.Context, sshKey []byte, discoveryTokenCaCertHash, certKey, namespace string, runner plan.Runner) error {
	log.Info("adding SSH key to WKS secret and applying its manifest")
	fileName := "03_secrets.yaml"
	secret, err := ki.deserializeSecret(fileName, namespace)
	if err != nil {
		return err
	}
	secret.Data["sshKey"] = sshKey
	secret.Data["discoveryTokenCaCertHash"] = []byte(discoveryTokenCaCertHash)
	secret.Data["certificateKey"] = []byte(certKey)
	// We only store the ID as a Secret object containing the bootstrap token's
	// secret is already created by kubeadm init under:
	//   kube-system/bootstrap-token-$ID
	secret.Data["bootstrapTokenID"] = []byte(ki.BootstrapToken.ID)
	bytes, err := yaml.Marshal(secret)
	if err != nil {
		return errors.Wrap(err, "failed to serialize manifest")
	}
	return RunKubectlApply(ctx, runner, KubectlApplyArgs{Content: bytes}, fileName)
}

func (ki *KubeadmInit) deserializeSecret(fileName, namespace string) (*corev1.Secret, error) {
	content, err := ki.updateManifestNamespace(fileName, namespace)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to upate manifest namespace")
	}
	secret := &corev1.Secret{}
	if err = yaml.Unmarshal(content, secret); err != nil {
		return nil, errors.Wrap(err, "failed to deserialize manifest")
	}
	return secret, nil
}

// Undo implements plan.Resource.
func (ki *KubeadmInit) Undo(ctx context.Context, runner plan.Runner, current plan.State) error {
	remotePath := "/tmp/wks_kubeadm_init_config.yaml"
	var ignored string
	return buildKubeadmInitPlan(
		remotePath,
		strings.Join(ki.IgnorePreflightErrors, ","),
		ki.UseIPTables, ki.KubernetesVersion, &ignored).Undo(
		ctx, runner, plan.EmptyState)
}

// buildKubeadmInitPlan builds a plan for kubeadm init command.
// Parameter k8sversion specified here represents the version of both Kubernetes and Kubeadm.
func buildKubeadmInitPlan(path string, ignorePreflightErrors string, useIPTables bool, k8sVersion string, output *string) plan.Resource {
	// Detect version for --upload-cert-flags
	uploadCertsFlag := "--upload-certs"
	if lt, err := version.LessThan(k8sVersion, "v1.15.0"); err == nil && lt {
		uploadCertsFlag = "--experimental-upload-certs"
	}

	// If we're at 1.17.0 or greater, we need to upgrade the kubeadm config before running "kubeadm init"
	upgradeKubeadmConfig := false
	if lt, err := version.LessThan(k8sVersion, "1.17.0"); err == nil && !lt {
		upgradeKubeadmConfig = true
	}

	//
	// We add resources to the plan graph for both "if" and "else" paths to make all resources deterministically connected.
	// The graph resources will be easier to reason about when we execute them in parallel in the future.
	//
	b := plan.NewBuilder()
	if useIPTables {
		b.AddResource(
			"configure:iptables",
			&Run{Script: object.String("sysctl net.bridge.bridge-nf-call-iptables=1")}) // TODO: undo?
	} else {
		b.AddResource(
			"configure:iptables",
			&Run{Script: object.String("echo no operation")})
	}

	if upgradeKubeadmConfig {
		b.AddResource(
			"kubeadm:config:upgrade",
			&Run{Script: plan.ParamString(
				WithoutProxy("kubeadm config migrate --old-config %s --new-config %s_upgraded && mv %s_upgraded %s"), &path, &path, &path, &path),
			},
			plan.DependOn("configure:iptables"),
		)
	} else {
		b.AddResource(
			"kubeadm:config:upgrade",
			&Run{Script: object.String("echo no upgrade is required")},
			plan.DependOn("configure:iptables"),
		)
	}

	b.AddResource(
		"kubeadm:reset",
		&Run{Script: object.String("kubeadm reset --force")},
		plan.DependOn("kubeadm:config:upgrade"),
	).AddResource(
		"kubeadm:config:images",
		&Run{Script: plan.ParamString("kubeadm config images pull --config=%s", &path)},
		plan.DependOn("kubeadm:reset"),
	).AddResource(
		"kubeadm:run-init",
		// N.B.: --experimental-upload-certs encrypts & uploads
		// certificates of the primary control plane in the kubeadm-certs
		// Secret, and prints the value for --certificate-key to STDOUT.
		&Run{Script: plan.ParamString("kubeadm init --config=%s --ignore-preflight-errors=%s %s", &path, &ignorePreflightErrors, &uploadCertsFlag),
			UndoResource: buildKubeadmRunInitUndoPlan(),
			Output:       output,
		},
		plan.DependOn("kubeadm:config:images"),
	)

	var homedir string

	b.AddResource(
		"kubeadm:get-homedir",
		&Run{Script: object.String("echo -n $HOME"), Output: &homedir},
	).AddResource(
		"kubeadm:config:kubectl-dir",
		&Dir{Path: plan.ParamString("%s/.kube", &homedir)},
		plan.DependOn("kubeadm:get-homedir"),
	).AddResource(
		"kubeadm:config:copy",
		&Run{Script: plan.ParamString("cp /etc/kubernetes/admin.conf %s/.kube/config", &homedir)},
		plan.DependOn("kubeadm:run-init", "kubeadm:config:kubectl-dir"),
	).AddResource(
		"kubeadm:config:set-ownership",
		&Run{Script: plan.ParamString("chown -R $(id -u):$(id -g) %s/.kube", &homedir)},
		plan.DependOn("kubeadm:config:copy"),
	)

	p, err := b.Plan()
	if err != nil {
		log.Fatalf("%v", err)
	}
	return &p
}

func buildKubeadmRunInitUndoPlan() plan.Resource {
	b := plan.NewBuilder()
	b.AddResource(
		"file:kube-apiserver.yaml",
		&File{Destination: "/etc/kubernetes/manifests/kube-apiserver.yaml"},
	).AddResource(
		"file:kube-controller-manager.yaml",
		&File{Destination: "/etc/kubernetes/manifests/kube-controller-manager.yaml"},
	).AddResource(
		"file:kube-scheduler.yaml",
		&File{Destination: "/etc/kubernetes/manifests/kube-scheduler.yaml"},
	).AddResource(
		"file:etcd.yaml",
		&File{Destination: "/etc/kubernetes/manifests/etcd.yaml"},
	).AddResource(
		"dir:etcd",
		&Dir{Path: object.String("/var/lib/etcd"), RecursiveDelete: true},
	)
	p, err := b.Plan()
	if err != nil {
		log.Fatalf("%v", err)
	}
	return &p
}

func removeFile(ctx context.Context, remotePath string, runner plan.Runner) error {
	if stdouterr, err := runner.RunCommand(ctx, fmt.Sprintf("rm -f %q", remotePath), nil); err != nil {
		log.WithField("stdouterr", stdouterr).WithField("path", remotePath).Debugf("failed to delete file")
		return errors.Wrapf(err, "failed to delete %q", remotePath)
	}
	return nil
}
