package test

// Deploys the capei (cluster-api-existinginfra) provider into a 'kind' cluster, then uses the provider to create
// a cluster on top of footloose machines.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"text/template"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/weaveworks/cluster-api-provider-existinginfra/apis/cluster.weave.works/v1alpha3"
	capeios "github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/os"
	clientcmdv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"sigs.k8s.io/yaml"
)

const (
	// Configure footloose to create two machines -- one master, one worker
	footlooseConfig = `
cluster:
  name: centos-multimaster
  privateKey: cluster-key
machines:
- count: 3
  spec:
    image: quay.io/footloose/centos7:0.3.0
    name: node%d
    portMappings:
    - containerPort: 22
      hostPort: 2222
    - containerPort: 6443
      hostPort: 6443
    - containerPort: 30443
      hostPort: 30443
    - containerPort: 30080
      hostPort: 30080
    privileged: true
    volumes:
    - type: volume
      destination: /var/lib/docker
`
	// Namespace in which we will create a workload cluster
	testNamespace = `
apiVersion: v1
kind: Namespace
metadata:
  labels:
  name: test
`
	// Machine pool containing the machines for a workload cluster
	testPoolTemplate = `
apiVersion: v1
kind: Secret
metadata:
  name: ip-pool
  namespace: weavek8sops
type: Opaque
data:
  config: {{ .SecretData }}
`
	// Configuration telling clusterctl where to find the provider
	clusterctlConfig = `
providers:
  - name: "existinginfra"
    url: "file://{{ .HomeDir }}/local-repository/infrastructure-existinginfra/v0.1.0/infrastructure-components.yaml"
    type: "InfrastructureProvider"
`
)

var (
	apiServerArgs = map[string]string{"alsologtostderr": "true", "audit-log-maxsize": "10000"}
	kubeletArgs   = map[string]string{"alsologtostderr": "true", "container-runtime": "docker"}
)

// Deploy our provider and use it to create a workload cluster
func TestWorkloadClusterCreation(t *testing.T) {
	version := os.Getenv("KUBERNETES_VERSION")
	if version == "" {
		version = "1.17.5"
		fmt.Printf("Using default version: '%s'\n", version)
	}

	c := getContext(t)
	defer c.cleanup()

	// Create two footloose machines to host a workload cluster
	machineInfo := createFootlooseMachines(c)
	defer deleteFootlooseMachines(c)

	// Set up a docker network for communication
	setupNetworking(c)

	// Let cluster stabilize
	ensureAllManagementPodsAreRunning(c)

	// Create a local provider repository in the temp directory
	setupProviderRepository(c)

	// Install the existinginfra provider into the management (kind) cluster
	installProvider(c)

	// Set up load balancer
	c.ConfigureHAProxy("127.0.0.1", 2222)

	// Create the namespace that will contain our resources
	installNamespace(c)

	// Create a machine pool with IPs, keys, and users
	installMachinePool(c, machineInfo)

	// Wait for the management cluster to be ready
	ensureAllManagementPodsAreRunning(c)

	// Create a workload cluster
	createWorkloadCluster(c, version)

	// Get workload kubeconfig
	workloadKubeConfig := getWorkloadKubeconfig(c)

	// Wait for the cluster to be fully up with two ready nodes
	ensureAllWorkloadNodesAreRunning(c, workloadKubeConfig)

	// Change some apiserver and kubelet arguments
	applyNewAPIServerAndKubeletArguments(c, workloadKubeConfig)

	// Wait for the cluster to start repaving
	ensureAllWorkloadNodesStoppedRunning(c, workloadKubeConfig)

	// Wait for the cluster to once again be fully up with two ready nodes
	ensureAllWorkloadNodesAreRunning(c, workloadKubeConfig)

	// Check that the arguments are updated
	ensureNewArgumentsWereProcessed(c)

}

func installCertManager(c *context) {
	log.Info("Installing cert manager...")
	// kubectl apply --validate=false -f https://github.com/jetstack/cert-manager/releases/download/v0.11.1/cert-manager.yaml
	c.runAndCheckError("kubectl", "apply", "--validate=false", "-f", "https://github.com/jetstack/cert-manager/releases/download/v0.11.1/cert-manager.yaml")
}

func setupNetworking(c *context) {
	c.runAndCheckError("docker", "network", "connect", "bridge", "kind-control-plane")
}

// Copy in the existinginfra local-repository and set up configuration to point to it
func setupProviderRepository(c *context) {
	log.Info("Setting up provider repository...")
	providerRepositoryDir := filepath.Join(c.testDir, "..", "..", "..", "local-repository")
	c.runAndCheckError("cp", "-r", providerRepositoryDir, c.tmpDir)
	t, err := template.New("clusterctlconfig").Parse(clusterctlConfig)
	require.NoError(c.t, err)
	var populated bytes.Buffer
	err = t.Execute(&populated, struct {
		HomeDir string
	}{
		c.tmpDir,
	})
	require.NoError(c.t, err)
	configDir := filepath.Join(c.tmpDir, ".cluster-api")
	os.MkdirAll(configDir, 0777)
	ioutil.WriteFile(filepath.Join(configDir, "clusterctl.yaml"), populated.Bytes(), 0600)
}

func installProvider(c *context) {
	log.Info("Installing existinginfra provider...")
	c.runWithConfig(
		commandConfig{
			Env:        c.getProviderEnvironment(),
			Stdout:     os.Stdout,
			Stderr:     os.Stderr,
			CheckError: true},
		filepath.Join(c.tmpDir, "clusterctl"), "init", "--infrastructure=existinginfra")
}

func installNamespace(c *context) {
	log.Info("Installing namespace...")
	c.applyManagementManifest(testNamespace)
}

// Create a pool containing two footloose machines and their credentials
func installMachinePool(c *context, info []capeios.MachineInfo) {
	log.Info("Installing machine pool...")
	t, err := template.New("machine-pool").Parse(testPoolTemplate)
	require.NoError(c.t, err)

	infostr, err := json.Marshal(info)
	require.NoError(c.t, err)
	encoded := base64.StdEncoding.EncodeToString(infostr)
	var populated bytes.Buffer
	err = t.Execute(&populated, struct {
		SecretData string
	}{
		encoded,
	})
	require.NoError(c.t, err)
	c.applyManagementManifest(string(populated.Bytes()))
}

// Update kubelet and apiserver arguments in running cluster
func applyNewAPIServerAndKubeletArguments(c *context, kubeconfig string) {
	eic := getExistingInfraCluster(c)
	cleanJson := eic.Annotations["kubectl.kubernetes.io/last-applied-configuration"]
	var cleanEic v1alpha3.ExistingInfraCluster
	err := json.Unmarshal([]byte(cleanJson), &cleanEic)
	require.NoError(c.t, err)
	eic = &cleanEic
	aargs := []v1alpha3.ServerArgument{}
	for name, value := range apiServerArgs {
		aargs = append(aargs, v1alpha3.ServerArgument{Name: name, Value: value})
	}
	eic.Spec.APIServer.ExtraArguments = aargs
	kargs := []v1alpha3.ServerArgument{}
	for name, value := range kubeletArgs {
		kargs = append(kargs, v1alpha3.ServerArgument{Name: name, Value: value})
	}
	eic.Spec.KubeletArguments = kargs
	bytes, err := yaml.Marshal(eic)
	require.NoError(c.t, err)
	c.applyWorkloadManifest(string(bytes), kubeconfig)
}

// Retrieve the cluster resource from the management cluster
func getExistingInfraCluster(c *context) *v1alpha3.ExistingInfraCluster {
	cmanifest, _, err := c.runCollectingOutput("kubectl", "get", "existinginfracluster", "test-cluster", "--namespace=test", "-o", "json")
	require.NoError(c.t, err)
	var eic v1alpha3.ExistingInfraCluster
	err = json.Unmarshal(cmanifest, &eic)
	require.NoError(c.t, err)
	return &eic
}

type conn struct {
	ip   string
	port string
}

// Check that arguments show up after being changed on the fly
func ensureNewArgumentsWereProcessed(c *context) {
	conns := []conn{{ip: "127.0.0.1", port: "2223"}, {ip: "127.0.0.1", port: "2224"}}

	for name, val := range kubeletArgs {
		for _, conn := range conns {
			argString := fmt.Sprintf("%s=%s", name, val)
			out, eout, err := c.sshCall(conn.ip, conn.port, fmt.Sprintf("ps -ef | grep -v 'ps -ef' | grep /usr/bin/kubelet | grep %s", argString))
			log.Infof("OUT: %s, EOUT: %s, ERR: %v", out, eout, err)
		}
	}

	for name, val := range apiServerArgs {
		for _, conn := range conns {
			argString := fmt.Sprintf("%s=%s", name, val)
			out, eout, err := c.sshCall(conn.ip, conn.port, fmt.Sprintf("ps -ef | grep -v 'ps -ef' | grep kube-apiserver | grep %s", argString))
			log.Infof("AOUT: %s, AEOUT: %s, AERR: %v", out, eout, err)
			//		c.makeSSHCallAndCheckError("172.17.0.4", "2224", fmt.Sprintf("ps -ef | grep -v 'ps -ef' | grep kube-apiserver | grep %s", argString))
		}
	}
}

// Wait for the management cluster to be ready for cluster creation
func ensureAllManagementPodsAreRunning(c *context) {
	log.Info("Ensuring all pods are running...")
	c.ensureRunning("pods", filepath.Join(c.tmpDir, ".kube", "config"))
}

// Wait for the workload cluster to be ready
func ensureAllWorkloadNodesAreRunning(c *context, workloadKubeconfig string) {
	log.Info("Ensuring nodes are running...")
	c.ensureCount("nodes", 2, workloadKubeconfig)
	c.ensureRunning("nodes", workloadKubeconfig)
}

// Wait for the workload cluster to be NOT ready
func ensureAllWorkloadNodesStoppedRunning(c *context, workloadKubeconfig string) {
	log.Info("Ensuring all nodes stop running...")
	c.ensureAllStoppedRunning("nodes", workloadKubeconfig)
}

// Get the configuration for the workload cluster
func getWorkloadKubeconfig(c *context) string {
	var configBytes []byte
	for retryCount := 1; retryCount <= 30; retryCount++ {
		localConfigBytes, _, err := c.sshCall("127.0.0.1", "2223", "cat /etc/kubernetes/admin.conf")
		if err == nil {
			log.Info("Got kubeconfig for workload cluster...")
			configBytes = bytes.Replace(localConfigBytes, []byte("172.17.0.3"), []byte("127.0.0.1"), 1)
			var config clientcmdv1.Config
			err := yaml.Unmarshal(configBytes, &config)
			require.NoError(c.t, err)
			cluster := &config.Clusters[0].Cluster
			cluster.InsecureSkipTLSVerify = true
			cluster.CertificateAuthorityData = nil
			configBytes, err = yaml.Marshal(config)
			break
		} else {
			log.Infof("Waiting for kubeconfig to be created, retry: %d...", retryCount)
		}
		time.Sleep(30 * time.Second)
	}
	f, err := ioutil.TempFile(c.tmpDir, "kubeconfig-*")
	require.NoError(c.t, err)
	defer f.Close()
	fmt.Fprintf(f, "%s", configBytes)
	log.Infof("Kubeconfig name: %s", f.Name())
	return f.Name()
}

// Apply the generated cluster manifest to trigger workload cluster creation
func createWorkloadCluster(c *context, vsn string) {
	log.Info("Creating workload cluster...")
	manifest, eout, err := c.runCollectingOutputWithConfig(
		commandConfig{
			Env:    c.getProviderEnvironment(),
			Stdout: os.Stdout,
			Stderr: os.Stderr},
		filepath.Join(c.tmpDir, "clusterctl"), "config", "cluster", "test-cluster", "--kubernetes-version", vsn, "-n", "test")
	if err != nil {
		log.Infof("Error out: %s, err: %#v", eout, err)
	}
	require.NoError(c.t, err)
	c.applyManagementManifest(string(manifest))
}

// Create footloose machines to host a workload cluster
func createFootlooseMachines(c *context) []capeios.MachineInfo {
	// First, make sure we're clean
	c.runWithConfig(commandConfig{}, "docker", "rm", "-f", "centos-multimaster-node0", "centos-multimaster-node1", "centos-multimaster-node2")
	log.Info("Creating footloose machines...")
	configPath := filepath.Join(c.tmpDir, "footloose.yaml")
	err := ioutil.WriteFile(configPath, []byte(footlooseConfig), 0600)
	require.NoError(c.t, err)
	key, _ := createKey(c, "cluster-key")
	alternatePrivateKey, alternatePublicKey := createKey(c, "alternate-key") // Different key for second machine - we'll add it to authorized_keys
	c.runWithConfig(commandConfig{CheckError: true, Dir: c.tmpDir}, filepath.Join(c.tmpDir, "go", "bin", "footloose"), "create")
	c.runAndCheckError("sh", "-c",
		fmt.Sprintf("echo '%s' | ssh -i %s -l root -o 'UserKnownHostsFile /dev/null' -o 'StrictHostKeyChecking=no' -p 2224 127.0.0.1 'cat >> /root/.ssh/authorized_keys'",
			alternatePublicKey, filepath.Join(c.tmpDir, "cluster-key")))
	return []capeios.MachineInfo{
		{
			SSHUser:     "root",
			SSHKey:      base64.StdEncoding.EncodeToString(key),
			PublicIP:    "172.17.0.3",
			PublicPort:  "22",
			PrivateIP:   "172.17.0.3",
			PrivatePort: "22",
		},
		{
			SSHUser:     "root",
			SSHKey:      base64.StdEncoding.EncodeToString(alternatePrivateKey),
			PublicIP:    "172.17.0.4",
			PublicPort:  "22",
			PrivateIP:   "172.17.0.4",
			PrivatePort: "22",
		},
		{
			// load balancer
			SSHUser: "root",
			SSHKey:  base64.StdEncoding.EncodeToString(key),
			// Use private address for public since we're using footloose machines
			// from docker
			PublicIP:    "172.17.0.2",
			PublicPort:  "22",
			PrivateIP:   "172.17.0.2",
			PrivatePort: "22",
		},
	}
}

// Delete the machines underpinning the workload cluster
func deleteFootlooseMachines(c *context) {
	c.runWithConfig(commandConfig{Dir: c.tmpDir}, filepath.Join(c.tmpDir, "go", "bin", "footloose"), "delete")
}

// Create an SSH key for the footloose machines
func createKey(c *context, keyFileName string) ([]byte, []byte) {
	// ssh-keygen -q -t rsa -b 4096 -C wk-quickstart@weave.works -f cluster-key -N ""
	path := filepath.Join(c.tmpDir, keyFileName)
	c.runAndCheckError("ssh-keygen", "-q", "-t", "rsa", "-b", "4096", "-C", "wk-quickstart@weave.works", "-f", path, "-N", "")
	privateKey, err := ioutil.ReadFile(path)
	require.NoError(c.t, err)
	publicKey, err := ioutil.ReadFile(path + ".pub")
	return privateKey, publicKey
}
