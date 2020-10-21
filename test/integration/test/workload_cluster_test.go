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
	"strings"
	"testing"
	"text/template"
	"time"

	yaml "github.com/ghodss/yaml"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	capeios "github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/os"
	clientcmdv1 "k8s.io/client-go/tools/clientcmd/api/v1"
)

const (
	// Configure footloose to create two machines -- one master, one worker
	footlooseConfig = `
cluster:
  name: centos-singlemaster
  privateKey: cluster-key
machines:
- count: 2
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
  namespace: test
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

	// Install the cert manager before installing our provicer
	installCertManager(c)

	// Create a local provider repository in the temp directory
	setupProviderRepository(c)

	// Install the existinginfra provider into the management (kind) cluster
	installProvider(c)

	// Create the namespace that will contain our resources
	installNamespace(c)

	// Create a machine pool with IPs, keys, and users
	installMachinePool(c, machineInfo)

	// Wait for the management cluster to be ready
	ensureAllManagementPodsAreRunning(c)

	// Create a workload cluster
	createWorkloadCluster(c, version)

	// Wait for the cluster to be fully up with two ready nodes
	ensureAllWorkloadNodesAreRunning(c)
}

func installCertManager(c *context) {
	log.Info("Installing cert manager...")
	// kubectl apply --validate=false -f https://github.com/jetstack/cert-manager/releases/download/v0.11.1/cert-manager.yaml
	c.runAndCheckError("kubectl", "apply", "--validate=false", "-f", "https://github.com/jetstack/cert-manager/releases/download/v1.0.3/cert-manager.yaml")
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
	c.runAndCheckError(filepath.Join(c.tmpDir, "clusterctl"), "init", "--infrastructure=existinginfra")
}

func installNamespace(c *context) {
	log.Info("Installing namespace...")
	c.applyLocalManifest(testNamespace)
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
	c.applyLocalManifest(string(populated.Bytes()))
}

// Wait for the management cluster to be ready for cluster creation
func ensureAllManagementPodsAreRunning(c *context) {
	log.Info("Ensuring all pods are running...")
	ensureRunning(c, "pods", filepath.Join(c.tmpDir, ".kube", "config"))
}

// Wait for the workload cluster to be ready
func ensureAllWorkloadNodesAreRunning(c *context) {
	log.Info("Ensuring nodes are running...")
	workloadKubeconfig := getWorkloadKubeconfig(c)
	ensureCount(c, "nodes", 2, workloadKubeconfig)
	ensureRunning(c, "nodes", workloadKubeconfig)
}

// Get the configuration for the workload cluster
func getWorkloadKubeconfig(c *context) string {
	var configBytes []byte
	for {
		localConfigBytes, _, err := c.runCollectingOutput("ssh", "-i", filepath.Join(c.tmpDir, "cluster-key"), "-l", "root", "-o", "UserKnownHostsFile /dev/null",
			"-o", "StrictHostKeyChecking=no", "-p", "2222", "127.0.0.1", "cat", "/etc/kubernetes/admin.conf")
		if err == nil {
			log.Info("Got kubeconfig for workload cluster...")
			configBytes = bytes.Replace(localConfigBytes, []byte("172.17.0.2"), []byte("127.0.0.1"), 1)
			var config clientcmdv1.Config
			err := yaml.Unmarshal(configBytes, &config)
			require.NoError(c.t, err)
			config.Clusters[0].Cluster.InsecureSkipTLSVerify = true
			config.Clusters[0].Cluster.CertificateAuthorityData = nil
			configBytes, err = yaml.Marshal(config)
			break
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

// Check that a specified number of a resource type is running
func ensureCount(c *context, itemType string, count int, kubeconfigPath string) {
	for retryCount := 1; retryCount <= 20; retryCount++ {
		cmdItems := []string{"kubectl", "get", itemType, "--all-namespaces", "--no-headers=true"}
		cmdResults, _, err := c.runCollectingOutputWithConfig(commandConfig{Env: env("KUBECONFIG=" + kubeconfigPath)}, cmdItems...)
		require.NoError(c.t, err)
		if len(strings.Split(string(cmdResults), "\n")) > count { // Must be "count+1" because of ending blank line
			return
		}
		log.Infof("Waiting for %d %s, retry: %d...", count, itemType, retryCount)
		c.runWithConfig(commandConfig{Env: env("KUBECONFIG=" + kubeconfigPath)},
			"sh", "-c", "kubectl logs -f $(kubectl get pods -A | grep wks-controller | awk '{print($2)}') -n test")
		time.Sleep(30 * time.Second)
	}
	require.FailNow(c.t, fmt.Sprintf("Fewer than %d %s are running...", count, itemType))
}

// Check that each instance of a specified resource type is ready
func ensureRunning(c *context, itemType, kubeconfigPath string) {
	cmdItems := []string{"kubectl", "get", itemType, "--all-namespaces", "-o",
		`jsonpath={range .items[*]}{"\n"}{@.metadata.name}:{range @.status.conditions[*]}{@.type}={@.status};{end}{end}`}

	for retryCount := 1; retryCount <= 20; retryCount++ {
		allReady := true
		cmdResults, _, err := c.runCollectingOutputWithConfig(commandConfig{Env: env("KUBECONFIG=" + kubeconfigPath)}, cmdItems...)
		require.NoError(c.t, err)
		strs := strings.Split(string(cmdResults), "\n")
		for _, str := range strs {
			if str != "" && !strings.Contains(str, "Ready=True") {
				log.Infof("Waiting for: %s", str)
				allReady = false
			}
		}
		if allReady {
			return
		}
		log.Infof("Waiting for all %s to be running, retry: %d...", itemType, retryCount)
		time.Sleep(30 * time.Second)
	}
	require.FailNow(c.t, fmt.Sprintf("Not all %s are running...", itemType))
}

// Apply the generated cluster manifest to trigger workload cluster creation
func createWorkloadCluster(c *context, version string) {
	log.Info("Creating workload cluster...")
	manifest, eout, err := c.runCollectingOutput(filepath.Join(c.tmpDir, "clusterctl"), "config", "cluster", "test-cluster", "--kubernetes-version", version, "-n", "test")
	if err != nil {
		log.Infof("Error out: %s, err: %#v", eout, err)
	}
	require.NoError(c.t, err)
	c.applyLocalManifest(string(manifest))
}

// Create footloose machines to host a workload cluster
func createFootlooseMachines(c *context) []capeios.MachineInfo {
	// First, make sure we're clean
	c.runWithConfig(commandConfig{}, "docker", "rm", "-f", "centos-singlemaster-node0", "centos-singlemaster-node1")
	log.Info("Creating footloose machines...")
	configPath := filepath.Join(c.tmpDir, "footloose.yaml")
	err := ioutil.WriteFile(configPath, []byte(footlooseConfig), 0600)
	require.NoError(c.t, err)
	key := createKey(c)
	c.runWithConfig(commandConfig{CheckError: true, Dir: c.tmpDir}, filepath.Join(c.tmpDir, "go", "bin", "footloose"), "create")
	return []capeios.MachineInfo{
		{
			SSHUser: "root",
			SSHKey:  key,
			// Use private address for public since we're using footloose machines
			// from docker
			PublicIP:    "172.17.0.2",
			PublicPort:  "22",
			PrivateIP:   "172.17.0.2",
			PrivatePort: "22",
		},
		{
			SSHUser:     "root",
			SSHKey:      key,
			PublicIP:    "172.17.0.3",
			PublicPort:  "22",
			PrivateIP:   "172.17.0.3",
			PrivatePort: "22",
		},
	}
}

// Delete the machines underpinning the workload cluster
func deleteFootlooseMachines(c *context) {
	c.runWithConfig(commandConfig{Dir: c.tmpDir}, filepath.Join(c.tmpDir, "go", "bin", "footloose"), "delete")
}

// Create an SSH key for the footloose machines
func createKey(c *context) string {
	// ssh-keygen -q -t rsa -b 4096 -C wk-quickstart@weave.works -f cluster-key -N ""
	path := fmt.Sprintf("%s/cluster-key", c.tmpDir)
	c.runAndCheckError("ssh-keygen", "-q", "-t", "rsa", "-b", "4096", "-C", "wk-quickstart@weave.works", "-f", path, "-N", "")
	key, err := ioutil.ReadFile(path)
	require.NoError(c.t, err)
	return base64.StdEncoding.EncodeToString(key)
}
