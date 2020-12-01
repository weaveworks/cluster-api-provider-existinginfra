//nolint:deadcode,unused // _test files are ignored in .golangci.yaml
package test

// A set of utilities to help with constructing integration tests for cluster-api-existinginfra.
// The "context" struct contains useful parameters and has a set of methods that perform generic
// test operations.

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	existinginfrav1 "github.com/weaveworks/cluster-api-provider-existinginfra/apis/cluster.weave.works/v1alpha3"
	capeios "github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/os"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/recipe"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/resource"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/runners/ssh"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/runners/sudo"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/specs"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/envcfg"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/object"
)

// Holds useful parameters for integration tests. "testDir" is the directory containing the running test; "tmpDir" is
// a temporary directory that can be used as a test base.
type testContext struct {
	t       *testing.T
	tmpDir  string
	testDir string
}

// Configuration options for command-running operations
type commandConfig struct {
	CheckError bool
	Dir        string
	Env        []string
	Stdout     *os.File
	Stderr     *os.File
}

// getTestContext returns a "testContext" object containing all the information needed to perform most
// test tasks. Methods on the testContext object can be used to implement integration tests and manage
// temporary directories, git repositories, and clusters.
func getTestContext(t *testing.T) *testContext {
	tmpDir, err := ioutil.TempDir("", "tmp_dir")
	require.NoError(t, err)
	return getTestContextFrom(t, tmpDir)
}

// Creates a testContext, doing the following:
// - creating a temporary directory (tmpDir) which will be established as HOME (for user-relative configuration)
// - installing kind
// - installing clusterctl
// - cleaning up any existing kind clusters
// - creating a new kind cluster
func getTestContextFrom(t *testing.T, tmpDir string) *testContext {
	log.Infof("Using temporary directory: %s\n", tmpDir)

	c := &testContext{
		t:       t,
		tmpDir:  tmpDir,
		testDir: getTestDir(t),
	}
	log.Info("Installing kind...")
	c.runWithConfig(commandConfig{CheckError: true, Env: env("GO111MODULE=on", "HOME="+tmpDir, "CGO_ENABLED=0"), Stdout: os.Stdout, Stderr: os.Stderr},
		"go", "get", "sigs.k8s.io/kind@v0.9.0")

	log.Info("Installing footloose...")
	c.runWithConfig(commandConfig{CheckError: true, Env: env("GO111MODULE=on", "HOME="+tmpDir, "CGO_ENABLED=0"), Stdout: os.Stdout, Stderr: os.Stderr},
		"go", "get", "github.com/weaveworks/footloose")

	log.Info("Installing clusterctl...")
	for {
		fetchCmd := fmt.Sprintf("curl -L https://github.com/kubernetes-sigs/cluster-api/releases/download/v0.3.10/clusterctl-%s-%s -o %s/clusterctl && chmod a+x %s/clusterctl",
			c.getOS(), c.getArch(), c.tmpDir, c.tmpDir)
		c.runAndCheckError("sh", "-c", fetchCmd)
		_, _, err := c.runCollectingOutput(filepath.Join(c.tmpDir, "clusterctl"), "version")
		if err == nil {
			break
		}
	}
	err := os.Setenv("HOME", c.tmpDir)
	require.NoError(c.t, err)
	kindCmd := filepath.Join(c.tmpDir, "go", "bin", "kind")
	c.run(kindCmd, "delete", "cluster")
	c.runAndCheckError(kindCmd, "create", "cluster")
	return c
}

// Clean everything up; remove temp directory and delete kind cluster
func (c *testContext) cleanup() {
	log.Infof("About to remove temp dir: '%s'", c.tmpDir)
	c.runAndCheckError(filepath.Join(c.tmpDir, "go", "bin", "kind"), "delete", "cluster")
	os.RemoveAll(c.tmpDir)
}

// Determine the current OS
func (c *testContext) getOS() string {
	osbytes, _, err := c.runCollectingOutput("uname", "-s")
	require.NoError(c.t, err)
	os := string(osbytes)
	//nolint:gocritic // This is fine.
	switch {
	case strings.HasPrefix(os, "Linux"):
		return "linux"
	case strings.HasPrefix(os, "Darwin"):
		return "darwin"
	default:
		require.FailNow(c.t, fmt.Sprintf("Unknown operating system: '%s'", os))
	}
	return ""
}

// Determine the current machine architecture
var archmap = map[string]string{
	"armv5":   "armv5",
	"armv6":   "armv6",
	"armv7":   "armv7",
	"aarch64": "arm64",
	"x86_64":  "amd64",
	"x86":     "386",
	"i386":    "386",
	"i686":    "386",
}

func (c *testContext) getArch() string {
	archbytes, _, err := c.runCollectingOutput("uname", "-m")
	arch := string(archbytes)

	require.NoError(c.t, err)
	for key, val := range archmap {
		if strings.HasPrefix(arch, key) {
			return val
		}
	}
	require.FailNow(c.t, fmt.Sprintf("Unknown architecture: '%s'", arch))
	return ""
}

// Find the directory containing the test
func getTestDir(t *testing.T) string {
	testDir, err := os.Getwd()
	require.NoError(t, err)
	return testDir
}

// Helper to create environment slices
func env(items ...string) []string {
	return items
}

// Apply a manifest available inline to the management cluster
func (c *testContext) applyManagementManifest(manifest string) {
	f, err := ioutil.TempFile(c.tmpDir, "---manifest--*---")
	require.NoError(c.t, err)
	defer os.Remove(f.Name())
	err = ioutil.WriteFile(f.Name(), []byte(manifest), 0600)
	require.NoError(c.t, err)
	c.runAndCheckError("kubectl", "apply", "-f", f.Name())
}

// Apply a manifest available inline to the workload cluster
func (c *testContext) applyWorkloadManifest(manifest, kubeconfig string) {
	f, err := ioutil.TempFile(c.tmpDir, "---manifest--*---")
	require.NoError(c.t, err)
	defer os.Remove(f.Name())
	err = ioutil.WriteFile(f.Name(), []byte(manifest), 0600)
	require.NoError(c.t, err)
	_, eout, err := c.runCollectingOutputWithConfig(commandConfig{Env: env("KUBECONFIG=" + kubeconfig)},
		"kubectl", "apply", "-f", f.Name())
	if err != nil {
		require.FailNow(c.t, fmt.Sprintf("Failed to apply manifest: %v -- %s", err, eout))
	}
}

// Run a command ignoring output (though display it while command is running)
func (c *testContext) run(cmdItems ...string) {
	c.runWithConfig(commandConfig{Stdout: os.Stdout, Stderr: os.Stderr, Env: os.Environ()}, cmdItems...)
}

// Run a command ignoring output and exit the test if an error occurs
func (c *testContext) runAndCheckError(cmdItems ...string) {
	c.runWithConfig(commandConfig{Stdout: os.Stdout, Stderr: os.Stderr, Env: os.Environ(), CheckError: true}, cmdItems...)
}

// Run a command ignoring output allowing configuration of stdout, stderr, dir, env, and whether or not to exit on error
func (c *testContext) runWithConfig(config commandConfig, cmdItems ...string) {
	c.t.Helper()
	cmd := exec.Command(cmdItems[0], cmdItems[1:]...)
	cmd.Dir = config.Dir
	cmd.Stdout = config.Stdout
	cmd.Stderr = config.Stderr
	cmd.Env = config.Env
	err := cmd.Run()
	if config.CheckError {
		if err != nil {
			log.Errorf("Run error: %v", err)
		}
		require.NoError(c.t, err)
	}
}

// Run a command capturing stdout and stderr separately
func (c *testContext) runCollectingOutput(cmdItems ...string) ([]byte, []byte, error) {
	return c.runCollectingOutputWithConfig(commandConfig{Env: os.Environ()}, cmdItems...)
}

// Run a command capturing stdout and stderr separately allowing configuration of dir and env
func (c *testContext) runCollectingOutputWithConfig(config commandConfig, cmdItems ...string) ([]byte, []byte, error) {
	cmd := exec.Command(cmdItems[0], cmdItems[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Dir = config.Dir
	cmd.Env = config.Env
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// Make an ssh call
func (c *testContext) sshCall(ip, port, cmd string) ([]byte, []byte, error) {
	return c.runCollectingOutput("ssh", "-i", filepath.Join(c.tmpDir, "cluster-key"), "-l", "root",
		"-o", "UserKnownHostsFile /dev/null", "-o", "StrictHostKeyChecking=no", "-p", port, ip, cmd)
}

// Make an ssh call and fail if it errors
func (c *testContext) makeSSHCallAndCheckError(ip, port, cmd string) {
	c.runAndCheckError("ssh", "-i", filepath.Join(c.tmpDir, "cluster-key"), "-l", "root",
		"-o", "UserKnownHostsFile /dev/null", "-o", "StrictHostKeyChecking=no", "-p", port, ip, cmd)
}

// Make an ssh call and fail if it errors after "n" retries
func (c *testContext) makeSSHCallWithRetries(ip, port, cmd string, retryCount int) {
	for ; retryCount > 0; retryCount-- {
		out, eout, err := c.sshCall(ip, port, cmd)
		if err == nil {
			log.Infof("Call failed: %s, %s, %v", out, eout, err)
			return
		}
	}
}

// Check that a specified number of a resource type is running
func (c *testContext) ensureCount(itemType string, count int, kubeconfigPath string) {
	for retryCount := 1; retryCount <= 30; retryCount++ {
		cmdItems := []string{"kubectl", "get", itemType, "--all-namespaces", "--no-headers=true"}
		cmdResults, eout, err := c.runCollectingOutputWithConfig(commandConfig{Env: env("KUBECONFIG=" + kubeconfigPath)}, cmdItems...)
		if string(eout) != "" {
			log.Infof("EOUT: %s, ERR: %v", eout, err)
		}
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
func (c *testContext) ensureRunning(itemType, kubeconfigPath string) {
	cmdItems := []string{"kubectl", "get", itemType, "--all-namespaces", "-o",
		`jsonpath={range .items[*]}{"\n"}{@.metadata.name}:{@.spec.unschedulable}:{range @.status.conditions[*]}{@.type}={@.status};{end}{end}`}

	for retryCount := 1; retryCount <= 30; retryCount++ {
		allReady := true
		cmdResults, _, _ := c.runCollectingOutputWithConfig(commandConfig{Env: env("KUBECONFIG=" + kubeconfigPath)}, cmdItems...)
		strs := strings.Split(string(cmdResults), "\n")
		for _, str := range strs {
			if str != "" && (!strings.Contains(str, "Ready=True") || strings.Contains(str, ":true:")) {
				log.Infof("Waiting for: %s", str)
				allReady = false
			}
		}
		if allReady {
			return
		}
		log.Infof("Waiting for all %s to be running, retry: %d...", itemType, retryCount)
		if retryCount > 6 {
			c.runWithConfig(commandConfig{Env: env("KUBECONFIG=" + kubeconfigPath), Stdout: os.Stdout, Stderr: os.Stderr},
				"kubectl", "get", "nodes", "-A", "-o", "yaml")
		}
		time.Sleep(30 * time.Second)
	}
	require.FailNow(c.t, fmt.Sprintf("Not all %s are running...", itemType))
}

// Check that not all instances of a specified resource type are ready
func (c *testContext) ensureAllStoppedRunning(itemType, kubeconfigPath string) {
	cmdItems := []string{"kubectl", "get", itemType, "--all-namespaces", "-o",
		`jsonpath={range .items[*]}{"\n"}{@.metadata.name}:{@.spec.unschedulable}:{range @.status.conditions[*]}{@.type}={@.status};{end}{end}`}

	unreadySeen := ""
	for retryCount := 1; retryCount <= 100; retryCount++ {
		cmdResults, _, err := c.runCollectingOutputWithConfig(commandConfig{Env: env("KUBECONFIG=" + kubeconfigPath)}, cmdItems...)
		if err != nil {
			time.Sleep(time.Second * 5)
			continue
		}
		strs := strings.Split(string(cmdResults), "\n")
		for _, str := range strs {
			nameAndConditions := strings.Split(str, ":")
			log.Infof("Response: %s", str)
			if len(nameAndConditions) < 3 { // name, unschedulable, conditions
				continue
			}
			if str != "" && nameAndConditions[0] != unreadySeen &&
				(!strings.Contains(nameAndConditions[2], "Ready=True") || nameAndConditions[1] == "true") {
				log.Infof("Machine %s stopped...", nameAndConditions[0])
				if unreadySeen != "" {
					return
				}
				unreadySeen = nameAndConditions[0]
			}
		}
		if retryCount%10 == 0 {
			log.Infof("Waiting for all %s to have stopped running, retry: %d...", itemType, retryCount)
		}
		time.Sleep(5 * time.Second)
	}
	require.FailNow(c.t, fmt.Sprintf("Some %s did not stop running...", itemType))
}

// Set up a provider-friendly environment
func (c *testContext) getProviderEnvironment() []string {
	tag, _, err := c.runCollectingOutput(filepath.Join(c.testDir, "../../../tools/image-tag"))
	require.NoError(c.t, err)
	return env("NAMESPACE=test", "CONTROL_PLANE_MACHINE_COUNT=2", "WORKER_MACHINE_COUNT=0", "HOME="+c.tmpDir,
		"CONTROL_PLANE_ENDPOINT=172.17.0.2:6443",
		"EXISTINGINFRA_CONTROLLER_IMAGE=docker.io/weaveworks/cluster-api-existinginfra-controller:"+string(tag))
}

// Create a load balancer so that we can repave machines
func (c *testContext) ConfigureHAProxy(loadBalancerAddress string, loadBalancerSSHPort int) {
	log.Info("Configuring H/A proxy...")
	ctx := context.TODO()
	keyFile := filepath.Join(c.tmpDir, "cluster-key")
	sshClient, err := ssh.NewClient(ssh.ClientParams{
		User:           "root",
		Host:           loadBalancerAddress,
		Port:           uint16(loadBalancerSSHPort),
		PrivateKeyPath: keyFile,
	})
	require.NoError(c.t, err)
	defer sshClient.Close()
	installer, err := capeios.Identify(ctx, sshClient)
	require.NoError(c.t, err)
	runner := &sudo.Runner{Runner: sshClient}
	cfg, err := envcfg.GetEnvSpecificConfig(ctx, installer.PkgType, "default", "", runner)
	require.NoError(c.t, err)
	// resources
	baseResource := recipe.BuildBasePlan(installer.PkgType)
	dockerConfigResource, err := buildDockerConfigResource(c)
	require.NoError(c.t, err)
	criResource := recipe.BuildCRIPlan(
		ctx,
		&existinginfrav1.ContainerRuntime{
			Kind:    "docker",
			Package: "docker-ce",
			Version: "19.03.8",
		},
		cfg,
		installer.PkgType)
	ips := []string{"172.17.0.3", "172.17.0.4"}
	haConfigResource := &resource.File{
		Content:     generateHAConfiguration(ips),
		Destination: "/tmp/haproxy.cfg",
	}
	haproxyResource := &resource.Run{
		Script:     object.String("mkdir /tmp/haproxy && docker run --detach --name haproxy -v /tmp/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg -v /tmp/haproxy:/var/lib/haproxy -p 6443:6443 haproxy"),
		UndoScript: object.String("docker rm haproxy || true"),
	}
	lbPlanBuilder := plan.NewBuilder()
	lbPlanBuilder.AddResource("install:base", baseResource)
	lbPlanBuilder.AddResource("install:docker-repo-config", dockerConfigResource,
		plan.DependOn("install:base"))
	lbPlanBuilder.AddResource("install:cri", criResource, plan.DependOn("install:docker-repo-config"))
	lbPlanBuilder.AddResource("install:ha-config", haConfigResource, plan.DependOn("install:cri"))
	lbPlanBuilder.AddResource("install:haproxy", haproxyResource, plan.DependOn("install:ha-config"))

	lbPlan, err := lbPlanBuilder.Plan()
	require.NoError(c.t, err)
	err = lbPlan.Undo(ctx, runner, plan.EmptyState)
	require.NoError(c.t, err)
	_, err = lbPlan.Apply(ctx, runner, plan.EmptyDiff())
	require.NoError(c.t, err)
}

func generateHAConfiguration(clusterIPs []string) string {
	var str strings.Builder
	str.WriteString(haproxyTemplate)

	for idx, IP := range clusterIPs {
		str.WriteString(fmt.Sprintf("    server master-%d %s:6443 check\n", idx, IP))
	}

	return str.String()
}

func buildDockerConfigResource(c *testContext) (plan.Resource, error) {
	manifest, eout, err := c.runCollectingOutputWithConfig(
		commandConfig{
			Env:    c.getProviderEnvironment(),
			Stdout: os.Stdout,
			Stderr: os.Stderr},
		filepath.Join(c.tmpDir, "clusterctl"), "config", "cluster", "test-cluster", "--kubernetes-version", "1.17.5", "-n", "test")
	if err != nil {
		log.Infof("E: %v, OUT: %s", err, eout)
	}
	require.NoError(c.t, err)

	b := plan.NewBuilder()
	_, eic, err := specs.ParseCluster(ioutil.NopCloser(bytes.NewReader(manifest)))
	require.NoError(c.t, err)
	filespecs := &eic.Spec.OS.Files
	for idx, srcspec := range *filespecs {
		fileResource := &resource.File{Destination: srcspec.Destination, Content: srcspec.Source.Contents}
		b.AddResource(fmt.Sprintf("install-config-file-%d", idx), fileResource)
	}
	p, err := b.Plan()
	if err != nil {
		return nil, err
	}
	return &p, nil
}

const haproxyTemplate = `#---------------------------------------------------------------------
# HAProxy configuration file for the Kubernetes API service.
#
# See the full configuration options online at:
#
#   http://haproxy.1wt.eu/download/1.4/doc/configuration.txt
#
#---------------------------------------------------------------------

#---------------------------------------------------------------------
# Global settings
#---------------------------------------------------------------------
global
    log         127.0.0.1 local2

    pidfile     /var/run/haproxy.pid
    maxconn     4000
    daemon

    # turn on stats unix socket
    stats socket /var/lib/haproxy/stats

#---------------------------------------------------------------------
# common defaults that all the 'listen' and 'backend' sections will
# use if not designated in their block
#---------------------------------------------------------------------
defaults
    mode                    http
    log                     global
    option                  httplog
    option                  dontlognull
    option http-server-close
    option forwardfor       except 127.0.0.0/8
    option                  redispatch
    retries                 3
    timeout http-request    10s
    timeout queue           1m
    timeout connect         10s
    timeout client          1m
    timeout server          1m
    timeout http-keep-alive 10s
    timeout check           10s
    maxconn                 3000

#---------------------------------------------------------------------
# OPTIONAL - stats UI that allows you to see which masters have joined
#            the LB roundrobin
#---------------------------------------------------------------------
frontend stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 10s
    stats admin if LOCALHOST

#---------------------------------------------------------------------
# KubeAPI frontend which proxys to the master nodes
#---------------------------------------------------------------------
frontend kubernetes
    bind *:6443
    default_backend             kubernetes
    mode tcp
    option tcplog

backend kubernetes
    balance     roundrobin
    mode tcp
    option tcp-check
    default-server inter 10s downinter 5s rise 2 fall 2 slowstart 60s maxconn 250 maxqueue 256 weight 100
`
