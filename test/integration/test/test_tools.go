package test

// A set of utilities to help with constructing integration tests for cluster-api-existinginfra.
// The "context" struct contains useful parameters and has a set of methods that perform generic
// test operations.

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// Holds useful parameters for integration tests. "testDir" is the directory containing the running test; "tmpDir" is
// a temporary directory that can be used as a test base.
type context struct {
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

// getContext returns a "context" object containing all the information needed to perform most
// test tasks. Methods on the context object can be used to implement integration tests and manage
// temporary directories, git repositories, and clusters.
func getContext(t *testing.T) *context {
	tmpDir, err := ioutil.TempDir("", "tmp_dir")
	require.NoError(t, err)
	return getContextFrom(t, tmpDir)
}

// Creates a context, doing the following:
// - creating a temporary directory (tmpDir) which will be established as HOME (for user-relative configuration)
// - installing kind
// - installing clusterctl
// - cleaning up any existing kind clusters
// - creating a new kind cluster
func getContextFrom(t *testing.T, tmpDir string) *context {
	log.Infof("Using temporary directory: %s\n", tmpDir)

	c := &context{
		t:       t,
		tmpDir:  tmpDir,
		testDir: getTestDir(t),
	}
	log.Info("Installing kind...")
	c.runWithConfig(commandConfig{CheckError: true, Env: env("GO111MODULE=on", "GOPATH="+tmpDir, "HOME="+tmpDir, "CGOENABLED=0"), Stdout: os.Stdout, Stderr: os.Stderr},
		"go", "get", "sigs.k8s.io/kind@v0.9.0")
	log.Info("Installing clusterctl...")
	for {
		fetchCmd := fmt.Sprintf("curl -L https://github.com/kubernetes-sigs/cluster-api/releases/download/v0.3.8/clusterctl-%s-%s -o %s/clusterctl && chmod a+x %s/clusterctl",
			c.getOS(), c.getArch(), c.tmpDir, c.tmpDir)
		c.runAndCheckError("sh", "-c", fetchCmd)
		_, _, err := c.runCollectingOutput(filepath.Join(c.tmpDir, "clusterctl"), "version")
		if err == nil {
			break
		}
	}
	err := os.Setenv("HOME", c.tmpDir)
	require.NoError(c.t, err)
	kindCmd := filepath.Join(c.tmpDir, "bin", "kind")
	c.run(kindCmd, "delete", "cluster")
	c.runAndCheckError(kindCmd, "create", "cluster")
	return c
}

// Clean everything up; remove temp directory and delete kind cluster
func (c *context) cleanup() {
	log.Infof("About to remove temp dir: '%s'", c.tmpDir)
	os.RemoveAll(c.tmpDir)
	c.runAndCheckError(filepath.Join(c.tmpDir, "bin", "kind"), "delete", "cluster")
}

// Determine the current OS
func (c *context) getOS() string {
	osbytes, _, err := c.runCollectingOutput("uname", "-s")
	require.NoError(c.t, err)
	os := string(osbytes)
	if strings.HasPrefix(os, "Linux") {
		return "linux"
	} else if strings.HasPrefix(os, "Darwin") {
		return "darwin"
	} else {
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

func (c *context) getArch() string {
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

// Apply a manifest available inline
func (c *context) applyLocalManifest(manifest string) {
	f, err := ioutil.TempFile(c.tmpDir, "---manifest--*---")
	require.NoError(c.t, err)
	defer os.Remove(f.Name())
	err = ioutil.WriteFile(f.Name(), []byte(manifest), 0600)
	require.NoError(c.t, err)
	c.runAndCheckError("kubectl", "apply", "-f", f.Name())
}

// Run a command ignoring output (though display it while command is running)
func (c *context) run(cmdItems ...string) {
	c.runWithConfig(commandConfig{Stdout: os.Stdout, Stderr: os.Stderr}, cmdItems...)
}

// Run a command ignoring output and exit the test if an error occurs
func (c *context) runAndCheckError(cmdItems ...string) {
	c.runWithConfig(commandConfig{Stdout: os.Stdout, Stderr: os.Stderr, CheckError: true}, cmdItems...)
}

// Run a command ignoring output allowing configuration of stdout, stderr, dir, env, and whether or not to exit on error
func (c *context) runWithConfig(config commandConfig, cmdItems ...string) {
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
func (c *context) runCollectingOutput(cmdItems ...string) ([]byte, []byte, error) {
	return c.runCollectingOutputWithConfig(commandConfig{}, cmdItems...)
}

// Run a command capturing stdout and stderr separately allowing configuration of dir and env
func (c *context) runCollectingOutputWithConfig(config commandConfig, cmdItems ...string) ([]byte, []byte, error) {
	cmd := exec.Command(cmdItems[0], cmdItems[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Dir = config.Dir
	cmd.Env = config.Env
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// Determine if the temporary directory exists
func tempDirExists(c *context) bool {
	_, err := os.Stat(c.tmpDir)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		log.Errorf("Got error attempting to stat temp directory")
		return false
	}
	return true
}
