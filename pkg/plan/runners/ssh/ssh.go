package ssh

import (
	"fmt"
	"io"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan"
	sshutil "github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/ssh"
	"github.com/weaveworks/common/localcmd"
	"golang.org/x/crypto/ssh"
)

// ClientParams groups inputs to build a client object.
type ClientParams struct {
	User           string
	Host           string
	Port           uint16
	PrivateKeyPath string
	PrivateKey     []byte
	PrintOutputs   bool
}

// Client is a higher-level abstraction around the standard API's SSH
// configuration, client and connection to the remote machine.
type Client struct {
	client       *ssh.Client
	printOutputs bool
}

var _ plan.Runner = &Client{}

const tcp = "tcp"

// NewClient instantiates a new SSH Client object.
// N.B.: provide either the key (privateKey) or its path (privateKeyPath).
func NewClient(params ClientParams) (*Client, error) {
	log.WithFields(log.Fields{"user": params.User, "host": params.Host, "port": params.Port, "privateKeyPath": params.PrivateKeyPath, "printOutputs": params.PrintOutputs}).Debugf("creating SSH client")
	signer, err := sshutil.SignerFromPrivateKey(params.PrivateKeyPath, params.PrivateKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read private key from \"%s\"", params.PrivateKeyPath)
	}
	hostPublicKey, err := sshutil.HostPublicKey(params.Host)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read host %s's public key", params.Host)
	}
	config := &ssh.ClientConfig{
		User: params.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: sshutil.HostKeyCallback(hostPublicKey),
	}
	hostPort := fmt.Sprintf("%s:%d", params.Host, params.Port)
	client, err := ssh.Dial(tcp, hostPort, config)
	if err != nil {
		return nil, errors.Wrapf(err,
			"failed to connect to %s using private key %s as user %s, please verify connection manually", hostPort, params.PrivateKeyPath, config.User)
	}
	return &Client{
		client:       client,
		printOutputs: params.PrintOutputs,
	}, nil
}

// RunCommand executes the provided command on the remote machine configured in
// this Client object. A new Session is created for each call to RunCommand.
// A Client supports multiple interactive sessions.
func (c *Client) RunCommand(command string, stdin io.Reader) (string, error) {
	log.Debugf("running command: %s", command)
	return c.handleSessionIO(func(session *ssh.Session) error {
		session.Stdin = stdin
		return session.Start(command)
	})
}

// Handle output and command completion for a remote shell
func (c *Client) handleSessionIO(action func(*ssh.Session) error) (string, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return "", errors.Wrap(err, "failed to create new SSH session")
	}
	defer session.Close()
	// Write stdout and stderr to both this process' stdout and stderr, and
	// buffers, for later re-use.
	stdOutPipe, err := session.StdoutPipe()
	if err != nil {
		return "", errors.Wrap(err, "failed to get pipe to standard output")
	}
	stdErrPipe, err := session.StderrPipe()
	if err != nil {
		return "", errors.Wrap(err, "failed to get pipe to standard error")
	}

	err = action(session)
	// Don't respond to err until output complete

	stdOut, stdErr, outputErr := localcmd.ReadAllOutput(stdOutPipe, stdErrPipe)

	// Now we can return the error
	if err != nil {
		return stdOut + stdErr, errors.Wrap(err, "failed while remote executing")
	}

	if err := session.Wait(); err != nil {
		if err, ok := err.(*ssh.ExitError); ok {
			return stdOut + stdErr, &plan.RunError{ExitCode: err.ExitStatus()}
		}
		return stdOut + stdErr, errors.Wrap(err, "failed while waiting for end of remote execution")
	}

	if outputErr != nil {
		return stdOut + stdErr, errors.Wrap(outputErr, "reading from ssh command")
	}
	return stdOut + stdErr, outputErr
}

// Close closes this high-level Client's underlying SSH connection.
func (c *Client) Close() error {
	return c.client.Close()
}
