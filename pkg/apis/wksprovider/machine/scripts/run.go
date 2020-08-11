package scripts

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

// runner is something that can run a command somewhere.
//
// N.B.: this interface is meant to match pkg/plan.Runner, and is used in order
// to decouple packages.
type runner interface {
	// RunCommand runs the provided command in a shell.
	// cmd can be more than one single command, it can be a full shell script.
	RunCommand(cmd string, stdin io.Reader) (stdouterr string, err error)
}

func WriteFile(content []byte, dstPath string, perm os.FileMode, runner runner) error {
	input := bytes.NewReader(content)
	cmd := fmt.Sprintf("mkdir -pv $(dirname %q) && sed -n 'w %s' && chmod 0%o %q", dstPath, dstPath, perm, dstPath)
	_, err := runner.RunCommand(cmd, input)
	return err
}
