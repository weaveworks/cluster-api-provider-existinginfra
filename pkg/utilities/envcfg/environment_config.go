package envcfg

import (
	"context"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/resource"
)

type EnvSpecificConfig struct {
	ConntrackMax          int32
	UseIPTables           bool
	IgnorePreflightErrors []string
	SELinuxInstalled      bool
	SetSELinuxPermissive  bool
	DisableSwap           bool
	LockYUMPkgs           bool
	Namespace             string
	HostnameOverride      string
}

const (
	FC_bridge_nf_call_iptables = `FileContent--proc-sys-net-bridge-bridge-nf-call-iptables`
	Swap                       = `Swap`
	SystemVerification         = `SystemVerification`
)

func getHostnameOverride(ctx context.Context, cloudProvider string, runner plan.Runner) (string, error) {
	switch cloudProvider {
	case "aws":
		return runner.RunCommand(ctx, "curl -s http://169.254.169.254/latest/meta-data/local-hostname 2>/dev/null", nil)
	default:
		return "", nil
	}
}

func GetEnvSpecificConfig(ctx context.Context, pkgType resource.PkgType, namespace string, cloudProvider string, r plan.Runner) (*EnvSpecificConfig, error) {
	osres, err := resource.NewOS(ctx, r)
	if err != nil {
		return nil, errors.Wrap(err, "NewOS")
	}
	seLinuxStatus, seLinuxMode, err := osres.GetSELinuxStatus(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "GetSELinuxStatus")
	}

	inContainerVM, err := osres.IsOSInContainerVM(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "IsOSInContainerVM")
	}

	hostnameOverride, err := getHostnameOverride(ctx, cloudProvider, r)
	if err != nil {
		return nil, err
	}

	ignorePreflightErrors := []string{}
	if inContainerVM {
		ignorePreflightErrors = []string{
			FC_bridge_nf_call_iptables,
			Swap,
			SystemVerification,
		}
	}

	log.Debug("Current SELinuxMode: ", seLinuxMode)
	config := &EnvSpecificConfig{
		ConntrackMax:          0,
		UseIPTables:           !inContainerVM,
		SELinuxInstalled:      seLinuxStatus.IsInstalled(),
		SetSELinuxPermissive:  !inContainerVM && seLinuxStatus.IsInstalled() && !seLinuxMode.IsDisabled(), // if selinux is installed and not disabled, set it to permissive
		LockYUMPkgs:           pkgType == resource.PkgTypeRPM,
		DisableSwap:           !inContainerVM,
		IgnorePreflightErrors: ignorePreflightErrors,
		Namespace:             namespace,
		HostnameOverride:      hostnameOverride,
	}
	log.WithField("config", config).Debug("the following env-specific configuration will be used")
	return config, nil
}
