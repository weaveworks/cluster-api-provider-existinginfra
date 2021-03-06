package recipe

import (
	"context"
	"fmt"
	"sort"

	log "github.com/sirupsen/logrus"
	existinginfrav1 "github.com/weaveworks/cluster-api-provider-existinginfra/apis/cluster.weave.works/v1alpha3"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/flavors/eksd"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/resource"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/envcfg"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/object"
)

const (
	// PlanKey for storing plans as annotations on Nodes
	PlanKey string = "wks.weave.works/node-plan"
)

// BuildBasePlan creates a plan for installing the base building blocks for the node
func BuildBasePlan(pkgType resource.PkgType) plan.Resource {
	b := plan.NewBuilder()

	switch pkgType {
	case resource.PkgTypeRPM, resource.PkgTypeRHEL:
		// Package manager features
		b.AddResource("install:yum-utils", &resource.RPM{Name: "yum-utils"})
		b.AddResource("install:yum-versionlock", &resource.RPM{Name: "yum-plugin-versionlock"})

		// Device Mapper
		b.AddResource("install:device-mapper-persistent-data", &resource.RPM{Name: "device-mapper-persistent-data"})
		b.AddResource("install:lvm2", &resource.RPM{Name: "lvm2"})

	case resource.PkgTypeDeb:
		// Package manager features
		b.AddResource("install:gnupg", &resource.Deb{Name: "gnupg"})
		// TODO(michal): Enable locking

		// Device Mapper
		b.AddResource("install:thin-provisioning-tools", &resource.Deb{Name: "thin-provisioning-tools"})
		b.AddResource("install:lvm2", &resource.Deb{Name: "lvm2"})
	}

	p, err := b.Plan()
	p.SetUndoCondition(func(_ plan.Runner, _ plan.State) bool { return false })
	if err != nil {
		log.Fatalf("%v", err)
	}
	return &p
}

// BuildConfigPlan creates a plan for handling the configuration files
func BuildConfigPlan(files []*resource.File) plan.Resource {
	b := plan.NewBuilder()
	for idx, file := range files {
		b.AddResource(fmt.Sprintf("install:config-file-%d", idx), file)
	}
	p, err := b.Plan()
	if err != nil {
		log.Fatalf("%v", err)
	}
	return &p
}

// BuildConfigMapPlan creates a plan to handle config maps
func BuildConfigMapPlan(manifests map[string][]byte, namespace string) plan.Resource {
	b := plan.NewBuilder()
	for name, manifest := range manifests {
		remoteName := fmt.Sprintf("config-map-%s", name)
		b.AddResource("install:"+remoteName, &resource.KubectlApply{Filename: object.String(remoteName), Manifest: manifest, Namespace: object.String(namespace)})
	}
	p, err := b.Plan()
	if err != nil {
		log.Fatalf("%v", err)
	}
	return &p
}

// BuildCNIPlan creates a sub-plan to install the CNI plugin.
func BuildCNIPlan(cni string, manifests [][]byte) plan.Resource {
	b := plan.NewBuilder()

	b.AddResource(
		"install-cni:apply-manifests",
		&resource.KubectlApply{Manifest: manifests[0], Filename: object.String(cni + ".yaml")},
	)
	if len(manifests) == 2 {
		b.AddResource(
			"install-cni:apply-manifests-ds",
			&resource.KubectlApply{Manifest: manifests[1], Filename: object.String(cni + "-daemon-set" + ".yaml")},
			plan.DependOn("install-cni:apply-manifests"))
	}

	p, err := b.Plan()
	if err != nil {
		log.Fatalf("%v", err)
	}
	return &p
}

// BuildCRIPlan creates a plan for installing a CRI.  Currently, Docker is the only supported CRI
func BuildCRIPlan(ctx context.Context, criSpec *existinginfrav1.ContainerRuntime, cfg *envcfg.EnvSpecificConfig, pkgType resource.PkgType) plan.Resource {
	b := plan.NewBuilder()

	if criSpec.Kind != "docker" {
		log.Fatalf("Unknown CRI - %s", criSpec.Kind)
	}

	IsDockerOnCentOS := false

	// Docker runtime
	switch pkgType {
	case resource.PkgTypeRHEL:
		b.AddResource("install:container-selinux",
			&resource.Run{
				Script:     object.String("yum install -y http://mirror.centos.org/centos/7/extras/x86_64/Packages/container-selinux-2.107-1.el7_6.noarch.rpm || true"),
				UndoScript: object.String("yum remove -y container-selinux || true")})

		b.AddResource("install:docker",
			&resource.RPM{Name: criSpec.Package, Version: criSpec.Version},
			plan.DependOn("install:container-selinux"))

		// SELinux will be here along with docker and containerd-selinux packages
		IsDockerOnCentOS = true

	case resource.PkgTypeRPM:
		b.AddResource("install:docker",
			&resource.RPM{Name: criSpec.Package, Version: criSpec.Version})

		// SELinux will be here along with docker and containerd-selinux packages
		IsDockerOnCentOS = true
	case resource.PkgTypeDeb:
		// TODO(michal): Use the official docker.com repo
		b.AddResource("install:docker", &resource.Deb{Name: "docker.io"})
	}

	if cfg.LockYUMPkgs {
		b.AddResource(
			"lock-package:docker",
			&resource.Run{
				Script: object.String("yum versionlock add docker-ce"),
				// If we never installed yum-plugin-versionlock or docker, this should not fail
				UndoScript: object.String("yum versionlock delete docker-ce || true")},
			plan.DependOn("install:docker"))
	}

	// this is a special case: if SELinux is not there on RH, CentOS Linux family
	// installing Docker will also installing SELinux
	// then we set SELinux mode to be permissive right after the docker installation step
	if IsDockerOnCentOS && cfg.SetSELinuxPermissive {
		b.AddResource(
			"selinux:permissive",
			&resource.Run{
				Script: object.String("setenforce 0 && sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config"),
				// sometime, SELinux not installed yet so || true to ignore the error
				UndoScript: object.String("setenforce 1 && sed -i 's/^SELINUX=permissive$/SELINUX=enforcing/' /etc/selinux/config || true"),
			},
			plan.DependOn("install:docker"))
	}

	b.AddResource(
		"systemd:daemon-reload",
		&resource.Run{Script: object.String("systemctl daemon-reload")},
		plan.DependOn("install:docker"),
	)
	b.AddResource(
		"service-init:docker-service",
		&resource.Service{Name: "docker", Status: "active", Enabled: true},
		plan.DependOn("systemd:daemon-reload"))

	p, err := b.Plan()

	p.SetUndoCondition(func(r plan.Runner, _ plan.State) bool {
		type AwareChanger interface {
			WouldChangeState(ctx context.Context, r plan.Runner) (bool, error)
		}
		chg, err := p.GetResource("install:docker").(AwareChanger).WouldChangeState(ctx, r)
		return chg || (err != nil)
	})
	if err != nil {
		log.Fatalf("%v", err)
	}
	return &p
}

// BinInstaller creates a function to install binaries based on package type and cluster flavors
func BinInstaller(pkgType resource.PkgType, f *eksd.EKSD) (func(string, string) plan.Resource, error) {
	if f != nil {
		log.Debugf("Using flavor %+v", f)
		return func(binName, version string) plan.Resource {
			// TODO (Mark) logic for the architecture
			binURL, sha256, err := f.KubeBinURL(binName)
			if err != nil {
				log.Fatalf("%v", err)
				return nil
			}
			binPath := "/usr/bin/" + binName
			return &resource.Run{
				Script:     object.String(fmt.Sprintf("curl -o %s %s && openssl dgst -sha256 %s | grep \"%s\" > /dev/null && chmod 755 %s", binPath, binURL, binPath, sha256, binPath)),
				UndoScript: object.String(fmt.Sprintf("pkill --uid 0 %s && rm %s || true", binName, binPath))}
		}, nil
	}
	if pkgType == resource.PkgTypeDeb {
		return func(binName, version string) plan.Resource {
			return &resource.Deb{Name: binName, Suffix: "=" + version + "-00"}
		}, nil
	}
	return func(binName, version string) plan.Resource {
		return &resource.RPM{Name: binName, Version: version, DisableExcludes: "kubernetes"}
	}, nil

}

// BuildK8SPlan creates a plan for running kubernetes on a node
func BuildK8SPlan(kubernetesVersion string, kubeletNodeIP string, seLinuxInstalled, setSELinuxPermissive, disableSwap, lockYUMPkgs bool, pkgType resource.PkgType, cloudProvider string, extraArgs map[string]string, binInstaller func(string, string) plan.Resource, flavor *eksd.EKSD) plan.Resource {
	b := plan.NewBuilder()
	// Kubernetes repos
	switch pkgType {
	case resource.PkgTypeRPM, resource.PkgTypeRHEL:
		// do nothing
	case resource.PkgTypeDeb:
		// XXX: Workaround for https://github.com/weaveworks/wksctl/issues/654 : *.gpg is a binary format, and currently wks is unable to handle
		// binary files in the configuration configmap. Therefore, I needed to supply the *.gpg contents base64-encoded.
		// In a world without that bug, one could just use the "!!binary"" YAML format in the configmap and store the *.gpg there directly.
		b.AddResource("configure:kubernetes-repo-key", &resource.Run{
			Script: object.String("base64 -d /tmp/cloud-google-com.gpg.b64 > /etc/apt/trusted.gpg.d/cloud-google-com.gpg"),
		})

		repoLine := "deb https://apt.kubernetes.io/ kubernetes-xenial main"
		repoFile := "/etc/apt/sources.list.d/wks-google.list"
		sedExpr := fmt.Sprintf(`\!%s!d`, repoLine) // same as '/%s/d' but allows '/' in %s
		b.AddResource("configure:kubernetes-repo", &resource.Run{
			Script:     object.String(fmt.Sprintf("echo %q | tee -a %q", repoLine, repoFile)),
			UndoScript: object.String(fmt.Sprintf(`test ! -f %q || sed -i '%s' %q`, repoFile, sedExpr, repoFile)),
		}, plan.DependOn("configure:kubernetes-repo-key"))
	}

	// If SELinux is already installed and we need to set SELinux to permissive mode, do it
	if seLinuxInstalled && setSELinuxPermissive {
		b.AddResource(
			"selinux:permissive",
			&resource.Run{
				Script:     object.String("setenforce 0 && sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config"),
				UndoScript: object.String("setenforce 1 && sed -i 's/^SELINUX=permissive$/SELINUX=enforcing/' /etc/selinux/config || true"),
			})
	}

	// Install k8s packages
	switch pkgType {
	case resource.PkgTypeRPM, resource.PkgTypeRHEL:
		if flavor != nil {
			b.AddResource("install:kubelet-package", &resource.RPM{Name: "kubelet", Version: kubernetesVersion, DisableExcludes: "kubernetes"})
			b.AddResource(
				"cleanup:kubelet",
				&resource.Run{Script: object.String("pkill kubelet | true")},
				plan.DependOn("install:kubelet-package"))
			b.AddResource("install:kubelet", binInstaller("kubelet", kubernetesVersion), plan.DependOn("cleanup:kubelet"))
		} else {
			b.AddResource("install:kubelet", binInstaller("kubelet", kubernetesVersion))
		}
		b.AddResource("install:kubectl", binInstaller("kubectl", kubernetesVersion))
		b.AddResource("install:kubeadm",
			binInstaller("kubeadm", kubernetesVersion),
			plan.DependOn("install:kubectl"),
			plan.DependOn("install:kubelet"),
		)
	case resource.PkgTypeDeb:
		// TODO(michal): Install the newest release version by default instead of hardcoding "-00".
		if flavor != nil {
			b.AddResource("install:kubelet-package", &resource.Deb{Name: "kubelet", Suffix: "=" + kubernetesVersion + "-00"},
				plan.DependOn("configure:kubernetes-repo"))
			b.AddResource(
				"cleanup:kubelet",
				&resource.Run{Script: object.String("pkill kubelet | true")},
				plan.DependOn("install:kubelet-package"))
			b.AddResource("install:kubelet", binInstaller("kubelet", kubernetesVersion), plan.DependOn("cleanup:kubelet"))
		} else {
			b.AddResource("install:kubelet", binInstaller("kubelet", kubernetesVersion), plan.DependOn("configure:kubernetes-repo"))
		}
		b.AddResource("install:kubeadm", binInstaller("kubeadm", kubernetesVersion), plan.DependOn("configure:kubernetes-repo"), plan.DependOn("install:kubelet"))
		b.AddResource("install:kubectl", binInstaller("kubectl", kubernetesVersion), plan.DependOn("configure:kubernetes-repo"))

	}
	if lockYUMPkgs {
		b.AddResource(
			"lock-package:kubernetes",
			&resource.Run{
				Script: object.String("yum versionlock add 'kube*'"),
				// If we never installed yum-plugin-versionlock or kubernetes, this should not fail
				UndoScript: object.String("yum versionlock delete 'kube*' || true")},
			plan.DependOn("install:kubectl"),
		)
	}
	b.AddResource(
		"create-dir:kubelet.service.d",
		&resource.Dir{Path: object.String("/etc/systemd/system/kubelet.service.d")},
	)
	b.AddResource(
		"install:kubeadm-conf",
		&resource.File{Content: `# Note: This dropin only works with kubeadm and kubelet v1.11+
[Service]
Environment="KUBELET_KUBECONFIG_ARGS=--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf"
Environment="KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml"
# This is a file that "kubeadm init" and "kubeadm join" generates at runtime, populating the KUBELET_KUBEADM_ARGS variable dynamically
EnvironmentFile=-/var/lib/kubelet/kubeadm-flags.env
# This is a file that the user can use for overrides of the kubelet args as a last resort. Preferably, the user should use
# the .NodeRegistration.KubeletExtraArgs object in the configuration files instead. KUBELET_EXTRA_ARGS should be sourced from this file.
EnvironmentFile=-/etc/default/kubelet
ExecStart=
ExecStart=/usr/bin/kubelet $KUBELET_KUBECONFIG_ARGS $KUBELET_CONFIG_ARGS $KUBELET_KUBEADM_ARGS $KUBELET_EXTRA_ARGS`,
			Destination: "/etc/systemd/system/kubelet.service.d/10-kubeadm.conf"},
		plan.DependOn("create-dir:kubelet.service.d"))
	kubeletDeps := []string{"install:kubeadm-conf"}
	processCloudProvider := func(cmdline string) string {
		if cloudProvider != "" {
			log.WithField("cloudProvider", cloudProvider).Debug("using cloud provider")
			return fmt.Sprintf("%s --cloud-provider=%s\n", cmdline, cloudProvider)
		}
		return cmdline + "\n"
	}
	processAdditionalArgs := func(cmdline string) string {
		result := cmdline
		strs := []string{}
		for name, value := range extraArgs {
			strs = append(strs, fmt.Sprintf("--%s='%s'", name, value))
		}
		sort.Strings(strs)
		for _, str := range strs {
			result = fmt.Sprintf("%s %s", result, str)
		}
		return processCloudProvider(result)
	}

	switch pkgType {
	case resource.PkgTypeRPM, resource.PkgTypeRHEL:
		if disableSwap {
			swapDisable := "configure:kubernetes-swap-disable"
			kubeletDeps = append(kubeletDeps, swapDisable)
			b.AddResource(
				swapDisable,
				buildDisableSwapPlan(),
				plan.DependOn("create-dir:kubelet.service.d"))
			kubeletSysconfig := "configure:kubelet-sysconfig"
			b.AddResource(
				kubeletSysconfig,
				&resource.File{
					Content:     processAdditionalArgs(fmt.Sprintf("KUBELET_EXTRA_ARGS=--node-ip=%s", kubeletNodeIP)),
					Destination: "/etc/default/kubelet"},
				plan.DependOn("create-dir:kubelet.service.d", "install:kubelet"))
			kubeletDeps = append(kubeletDeps, kubeletSysconfig)
		} else {
			kubeletSysconfig := "configure:kubelet-sysconfig"
			kubeletDeps = append(kubeletDeps, kubeletSysconfig)
			b.AddResource(
				kubeletSysconfig,
				&resource.File{
					Content:     processAdditionalArgs(fmt.Sprintf("KUBELET_EXTRA_ARGS=--fail-swap-on=false --node-ip=%s", kubeletNodeIP)),
					Destination: "/etc/default/kubelet"},
				plan.DependOn("create-dir:kubelet.service.d", "install:kubelet"))
		}
	case resource.PkgTypeDeb:
		if disableSwap {
			swapDisable := "configure:kubernetes-swap-disable"
			kubeletDeps = append(kubeletDeps, swapDisable)
			b.AddResource(
				swapDisable,
				buildDisableSwapPlan(),
				plan.DependOn("create-dir:kubelet.service.d"))
			kubeletDefault := "configure:kubelet-default"
			kubeletDeps = append(kubeletDeps, kubeletDefault)
			b.AddResource(
				kubeletDefault,
				&resource.File{
					Content:     processAdditionalArgs(fmt.Sprintf("KUBELET_EXTRA_ARGS=--node-ip=%s", kubeletNodeIP)),
					Destination: "/etc/default/kubelet"},
				plan.DependOn("create-dir:kubelet.service.d", "install:kubelet"))
		} else {
			kubeletDefault := "configure:kubelet-default"
			kubeletDeps = append(kubeletDeps, kubeletDefault)
			b.AddResource(
				kubeletDefault,
				&resource.File{
					Content:     processAdditionalArgs(fmt.Sprintf("KUBELET_EXTRA_ARGS=--fail-swap-on=false --node-ip=%s", kubeletNodeIP)),
					Destination: "/etc/default/kubelet"},
				plan.DependOn("create-dir:kubelet.service.d", "install:kubelet"))
		}
	}
	b.AddResource(
		"systemd:daemon-reload",
		&resource.Run{Script: object.String("systemctl daemon-reload")},
		plan.DependOn("create-dir:kubelet.service.d", "install:kubelet"))
	b.AddResource(
		"service-init:kubelet",
		&resource.Service{Name: "kubelet", Status: "active", Enabled: true},
		plan.DependOn("systemd:daemon-reload", kubeletDeps...))
	p, err := b.Plan()
	if err != nil {
		log.Fatalf("%v", err)
	}
	return &p
}

// BuildDisableSwapPlan turns off swap and removes swap entries from /etc/fstab so swap will remain disabled on reboot
func buildDisableSwapPlan() plan.Resource {
	b := plan.NewBuilder()
	b.AddResource("configure:disable-swap-in-session", &resource.Run{Script: object.String("/sbin/swapoff -a")})
	b.AddResource(
		"configure:disable-swap-going-forward",
		&resource.Run{Script: object.String(
			// The ";" instead of "&&" below is because we want to copy the empty temp file over /etc/fstab if /etc/fstab only contains swap entries
			// and the "egrep" will fail on an empty file
			`tmpfile=$(mktemp /tmp/disable-swap.XXXXXX) && egrep -v '\s*\S*\s*\S*\s*swap.*' /etc/fstab > $tmpfile; mv $tmpfile /etc/fstab`)},
		plan.DependOn("configure:disable-swap-in-session"))
	p, err := b.Plan()
	if err != nil {
		log.Fatalf("%v", err)
	}
	return &p
}

// BuildKubeadmPrejoinPlan creates a sub-plan to prepare for running
// kubeadm join.
func BuildKubeadmPrejoinPlan(useIPTables bool) plan.Resource {
	b := plan.NewBuilder()
	if useIPTables {
		b.AddResource(
			"configure:net.bridge",
			&resource.Run{Script: object.String("sysctl net.bridge.bridge-nf-call-iptables=1")},
		)
	}
	b.AddResource(
		"configure:kubeadm-force-reset",
		&resource.Run{Script: object.String("kubeadm reset --force")},
	)
	p, err := b.Plan()
	if err != nil {
		log.Fatalf("%v", err)
	}
	return &p
}

// BuildSealedSecretPlan creates a sub-plan to install sealed secrets so we can check secrets into GitHub for GitOps
func BuildSealedSecretPlan(sealedSecretVersion, crdManifest, keyManifest, controllerManifest []byte) plan.Resource {
	b := plan.NewBuilder()
	b.AddResource("install:sealed-secret-crd",
		&resource.KubectlApply{Manifest: crdManifest, Filename: object.String("SealedSecretCRD.yaml"),
			WaitCondition: "condition=Established"})

	b.AddResource("install:sealed-secrets-key", &resource.KubectlApply{Manifest: keyManifest})
	b.AddResource("install:sealed-secrets-controller",
		&resource.KubectlApply{Manifest: controllerManifest, Filename: object.String("SealedSecretController.yaml")},
		plan.DependOn("install:sealed-secrets-key"))
	p, err := b.Plan()
	if err != nil {
		log.Fatalf("%v", err)
	}
	return &p
}
