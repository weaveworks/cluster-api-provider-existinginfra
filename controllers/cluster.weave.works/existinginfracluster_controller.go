/*
Copyright 2020 Weaveworks.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/go-logr/logr"
	gerrors "github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	clusterweaveworksv1alpha3 "github.com/weaveworks/cluster-api-provider-existinginfra/apis/cluster.weave.works/v1alpha3"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/config"
	capeios "github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/os"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/runners/ssh"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/specs"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/kubeadm"
	"github.com/weaveworks/libgitops/pkg/serializer"
	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1alpha3"
	"sigs.k8s.io/cluster-api/util"
	"sigs.k8s.io/cluster-api/util/patch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/yaml"
)

const (
	PoolSecretName       = "ip-pool"
	ConnectionSecretName = "connection-info"
)

// ExistingInfraClusterReconciler reconciles a ExistingInfraCluster object
type ExistingInfraClusterReconciler struct {
	client.Client
	Log           logr.Logger
	Scheme        *runtime.Scheme
	eventRecorder record.EventRecorder
}

// +kubebuilder:rbac:groups=cluster.weave.works,resources=existinginfraclusters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cluster.weave.works,resources=existinginfraclusters/status,verbs=get;update;patch

func (r *ExistingInfraClusterReconciler) Reconcile(req ctrl.Request) (_ ctrl.Result, reterr error) {
	ctx := context.TODO() // upstream will add this eventually
	contextLog := log.WithField("name", req.NamespacedName)

	// request only contains the name of the object, so fetch it from the api-server
	eic := &clusterweaveworksv1alpha3.ExistingInfraCluster{}
	err := r.Get(ctx, req.NamespacedName, eic)
	if err != nil {
		if apierrs.IsNotFound(err) { // isn't there; give in
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if eic.Spec.WorkloadCluster {
		created, err := r.machinesCreated(ctx, eic)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !created {
			contextLog.Info("About to set up new cluster")
			if err := r.setupInitialWorkloadCluster(ctx, eic); err != nil {
				contextLog.Infof("Failed to set up new cluster: %v", err)
				return ctrl.Result{}, err
			}
			contextLog.Info("Finished setting up new cluster")
		}
	}

	// Get Cluster via OwnerReferences
	cluster, err := util.GetOwnerCluster(ctx, r, eic.ObjectMeta)
	if err != nil {
		return ctrl.Result{}, err
	}
	if cluster == nil {
		contextLog.Info("Cluster Controller has not yet set ownerReferences")
		return ctrl.Result{}, err
	}
	contextLog = contextLog.WithField("cluster", cluster.Name)

	if util.IsPaused(cluster, eic) {
		contextLog.Info("ExistingInfraCluster or linked Cluster is marked as paused. Won't reconcile")
		return ctrl.Result{}, nil
	}

	// Initialize the patch helper
	patchHelper, err := patch.NewHelper(eic, r)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Attempt to Patch the ExistingInfraMachine object and status after each reconciliation.
	defer func() {
		if err := patchHelper.Patch(ctx, eic); err != nil {
			contextLog.Errorf("failed to patch ExistingInfraCluster: %v", err)
			if reterr == nil {
				reterr = err
			}
		}
	}()

	// Object still there but with deletion timestamp => run our finalizer
	if !eic.ObjectMeta.DeletionTimestamp.IsZero() {
		r.recordEvent(cluster, corev1.EventTypeNormal, "Delete", "Deleted cluster %v", cluster.Name)
		return ctrl.Result{}, errors.New("ClusterReconciler#Delete not implemented")
	}

	eic.Status.Ready = true // TODO: know whether it is really ready

	return ctrl.Result{}, nil
}

func (r *ExistingInfraClusterReconciler) setupInitialWorkloadCluster(ctx context.Context, eic *clusterweaveworksv1alpha3.ExistingInfraCluster) error {
	var finalError error
	controlPlaneCount, err := strconv.Atoi(eic.Spec.ControlPlaneMachineCount)
	if err != nil {
		return err
	}
	workerCount, err := strconv.Atoi(eic.Spec.WorkerMachineCount)
	if err != nil {
		return err
	}
	totalMachineCount := controlPlaneCount + workerCount
	machineInfo, err := r.allocate(ctx, int(totalMachineCount), eic.Namespace)
	if err != nil {
		return err
	}
	// Return all allocated IPs if we encounter an error
	defer func() {
		if val := recover(); val != nil {
			log.Infof("Panic value: %v", val)
			finalError = errors.New("Panic occurred!")
			r.deallocate(ctx, machineInfo, eic.Namespace)
		}
	}()

	cluster, err := r.getCluster(ctx, eic)
	if err != nil {
		return err
	}
	if err := r.modifyEIC(ctx, eic, func(eic *clusterweaveworksv1alpha3.ExistingInfraCluster) {
		eic.Spec.WorkloadCluster = true
	}); err != nil {
		return err
	}
	machines, eims, err := r.createMachines(machineInfo, int(controlPlaneCount), eic.Spec.KubernetesVersion, eic.Namespace, eic.Name)
	if err != nil {
		return err
	}

	log.Infof("Created machines: %v, %v", machines, eims)
	initError := r.initiateCluster(ctx, cluster, eic, machines, eims, machineInfo)
	if initError != nil && finalError == nil { // no panic
		log.Errorf("Failed to initiate cluster: %v", initError)
		r.deallocate(ctx, machineInfo, eic.Namespace)
	}
	return finalError
}

func (r *ExistingInfraClusterReconciler) machinesCreated(ctx context.Context, eic *clusterweaveworksv1alpha3.ExistingInfraCluster) (bool, error) {
	var machines clusterv1.MachineList
	err := r.Client.List(ctx, &machines, &client.ListOptions{Namespace: eic.Namespace})
	if err != nil {
		return false, err
	}
	if len(machines.Items) > 0 {
		return true, nil
	}
	return false, nil
}

func (r *ExistingInfraClusterReconciler) newBuilderWithMgr(mgr ctrl.Manager) *builder.Builder {
	return ctrl.NewControllerManagedBy(mgr).
		For(&clusterweaveworksv1alpha3.ExistingInfraCluster{}).
		WithEventFilter(pausedPredicates())
}

func (r *ExistingInfraClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.newBuilderWithMgr(mgr).Complete(r)
}

func (r *ExistingInfraClusterReconciler) SetupWithManagerOptions(mgr ctrl.Manager, options controller.Options) error {
	return r.newBuilderWithMgr(mgr).WithOptions(options).Complete(r)
}

func (r *ExistingInfraClusterReconciler) modifyEIC(ctx context.Context, eic *clusterweaveworksv1alpha3.ExistingInfraCluster, updater func(*clusterweaveworksv1alpha3.ExistingInfraCluster)) error {
	contextLog := log.WithFields(log.Fields{"cluster": eic.Name})
	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var result clusterweaveworksv1alpha3.ExistingInfraCluster
		getErr := r.Client.Get(ctx, client.ObjectKey{Name: eic.Name, Namespace: eic.Namespace}, &result)
		if getErr != nil {
			contextLog.Errorf("failed to read cluster info, assuming unsafe to update: %v", getErr)
			return getErr
		}
		updater(&result)
		updateErr := r.Client.Update(ctx, &result)
		if updateErr != nil {
			contextLog.Errorf("failed attempt to update cluster annotation: %v", updateErr)
			return updateErr
		}
		return nil
	})
	if retryErr != nil {
		contextLog.Errorf("failed to update cluster annotation: %v", retryErr)
		return gerrors.Wrapf(retryErr, "Could not mark cluster %s as updated", eic.Name)
	}
	return nil
}

func (r *ExistingInfraClusterReconciler) recordEvent(object runtime.Object, eventType, reason, messageFmt string, args ...interface{}) {
	r.eventRecorder.Eventf(object, eventType, reason, messageFmt, args...)
	switch eventType {
	case corev1.EventTypeWarning:
		log.Warnf(messageFmt, args...)
	case corev1.EventTypeNormal:
		log.Infof(messageFmt, args...)
	default:
		log.Debugf(messageFmt, args...)
	}
}

func (r *ExistingInfraClusterReconciler) initiateCluster(
	ctx context.Context,
	cluster *clusterv1.Cluster,
	eic *clusterweaveworksv1alpha3.ExistingInfraCluster,
	machines []*clusterv1.Machine,
	eims []*clusterweaveworksv1alpha3.ExistingInfraMachine,
	machineInfo []capeios.MachineInfo) error {
	sp := specs.New(cluster, eic, machines, eims)
	log.Infof("Got specs...")
	log.Infof("Machine info: %#v", machineInfo[0])
	sshKey, err := getSSHKey(machineInfo[0])
	if err != nil {
		return err
	}
	log.Infof("USER: %s, Host: %s, Port: %d", getSSHUser(machineInfo[0]), sp.GetMasterPublicAddress(), sp.MasterSpec.Public.Port)
	sshClient, err := ssh.NewClient(ssh.ClientParams{
		User:         getSSHUser(machineInfo[0]),
		PrivateKey:   sshKey,
		Host:         sp.GetMasterPublicAddress(),
		Port:         sp.MasterSpec.Public.Port,
		PrintOutputs: log.GetLevel() > log.InfoLevel})
	if err != nil {
		return gerrors.Wrap(err, "failed to create SSH client")
	}
	log.Infof("Got ssh client...")
	defer sshClient.Close()
	log.Infof("Connected to %s via ssh", sp.GetMasterPublicAddress())
	installer, err := capeios.Identify(sshClient)
	if err != nil {
		return gerrors.Wrapf(err, "failed to identify operating system for seed node (%s)", sp.GetMasterPublicAddress())
	}
	log.Infof("Identified operating system")

	// N.B.: we generate this bootstrap token where wksctl apply is run hoping
	// that this will be on a machine which has been running for a while, and
	// therefore will generate a "more random" token, than we would on a
	// potentially newly created VM which doesn't have much entropy yet.
	token, err := kubeadm.GenerateBootstrapToken()
	if err != nil {
		return gerrors.Wrap(err, "failed to generate bootstrap token")
	}

	ns := eic.Namespace

	cleanJson := eic.Annotations["kubectl.kubernetes.io/last-applied-configuration"]
	var cleanEic clusterweaveworksv1alpha3.ExistingInfraCluster
	if err := json.Unmarshal([]byte(cleanJson), &cleanEic); err != nil {
		return gerrors.Wrap(err, "failed to extract configuration")
	}
	eic = &cleanEic
	clusterManifest, err := marshal(cluster, eic)
	if err != nil {
		return gerrors.Wrap(err, "failed to marshal cluster manifests")
	}
	machineObjs := []interface{}{}
	for _, m := range machines {
		machineObjs = append(machineObjs, m)
	}
	for _, e := range eims {
		machineObjs = append(machineObjs, e)
	}
	machinesManifest, err := marshal(machineObjs...)
	if err != nil {
		return gerrors.Wrap(err, "failed to marshal machine manifests")
	}

	log.Infof("About to set up seed node: %s", sp.GetMasterPublicAddress())
	if err := capeios.SetupSeedNode(installer, capeios.SeedNodeParams{
		PublicIP:             sp.GetMasterPublicAddress(),
		PrivateIP:            sp.GetMasterPrivateAddress(),
		ServicesCIDRBlocks:   sp.Cluster.Spec.ClusterNetwork.Services.CIDRBlocks,
		PodsCIDRBlocks:       sp.Cluster.Spec.ClusterNetwork.Pods.CIDRBlocks,
		ExistingInfraCluster: *eic,
		ClusterManifest:      clusterManifest,
		MachinesManifest:     machinesManifest,
		ConnectionInfo:       machineInfo,
		BootstrapToken:       token,
		KubeletConfig: config.KubeletConfig{
			NodeIP:         sp.GetMasterPrivateAddress(),
			CloudProvider:  sp.GetCloudProvider(),
			ExtraArguments: sp.GetKubeletArguments(),
		},
		Controller: capeios.ControllerParams{
			ImageOverride: os.Getenv("EXISTINGINFRA_CONTROLLER_IMAGE"),
		},
		ImageRepository:      sp.ClusterSpec.ImageRepository,
		ControlPlaneEndpoint: sp.ClusterSpec.ControlPlaneEndpoint,
		AdditionalSANs:       sp.ClusterSpec.APIServer.AdditionalSANs,
		Namespace:            ns,
		AddonNamespaces:      map[string]string{},
	}); err != nil {
		return gerrors.Wrapf(err, "failed to set up seed node (%s)", sp.GetMasterPublicAddress())
	}

	r.modifyEIC(ctx, eic, func(c *clusterweaveworksv1alpha3.ExistingInfraCluster) {
		eic.Status.Ready = true
	})

	log.Infof("Finished setting up seed node: %s", sp.GetMasterPublicAddress())
	return nil
}

func getSSHKey(info capeios.MachineInfo) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(info.SSHKey)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func getSSHUser(info capeios.MachineInfo) string {
	return info.SSHUser
}

func (r *ExistingInfraClusterReconciler) allocate(ctx context.Context, numMachines int, ns string) ([]capeios.MachineInfo, error) {
	log.Infof("Starting allocation of %d machines", numMachines)
	var secret corev1.Secret
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: PoolSecretName}, &secret); err != nil {
		return nil, err
	}
	log.Info("Got secret")
	jsonData := []byte(secret.Data["config"])
	var info []capeios.MachineInfo
	if err := json.Unmarshal(jsonData, &info); err != nil {
		return nil, err
	}
	log.Info("Unmarshaled secret")

	if len(info) < numMachines {
		return nil, fmt.Errorf("Insufficient machines to create cluster; required: %d, available: %d", numMachines, len(info))
	}
	log.Info("Sufficient machines are present")
	resultMachines := info[:numMachines]
	info = info[numMachines:]
	infoBytes, err := json.Marshal(info)
	if err != nil {
		return nil, err
	}
	log.Info("Updating secret")
	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var result corev1.Secret
		getErr := r.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: PoolSecretName}, &result)
		if getErr != nil {
			log.Errorf("failed to read secret, can't reschedule: %v", getErr)
			return getErr
		}
		result.Data["config"] = infoBytes
		updateErr := r.Client.Update(ctx, &result)
		if updateErr != nil {
			log.Errorf("failed to reschedule secret: %v", updateErr)
			return updateErr
		}
		return nil
	})
	if retryErr != nil {
		log.Errorf("failed to reschedule secret: %v", retryErr)
		return nil, retryErr
	}

	log.Info("Successfully updated secret")
	return resultMachines, nil
}

func (r *ExistingInfraClusterReconciler) deallocate(ctx context.Context, machines []capeios.MachineInfo, ns string) error {
	log.Infof("Starting deallocation of %d machines", len(machines))
	var secret corev1.Secret
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: PoolSecretName}, &secret); err != nil {
		return err
	}
	log.Info("Got secret for deallocation")
	jsonData := []byte(secret.Data["config"])
	var info []capeios.MachineInfo
	if err := json.Unmarshal(jsonData, &info); err != nil {
		return err
	}
	log.Info("Unmarshaled secret")

	for _, m := range machines {
		info = append(info, m)
	}
	infoBytes, err := json.Marshal(info)
	if err != nil {
		return err
	}
	log.Info("Updating secret")
	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var result corev1.Secret
		getErr := r.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: PoolSecretName}, &result)
		if getErr != nil {
			log.Errorf("failed to read secret, can't reschedule: %v", getErr)
			return getErr
		}
		result.Data["config"] = infoBytes
		updateErr := r.Client.Update(ctx, &result)
		if updateErr != nil {
			log.Errorf("failed to reschedule secret: %v", updateErr)
			return updateErr
		}
		return nil
	})
	if retryErr != nil {
		log.Errorf("failed to reschedule secret: %v", retryErr)
		return retryErr
	}

	log.Info("Successfully updated secret")
	return nil
}

func (r *ExistingInfraClusterReconciler) getCluster(ctx context.Context, eic *clusterweaveworksv1alpha3.ExistingInfraCluster) (*clusterv1.Cluster, error) {
	var inputCluster clusterv1.Cluster
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: eic.Namespace, Name: eic.Name}, &inputCluster)
	if err != nil {
		return nil, err
	}
	cleanJson := inputCluster.Annotations["kubectl.kubernetes.io/last-applied-configuration"]
	var outputCluster clusterv1.Cluster
	if err := json.Unmarshal([]byte(cleanJson), &outputCluster); err != nil {
		return nil, err
	}
	return &outputCluster, nil
}

func (r *ExistingInfraClusterReconciler) createMachines(minfo []capeios.MachineInfo, controlPlaneCount int, k8sVersion, namespace, name string) ([]*clusterv1.Machine, []*clusterweaveworksv1alpha3.ExistingInfraMachine, error) {
	machines := []*clusterv1.Machine{}
	eims := []*clusterweaveworksv1alpha3.ExistingInfraMachine{}

	for idx, info := range minfo {
		machine, eim, err := createMachine(info, idx, idx < controlPlaneCount, k8sVersion, namespace, name)
		if err != nil {
			log.Infof("Got err: %v creating: %v", err, info)
			return nil, nil, err
		}
		machines = append(machines, machine)
		eims = append(eims, eim)
	}

	return machines, eims, nil
}

func createMachine(minfo capeios.MachineInfo, idx int, isControlPlane bool, k8sVersion, ns, name string) (*clusterv1.Machine, *clusterweaveworksv1alpha3.ExistingInfraMachine, error) {
	var machine clusterv1.Machine
	var eim clusterweaveworksv1alpha3.ExistingInfraMachine

	log.Infof("Creating machine: %v", minfo.PublicIP)
	baseName := "worker"
	if isControlPlane {
		baseName = "master"
	}
	log.Infof("Set base name: %s", baseName)
	machine.Labels = map[string]string{}
	machine.Labels["set"] = baseName
	log.Infof("Set label to: %s", baseName)
	machineName := fmt.Sprintf("%s-%s-%d", name, baseName, idx)

	log.Infof("Machine name: %s", machineName)
	machine.TypeMeta.APIVersion = "cluster.x-k8s.io/v1alpha3"
	machine.TypeMeta.Kind = "Machine"
	machine.Namespace = ns
	machine.Name = machineName
	machine.Spec.Version = &k8sVersion
	machine.Spec.ClusterName = name
	machine.Spec.InfrastructureRef.Kind = "ExistingInfraMachine"
	machine.Spec.InfrastructureRef.Name = machineName
	machine.Spec.InfrastructureRef.Namespace = ns
	machine.Spec.InfrastructureRef.APIVersion = "cluster.weave.works/v1alpha3"

	log.Infof("Machine: %v", machine)

	log.Infof("Creating existinginfra machine")

	eim.TypeMeta.APIVersion = "cluster.weave.works/v1alpha3"
	eim.TypeMeta.Kind = "ExistingInfraMachine"
	eim.Namespace = ns
	eim.Name = machineName

	publicEndpoint := &eim.Spec.Public
	publicAddress := minfo.PublicIP
	publicEndpoint.Address = publicAddress
	publicPort, err := toUint16(minfo.PublicPort)
	if err != nil {
		return nil, nil, err
	}
	publicEndpoint.Port = publicPort

	privateEndpoint := &eim.Spec.Private
	privateAddress := minfo.PrivateIP
	privateEndpoint.Address = privateAddress
	privatePort, err := toUint16(minfo.PrivatePort)
	if err != nil {
		return nil, nil, err
	}
	privateEndpoint.Port = privatePort

	return &machine, &eim, nil
}

func toUint16(num string) (uint16, error) {
	val, err := strconv.Atoi(num)
	if err != nil {
		return 0, err
	}
	return uint16(val), nil
}

func marshal(objs ...interface{}) (string, error) {
	var buf bytes.Buffer
	fw := serializer.NewYAMLFrameWriter(&buf)
	data := [][]byte{}
	for _, obj := range objs {
		value, err := yaml.Marshal(obj)
		if err != nil {
			return "", err
		}
		data = append(data, value)
	}
	if err := serializer.WriteFrameList(fw, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
