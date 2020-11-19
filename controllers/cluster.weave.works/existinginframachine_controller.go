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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/go-logr/logr"
	gerrors "github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	existinginfrav1 "github.com/weaveworks/cluster-api-provider-existinginfra/apis/cluster.weave.works/v1alpha3"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/config"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/os"
	machineutil "github.com/weaveworks/cluster-api-provider-existinginfra/pkg/cluster/machine"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/kubernetes/drain"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/recipe"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/resource"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/runners/ssh"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/specs"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/encoding"
	bootstraputils "github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/kubeadm"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/version"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	bootstrapapi "k8s.io/cluster-bootstrap/token/api"
	"k8s.io/kubernetes/cmd/kubeadm/app/phases/copycerts"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1alpha3"
	"sigs.k8s.io/cluster-api/util"
	"sigs.k8s.io/cluster-api/util/patch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	"sigs.k8s.io/yaml"
)

const (
	masterLabel         string = "node-role.kubernetes.io/master"
	originalMasterLabel string = "wks.weave.works/original-master"
	controllerName      string = "wks-controller"
	controllerNamespace string = "weavek8sops"
	controllerSecret    string = "wks-controller-secrets"
	bootstrapTokenID    string = "bootstrapTokenID"
)

// ExistingInfraMachineReconciler is responsible for managing this cluster's machines, and
// ensuring their state converge towards their definitions.
type ExistingInfraMachineReconciler struct {
	Client              client.Client
	Log                 logr.Logger
	Scheme              *runtime.Scheme
	clientSet           *kubernetes.Clientset
	controllerNamespace string
	eventRecorder       record.EventRecorder
	verbose             bool
}

// +kubebuilder:rbac:groups=cluster.weave.works,resources=existinginframachines,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cluster.weave.works,resources=existinginframachines/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;patch

func (a *ExistingInfraMachineReconciler) Reconcile(req ctrl.Request) (_ ctrl.Result, reterr error) {
	ctx := context.TODO() // upstream will add this eventually
	contextLog := log.WithField("name", req.NamespacedName)

	// request only contains the name of the object, so fetch it from the api-server
	eim := &existinginfrav1.ExistingInfraMachine{}
	err := a.Client.Get(ctx, req.NamespacedName, eim)
	if err != nil {
		if apierrs.IsNotFound(err) { // isn't there; give in
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Get Machine via OwnerReferences
	machine, err := util.GetOwnerMachine(ctx, a.Client, eim.ObjectMeta)
	if err != nil {
		return ctrl.Result{}, err
	}
	if machine == nil {
		contextLog.Info("Machine Controller has not yet set ownerReferences")
		return ctrl.Result{}, nil
	}
	contextLog = contextLog.WithField("machine", machine.Name)

	// Get Cluster via label "cluster.x-k8s.io/cluster-name"
	cluster, err := util.GetClusterFromMetadata(ctx, a.Client, machine.ObjectMeta)
	if err != nil {
		contextLog.Info("Machine is missing cluster label or cluster does not exist")
		return ctrl.Result{}, nil
	}

	if util.IsPaused(cluster, eim) {
		contextLog.Info("ExistingInfraMachine or linked Cluster is marked as paused. Won't reconcile")
		return ctrl.Result{}, nil
	}
	contextLog = contextLog.WithField("cluster", cluster.Name)

	// Now go from the Cluster to the ExistingInfraCluster
	if cluster.Spec.InfrastructureRef == nil || cluster.Spec.InfrastructureRef.Name == "" {
		contextLog.Info("Cluster is missing infrastructureRef")
		return ctrl.Result{}, nil
	}
	eic := &existinginfrav1.ExistingInfraCluster{}
	if err := a.Client.Get(ctx, client.ObjectKey{
		Namespace: eim.Namespace,
		Name:      cluster.Spec.InfrastructureRef.Name,
	}, eic); err != nil {
		contextLog.Infof("ExistingInfraCluster is not available yet - %v", err)
		return ctrl.Result{}, nil
	}

	// Initialize the patch helper
	patchHelper, err := patch.NewHelper(eim, a.Client)
	if err != nil {
		return ctrl.Result{}, err
	}
	// Attempt to Patch the ExistingInfraMachine object and status after each reconciliation.
	defer func() {
		if err := patchHelper.Patch(ctx, eim); err != nil {
			contextLog.Errorf("failed to patch ExistingInfraMachine: %v", err)
			if reterr == nil {
				reterr = err
			}
		}
	}()

	// Object still there but with deletion timestamp => run our finalizer
	if !eim.ObjectMeta.DeletionTimestamp.IsZero() {
		controllerutil.RemoveFinalizer(eim, existinginfrav1.ExistingInfraMachineFinalizer)
		err := a.delete(ctx, eic, machine, eim)
		if err != nil {
			contextLog.Errorf("failed to delete machine: %v", err)
		}
		return ctrl.Result{}, err
	}

	err = a.update(ctx, eic, machine, eim)
	if err != nil {
		contextLog.Errorf("failed to update machine: %v", err)
	}
	return ctrl.Result{}, err
}

func (a *ExistingInfraMachineReconciler) create(ctx context.Context, installer *os.OS, c *existinginfrav1.ExistingInfraCluster, machine *clusterv1.Machine, eim *existinginfrav1.ExistingInfraMachine) error {
	contextLog := log.WithFields(log.Fields{"machine": machine.Name, "cluster": c.Name})
	contextLog.Info("creating machine...")

	nodePlan, err := a.getNodePlan(ctx, c, machine, a.getMachineAddress(eim), installer)
	if err != nil {
		return err
	}
	if err := installer.SetupNode(ctx, nodePlan); err != nil {
		return gerrors.Wrapf(err, "failed to set up machine %s", machine.Name)
	}
	addr := a.getMachineAddress(eim)
	node, err := a.findNodeByPrivateAddress(ctx, addr)
	if err != nil {
		return gerrors.Wrapf(err, "failed to find node by address: %s", addr)
	}
	if err = a.setNodeProviderIDIfNecessary(ctx, node); err != nil {
		return err
	}
	if err = a.setNodeAnnotation(ctx, node.Name, recipe.PlanKey, nodePlan.ToState().ToJSON()); err != nil {
		return err
	}

	// CAPI machine controller requires providerID
	eim.Spec.ProviderID = generateProviderID(node.Name)
	eim.Status.Ready = true
	a.recordEvent(machine, corev1.EventTypeNormal, "Create", "created machine %s", machine.Name)
	return nil
}

func (a *ExistingInfraMachineReconciler) getClusterConfigMap(ctx context.Context, eic *existinginfrav1.ExistingInfraCluster) (*v1.ConfigMap, error) {
	var configMap v1.ConfigMap
	if err := a.Client.Get(ctx, client.ObjectKey{Namespace: a.controllerNamespace, Name: eic.Name}, &configMap); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.New("No cluster config map found")
		}
		log.Infof("Failed to retrieve config map")
		return nil, err
	}
	return &configMap, nil
}

func (a *ExistingInfraMachineReconciler) connectTo(ctx context.Context, c *existinginfrav1.ExistingInfraCluster, m *existinginfrav1.ExistingInfraMachine) (*os.OS, io.Closer, error) {
	privateAddress := a.getMachineAddress(m)
	info, err := a.getMachineInfo(ctx, privateAddress)
	if err != nil {
		return nil, nil, err
	}
	sshKey, err := getSSHKey(info)
	if err != nil {
		return nil, nil, err
	}

	sshClient, err := ssh.NewClient(ssh.ClientParams{
		User:         info.SSHUser,
		Host:         privateAddress,
		Port:         m.Spec.Private.Port,
		PrivateKey:   sshKey,
		PrintOutputs: a.verbose,
	})
	if err != nil {
		return nil, nil, gerrors.Wrapf(err, "failed to create SSH client using %v", m.Spec.Private)
	}
	os, err := os.Identify(ctx, sshClient)
	if err != nil {
		return nil, nil, gerrors.Wrapf(err, "failed to identify machine %s's operating system", a.getMachineAddress(m))
	}
	return os, sshClient, nil
}

func (a *ExistingInfraMachineReconciler) getMachineInfo(ctx context.Context, privateAddress string) (os.MachineInfo, error) {
	var secret corev1.Secret
	err := a.Client.Get(ctx, client.ObjectKey{Namespace: a.controllerNamespace, Name: ConnectionSecretName}, &secret)
	if err != nil {
		return os.MachineInfo{}, gerrors.Wrap(err, "failed to get connection secret")
	}
	pool := secret.Data["config"]
	var info []os.MachineInfo
	if err := json.Unmarshal(pool, &info); err != nil {
		return os.MachineInfo{}, gerrors.Wrap(err, "failed to unmarshal secret")
	}
	return a.getMachineInfoOrUseDefault(ctx, &info, privateAddress)
}

func (a *ExistingInfraMachineReconciler) getMachineInfoOrUseDefault(ctx context.Context, mi *[]os.MachineInfo, privateAddress string) (os.MachineInfo, error) {
	type infoKey struct {
		u string
		p string
	}
	uniqInfos := make(map[infoKey]interface{})
	for _, m := range *mi {
		if m.PrivateIP == privateAddress {
			return m, nil
		}
		uniqInfos[infoKey{u: m.SSHUser, p: m.SSHKey}] = nil
	}
	// if we don't find a user/key for this private IP and all of the entries are the same,
	// return the first one
	// TODO: Add an info for this private address
	if len(uniqInfos) == 1 {
		return (*mi)[0], nil
	}
	return os.MachineInfo{}, fmt.Errorf("No machine information found for: %s", privateAddress)
}

// kubeadmJoinSecrets groups the values available in the wks-controller-secrets
// Secret to provide to kubeadm join commands.
type kubeadmJoinSecrets struct {
	// DiscoveryTokenCaCertHash is used to validate that the root CA public key
	// of the cluster we are trying to join matches.
	DiscoveryTokenCaCertHash string
	// BootstrapTokenID is the ID of the token used by kubeadm init and kubeadm
	// join to safely form new clusters.
	BootstrapTokenID string
	// CertificateKey is used by kubeadm --certificate-key to have other master
	// nodes safely join the cluster.
	CertificateKey string
}

func (a *ExistingInfraMachineReconciler) kubeadmJoinSecrets(ctx context.Context) (*kubeadmJoinSecrets, error) {
	var secret corev1.Secret
	err := a.Client.Get(ctx, client.ObjectKey{Namespace: a.controllerNamespace, Name: controllerSecret}, &secret)
	if err != nil {
		return nil, gerrors.Wrap(err, "failed to get WKS' secret")
	}
	return &kubeadmJoinSecrets{
		DiscoveryTokenCaCertHash: string(secret.Data["discoveryTokenCaCertHash"]),
		BootstrapTokenID:         string(secret.Data[bootstrapTokenID]),
		CertificateKey:           string(secret.Data["certificateKey"]),
	}, nil
}

func (a *ExistingInfraMachineReconciler) updateKubeadmJoinSecrets(ctx context.Context, id string, secret *corev1.Secret) error {
	len := base64.StdEncoding.EncodedLen(len(id))
	enc := make([]byte, len)
	base64.StdEncoding.Encode(enc, []byte(id))
	patch := []byte(fmt.Sprintf("{\"data\":{\"%s\":\"%s\"}}", bootstrapTokenID, enc))
	err := a.Client.Patch(ctx, secret, client.RawPatch(types.StrategicMergePatchType, patch))
	if err != nil {
		log.Debugf("failed to patch wks secret %s %v", patch, err)
	}
	return err
}

func (a *ExistingInfraMachineReconciler) token(ctx context.Context, id string) (string, error) {
	ns := "kube-system"
	name := fmt.Sprintf("%s%s", bootstrapapi.BootstrapTokenSecretPrefix, id)
	secret := &corev1.Secret{}
	err := a.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, secret)
	if err != nil {
		// The secret may have been removed if it expired so we will generate a new one
		log.Infof("failed to find original bootstrap token %s/%s, generating a new one", ns, name)
		newSecret, err := a.installNewBootstrapToken(ctx, ns)
		if err != nil {
			return "", gerrors.Wrapf(err, "failed to find old secret %s/%s or generate a new one", ns, name)
		}
		secret = newSecret
	} else if bootstrapTokenHasExpired(secret) {
		log.Infof("token %s/%s has expired, generating a new one", ns, name)
		newSecret, err := a.installNewBootstrapToken(ctx, ns)
		if err != nil {
			return "", gerrors.Wrapf(err, "failed to replace expired secret %s/%s with a new one", ns, name)
		}
		secret = newSecret
	}
	tokenID, ok := secret.Data[bootstrapapi.BootstrapTokenIDKey]
	if !ok {
		return "", gerrors.Errorf("token-id not found %s/%s", ns, name)
	}
	tokenSecret, ok := secret.Data[bootstrapapi.BootstrapTokenSecretKey]
	if !ok {
		return "", gerrors.Errorf("token-secret not found %s/%s", ns, name)
	}
	return fmt.Sprintf("%s.%s", tokenID, tokenSecret), nil
}

func bootstrapTokenHasExpired(secret *corev1.Secret) bool {
	// verify that the token hasn't expired
	expiration, ok := secret.Data[bootstrapapi.BootstrapTokenExpirationKey]
	if !ok {
		log.Debugf("expiration not found for secret %s/%s", secret.ObjectMeta.Namespace, secret.ObjectMeta.Name)
		return true
	}
	expirationTime, err := time.Parse(time.RFC3339, string(expiration))
	if err != nil {
		log.Debugf("failed to parse token expiration %s for secret %s/%s error %v", expiration, secret.ObjectMeta.Namespace, secret.ObjectMeta.Name, err)
		return true
	}
	// if the token expires within 60 seconds, we need to generate a new one
	return time.Until(expirationTime).Seconds() < 60
}
func (a *ExistingInfraMachineReconciler) installNewBootstrapToken(ctx context.Context, ns string) (*corev1.Secret, error) {
	secret, err := bootstraputils.GenerateBootstrapSecret(ns)
	if err != nil {
		return nil, gerrors.Errorf("failed to create new bootstrap token %s/%s", ns, secret.ObjectMeta.Name)
	}
	err = a.Client.Create(ctx, secret)
	if err != nil {
		return nil, gerrors.Errorf("failed to install new bootstrap token %s/%s", ns, secret.ObjectMeta.Name)
	}
	tokenID, ok := secret.Data[bootstrapapi.BootstrapTokenIDKey]
	if !ok {
		return nil, gerrors.Errorf("token-id not found %s/%s", secret.ObjectMeta.Namespace, secret.ObjectMeta.Name)
	}
	if err := a.updateKubeadmJoinSecrets(ctx, string(tokenID), secret); err != nil {
		return nil, gerrors.Errorf("Failed to update wks join token %s/%s", secret.ObjectMeta.Namespace, secret.ObjectMeta.Name)
	}
	return secret, nil
}

// Delete the machine. If no error is returned, it is assumed that all dependent resources have been cleaned up.
func (a *ExistingInfraMachineReconciler) delete(ctx context.Context, c *existinginfrav1.ExistingInfraCluster, machine *clusterv1.Machine, eim *existinginfrav1.ExistingInfraMachine) error {
	contextLog := log.WithFields(log.Fields{"machine": machine.Name, "cluster": c.Name})
	contextLog.Info("deleting machine ...")
	addr := a.getMachineAddress(eim)
	node, err := a.findNodeByPrivateAddress(ctx, addr)
	if err != nil {
		return gerrors.Wrapf(err, "failed to find node by address: %s", addr)
	}
	// Check if there's an adequate number of masters
	isMaster := isMaster(node)
	masters, err := a.getMasterNodes(ctx)
	if err != nil {
		return err
	}
	if isMaster && len(masters) == 1 {
		return errors.New("there should be at least one master")
	}
	if err := drain.Drain(node, a.clientSet, drain.Params{
		Force:               true,
		DeleteLocalData:     true,
		IgnoreAllDaemonSets: true,
	}); err != nil {
		return err
	}
	if err := a.Client.Delete(ctx, node); err != nil {
		return err
	}
	a.recordEvent(machine, corev1.EventTypeNormal, "Delete", "deleted machine %s", machine.Name)
	return nil
}

// Update the machine to the provided definition.
func (a *ExistingInfraMachineReconciler) update(ctx context.Context, c *existinginfrav1.ExistingInfraCluster, machine *clusterv1.Machine, eim *existinginfrav1.ExistingInfraMachine) error {
	contextLog := log.WithFields(log.Fields{"machine": machine.Name, "cluster": c.Name})
	contextLog.Info("updating machine...")
	installer, closer, err := a.connectTo(ctx, c, eim)
	if err != nil {
		return gerrors.Wrapf(err, "failed to establish connection to machine %s", machine.Name)
	}
	defer closer.Close()

	addr := a.getMachineAddress(eim)
	node, err := a.findNodeByPrivateAddress(ctx, addr)
	if err != nil {
		if apierrs.IsNotFound(err) {
			log.Infof("no existing node found for %s...", addr)
			a.displayAllNodes(ctx)
			log.Infof("creating %s...", addr)
			// isn't there; try to create it

			// Since ExistingInfra controller handles bootstrapping, add the
			// finalizer here to ensure we cleanup on delete
			if err := a.modifyEIM(ctx, eim, func(e *existinginfrav1.ExistingInfraMachine) {
				controllerutil.AddFinalizer(eim, existinginfrav1.ExistingInfraMachineFinalizer)
			}); err != nil {
				return gerrors.Wrapf(err, "failed to add finalizer to: %s", eim.Spec.Private.Address)
			}
			return a.create(ctx, installer, c, machine, eim)
		}
		return gerrors.Wrapf(err, "failed to find node by address: %s", addr)
	}
	log.Infof("found existing node for %s...", addr)
	contextLog = contextLog.WithFields(log.Fields{"node": node.Name})

	if err = a.setNodeProviderIDIfNecessary(ctx, node); err != nil {
		return err
	}
	isMaster := isMaster(node)
	if isMaster {
		// Check if the kubeadm-certs secret exists.
		// If not, run the renewal plan to upload new certs:
		// kubeadm init phase upload-certs --upload-certs
		// and update wks-controller-secrets with the new certificate key and bootstrap token ID
		// so that new control plane nodes can be added to the cluster.

		exists, _ := a.kubeadmCertsExists(ctx)
		if !exists {
			log.Info("kubeadm-certs secret not found, regenerating...")
			err = a.renewKubeadmCerts(ctx, installer)
			if err != nil {
				return err
			}
		}

		if err := a.prepareForMasterUpdate(ctx, node); err != nil {
			contextLog.Infof("skipping update for %s...", addr)
			return err
		}
	}
	nodePlan, err := a.getNodePlan(ctx, c, machine, a.getMachineAddress(eim), installer)
	if err != nil {
		return gerrors.Wrapf(err, "Failed to get node plan for machine %s", machine.Name)
	}
	planState := nodePlan.ToState()
	currentPlan, found := node.Annotations[recipe.PlanKey]
	if !found {
		contextLog.Info("No plan annotation on Node; unable to update")
		return nil
	}
	currentState, err := plan.NewStateFromJSON(strings.NewReader(currentPlan))
	if err != nil {
		return gerrors.Wrapf(err, "Failed to parse node plan for machine %s", machine.Name)
	}
	// check equality by re-serialising to JSON; this avoids any formatting differences, also
	// type differences between deserialised State and State created from Plan.
	planJSON := planState.ToJSON()
	if currentState.ToJSON() == planJSON {
		contextLog.Info("Machine and node have matching plans; nothing to do")
		return nil
	}

	if diffedPlan, err := currentState.Diff(planState); err == nil {
		contextLog.Info("........................ DIFF PLAN ........................")
		fmt.Print(diffedPlan)
	} else {
		contextLog.Errorf("DIFF PLAN Error: %v", err)
	}

	contextLog.Infof("........................NEW UPDATE FOR: %s...........................", machine.Name)

	upOrDowngrade := isUpOrDowngrade(machine, node)
	contextLog.Infof("Is master: %t, is up or downgrade: %t", isMaster, upOrDowngrade)
	if upOrDowngrade {
		if err := checkForVersionJump(machine, node); err != nil {
			return err
		}
		version := machineutil.GetKubernetesVersion(machine)
		nodeStyleVersion := "v" + version
		originalNeedsUpdate, err := a.checkIfOriginalMasterNotAtVersion(ctx, nodeStyleVersion)
		if err != nil {
			return err
		}
		contextLog.Infof("Original needs update: %t", originalNeedsUpdate)
		masterNeedsUpdate, err := a.checkIfMasterNotAtVersion(ctx, nodeStyleVersion)
		if err != nil {
			return err
		}
		contextLog.Infof("Master needs update: %t", masterNeedsUpdate)
		isOriginal, err := a.isOriginalMaster(ctx, node)
		if err != nil {
			return err
		}
		contextLog.Infof("Is original: %t", isOriginal)
		if (!isOriginal && originalNeedsUpdate) || (!isMaster && masterNeedsUpdate) {
			return errors.New("Master nodes must be upgraded before worker nodes")
		}
		isController, err := a.isControllerNode(ctx, node)
		if err != nil {
			return err
		}
		contextLog.Infof("Is controller: %t", isController)
		if isMaster {
			switch {
			case isController:
				// If there is no error, this will end the run of this reconciliation since the controller will be migrated
				if err := drain.Drain(node, a.clientSet, drain.Params{
					Force:               true,
					DeleteLocalData:     true,
					IgnoreAllDaemonSets: true,
				}); err != nil {
					return err
				}
			case isOriginal:
				return a.kubeadmUpOrDowngrade(ctx, c, machine, eim, node, installer, version, planJSON, recipe.OriginalMaster)
			default:
				return a.kubeadmUpOrDowngrade(ctx, c, machine, eim, node, installer, version, planJSON, recipe.SecondaryMaster)
			}
		}
		return a.kubeadmUpOrDowngrade(ctx, c, machine, eim, node, installer, version, planJSON, recipe.Worker)
	}

	if err = a.performActualUpdate(ctx, installer, machine, node, nodePlan, c); err != nil {
		return err
	}

	if err = a.setNodeAnnotation(ctx, node.Name, recipe.PlanKey, planJSON); err != nil {
		return err
	}

	// CAPI machine controller requires providerID
	eim.Spec.ProviderID = generateProviderID(node.Name)
	eim.Status.Ready = true

	a.recordEvent(machine, corev1.EventTypeNormal, "Update", "updated machine %s", machine.Name)
	return nil
}

func (a *ExistingInfraMachineReconciler) displayAllNodes(ctx context.Context) {
	var nodes corev1.NodeList
	if err := a.Client.List(ctx, &nodes); err == nil {
		nodeIPs := []string{}
		for _, node := range nodes.Items {
			nodeIPs = append(nodeIPs, getNodePrivateAddress(&node))
		}
		log.Infof("all existing nodes found: %+v", nodeIPs)
	}
}

func (a *ExistingInfraMachineReconciler) renewKubeadmCerts(ctx context.Context, installer *os.OS) error {
	// Renewal of kubeadm-certs is done in two steps, generating a certificate key
	// which is passed to kubeadm upload certs plan
	certificateKey, err := copycerts.CreateCertificateKey()
	if err != nil {
		return err
	}
	log.Debugf(fmt.Sprintf("uploading kubeadm certs with cert key: %s", certificateKey))
	uploadCertsPlan, err := recipe.BuildUploadKubeadmCertsPlan(ctx, certificateKey)
	if err != nil {
		log.Errorf("failed to build upload kubeadm certs plan, err: %s", err)
		return err
	}
	_, err = uploadCertsPlan.Apply(ctx, installer.Runner, plan.EmptyDiff())
	if err != nil {
		log.Errorf("Apply of Plan failed:\n%s\n", err)
		return err
	}

	log.Infof("creating a new bootstrap token...")
	bootstrapTokenSecret, err := a.installNewBootstrapToken(ctx, "kube-system")
	if err != nil {
		return gerrors.Errorf("failed to create new bootstrap token, err: %s", err)
	}
	tokenID, ok := bootstrapTokenSecret.Data[bootstrapapi.BootstrapTokenIDKey]
	if !ok {
		return gerrors.Errorf("token-id not found %s/%s", bootstrapTokenSecret.ObjectMeta.Namespace, bootstrapTokenSecret.ObjectMeta.Name)
	}

	// Base64 encode the certificate key and token ID
	certificateKeyB64 := encoding.Base64Encode(certificateKey)
	tokenIDB64 := encoding.Base64Encode(string(tokenID))

	patch := []byte(fmt.Sprintf("{\"data\":{\"%s\":\"%s\", \"%s\":\"%s\"}}",
		"certificateKey", certificateKeyB64, "bootstrapTokenID", tokenIDB64))

	// Update wks-controller-secrets with new cert key and bootstrap token ID
	secret := corev1.Secret{}
	secretName := types.NamespacedName{
		Name:      controllerSecret,
		Namespace: controllerNamespace,
	}
	err = a.Client.Get(ctx, secretName, &secret)
	if err != nil {
		log.Infof("failed to get %s in namespace %s %s %v", controllerSecret, controllerNamespace, patch, err)
		return err
	}
	err = a.Client.Patch(ctx, &secret, client.RawPatch(types.StrategicMergePatchType, patch))
	if err != nil {
		log.Infof("failed to patch %s secret %s %v", controllerSecret, patch, err)
		return err
	}
	return nil
}

// kubeadmUpOrDowngrade does upgrade or downgrade a machine.
// Parameter k8sversion specified here represents the version of both Kubernetes and Kubeadm.
func (a *ExistingInfraMachineReconciler) kubeadmUpOrDowngrade(ctx context.Context, c *existinginfrav1.ExistingInfraCluster, machine *clusterv1.Machine, eim *existinginfrav1.ExistingInfraMachine, node *corev1.Node, installer *os.OS,
	k8sVersion, planJSON string, ntype recipe.NodeType) error {
	b := plan.NewBuilder()

	upgradeRes, err := recipe.BuildUpgradePlan(installer.PkgType, k8sVersion, ntype)

	if err != nil {
		return err
	}

	b.AddResource("upgrade:k8s", upgradeRes)

	p, err := b.Plan()
	if err != nil {
		return err
	}
	if err := installer.SetupNode(ctx, &p); err != nil {
		log.Infof("Failed to upgrade node %s: %v", node.Name, err)
		return err
	}
	log.Infof("About to uncordon node %s...", node.Name)
	if err := a.uncordon(ctx, node); err != nil {
		log.Info("Failed to uncordon...")
		return err
	}
	log.Info("Finished with uncordon...")
	if err = a.setNodeAnnotation(ctx, node.Name, recipe.PlanKey, planJSON); err != nil {
		return err
	}
	a.recordEvent(machine, corev1.EventTypeNormal, "Update", "updated machine %s", machine.Name)
	return nil
}

func (a *ExistingInfraMachineReconciler) prepareForMasterUpdate(ctx context.Context, node *corev1.Node) error {
	// Check if it's safe to update a master
	if err := a.checkMasterHAConstraint(ctx, node); err != nil {
		return gerrors.Wrap(err, "Not enough available master nodes to allow master update")
	}
	return nil
}

func (a *ExistingInfraMachineReconciler) performActualUpdate(
	ctx context.Context,
	installer *os.OS,
	machine *clusterv1.Machine,
	node *corev1.Node,
	nodePlan *plan.Plan,
	cluster *existinginfrav1.ExistingInfraCluster) error {
	if err := drain.Drain(node, a.clientSet, drain.Params{
		Force:               true,
		DeleteLocalData:     true,
		IgnoreAllDaemonSets: true,
	}); err != nil {
		return err
	}
	log.Info("repaving node...")
	if err := installer.SetupNode(ctx, nodePlan); err != nil {
		return gerrors.Wrapf(err, "failed to set up machine %s", machine.Name)
	}
	log.Info("uncordoning node...")
	if err := a.uncordon(ctx, node); err != nil {
		return err
	}
	log.Info("finished updating node...")
	return nil
}

func (a *ExistingInfraMachineReconciler) getNodePlan(ctx context.Context, provider *existinginfrav1.ExistingInfraCluster, machine *clusterv1.Machine, machineAddress string, installer *os.OS) (*plan.Plan, error) {
	namespace := a.controllerNamespace
	secrets, err := a.kubeadmJoinSecrets(ctx)
	if err != nil {
		return nil, err
	}
	token, err := a.token(ctx, secrets.BootstrapTokenID)
	if err != nil {
		return nil, err
	}
	master, err := a.getControllerNode(ctx)
	if err != nil {
		return nil, err
	}
	masterIP, err := getInternalAddress(master)
	if err != nil {
		return nil, err
	}
	configMaps, err := a.getProviderConfigMaps(ctx, provider)
	if err != nil {
		return nil, err
	}
	authConfigMap, err := a.getAuthConfigMap(ctx)
	if err != nil {
		return nil, err
	}
	var authSecrets map[string]resource.SecretData
	if authConfigMap != nil {
		authSecrets, err = a.getAuthSecrets(ctx, authConfigMap)
		if err != nil {
			return nil, err
		}
	}
	plan, err := installer.CreateNodeSetupPlan(ctx, os.NodeParams{
		IsMaster:                 machine.Labels["set"] == "master",
		MasterIP:                 masterIP,
		MasterPort:               6443, // TODO: read this dynamically, from somewhere.
		Token:                    token,
		DiscoveryTokenCaCertHash: secrets.DiscoveryTokenCaCertHash,
		CertificateKey:           secrets.CertificateKey,
		KubeletConfig: config.KubeletConfig{
			NodeIP:         machineAddress,
			CloudProvider:  provider.Spec.CloudProvider,
			ExtraArguments: specs.TranslateServerArgumentsToStringMap(provider.Spec.KubeletArguments),
		},
		KubernetesVersion:    machineutil.GetKubernetesVersion(machine),
		CRI:                  provider.Spec.CRI,
		ConfigFileSpecs:      provider.Spec.OS.Files,
		ProviderConfigMaps:   configMaps,
		AuthConfigMap:        authConfigMap,
		Secrets:              authSecrets,
		Namespace:            namespace,
		ControlPlaneEndpoint: provider.Spec.ControlPlaneEndpoint,
	})
	if err != nil {
		return nil, gerrors.Wrapf(err, "failed to create machine plan for %s", machine.Name)
	}
	return plan, nil
}

func (a *ExistingInfraMachineReconciler) getAuthConfigMap(ctx context.Context) (*corev1.ConfigMap, error) {
	var maps corev1.ConfigMapList
	err := a.Client.List(ctx, &maps, &client.ListOptions{Namespace: a.controllerNamespace})
	if err != nil {
		return nil, err
	}
	for _, cmap := range maps.Items {
		if cmap.Name == "auth-config" {
			return &cmap, nil
		}
	}
	return nil, nil
}

func (a *ExistingInfraMachineReconciler) getAuthSecrets(ctx context.Context, authConfigMap *corev1.ConfigMap) (map[string]resource.SecretData, error) {
	authSecrets := map[string]resource.SecretData{}
	for _, authType := range []string{"authentication", "authorization"} {
		secretName := authConfigMap.Data[authType+"-secret-name"]
		var secret corev1.Secret
		err := a.Client.Get(ctx, client.ObjectKey{Namespace: a.controllerNamespace, Name: secretName}, &secret)
		// TODO: retry several times like the old code did (?)
		// TODO: check whether it is a not-found response
		if err != nil {
			// No secret present
			continue
		}
		if secret.Data != nil {
			authSecrets[authType] = secret.Data
		}
	}
	return authSecrets, nil
}

func (a *ExistingInfraMachineReconciler) getProviderConfigMaps(ctx context.Context, provider *existinginfrav1.ExistingInfraCluster) (map[string]*corev1.ConfigMap, error) {
	fileSpecs := provider.Spec.OS.Files
	configMaps := map[string]*corev1.ConfigMap{}
	for _, fileSpec := range fileSpecs {
		mapName := fileSpec.Source.ConfigMap
		if _, seen := configMaps[mapName]; !seen {
			var configMap corev1.ConfigMap
			err := a.Client.Get(ctx, client.ObjectKey{Namespace: a.controllerNamespace, Name: mapName}, &configMap)
			if err != nil {
				return nil, err
			}
			configMaps[mapName] = &configMap
		}
	}
	return configMaps, nil
}

func isUpOrDowngrade(machine *clusterv1.Machine, node *corev1.Node) bool {
	return machineVersion(machine) != nodeVersion(node)
}

func checkForVersionJump(machine *clusterv1.Machine, node *corev1.Node) error {
	mVersion := machineVersion(machine)
	nVersion := nodeVersion(node)
	lt, err := version.LessThan(mVersion, nVersion)
	if err != nil {
		return err
	}
	if lt {
		return fmt.Errorf("Downgrade not supported. Machine version: %s is less than node version: %s", mVersion, nVersion)
	}
	isVersionJump, err := version.Jump(nVersion, mVersion)
	if err != nil {
		return err
	}
	if isVersionJump {
		return fmt.Errorf("Upgrades can only be performed between patch versions of a single minor version or between "+
			"minor versions differing by no more than 1 - machine version: %s, node version: %s", mVersion, nVersion)
	}
	return nil
}

func (a *ExistingInfraMachineReconciler) checkIfMasterNotAtVersion(ctx context.Context, kubernetesVersion string) (bool, error) {
	nodes, err := a.getMasterNodes(ctx)
	if err != nil {
		// If we can't read the nodes, return the error so we don't
		// accidentally flush the sole master
		return false, err
	}
	for _, master := range nodes {
		if nodeVersion(master) != kubernetesVersion {
			return true, nil
		}
	}
	return false, nil
}

func (a *ExistingInfraMachineReconciler) checkIfOriginalMasterNotAtVersion(ctx context.Context, kubernetesVersion string) (bool, error) {
	node, err := a.getOriginalMasterNode(ctx)
	if err != nil {
		// If we can't read the nodes, return the error so we don't
		// accidentally flush the sole master
		return false, err
	}
	return nodeVersion(node) != kubernetesVersion, nil
}

func (a *ExistingInfraMachineReconciler) getOriginalMasterNode(ctx context.Context) (*corev1.Node, error) {
	nodes, err := a.getMasterNodes(ctx)
	if err != nil {
		return nil, err
	}
	for _, node := range nodes {
		_, isOriginalMaster := node.Labels[originalMasterLabel]
		if isOriginalMaster {
			return node, nil
		}
	}

	if len(nodes) == 0 {
		return nil, errors.New("No master found")
	}

	// There is no master node which is labeled with originalMasterLabel
	// So we just pick nodes[0] of the list, then label it.
	originalMasterNode := nodes[0]
	if _, exist := originalMasterNode.Labels[originalMasterLabel]; !exist {
		if err := a.setNodeLabel(ctx, originalMasterNode.Name, originalMasterLabel, ""); err != nil {
			return nil, err
		}
	}

	return originalMasterNode, nil
}

func (a *ExistingInfraMachineReconciler) isOriginalMaster(ctx context.Context, node *corev1.Node) (bool, error) {
	masterNode, err := a.getOriginalMasterNode(ctx)
	if err != nil {
		return false, err
	}
	return masterNode.Name == node.Name, nil
}

func machineVersion(machine *clusterv1.Machine) string {
	return "v" + machineutil.GetKubernetesVersion(machine)
}

func nodeVersion(node *corev1.Node) string {
	return node.Status.NodeInfo.KubeletVersion
}

func (a *ExistingInfraMachineReconciler) uncordon(ctx context.Context, node *corev1.Node) error {
	contextLog := log.WithFields(log.Fields{"node": node.Name})
	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var result corev1.Node
		getErr := a.Client.Get(ctx, client.ObjectKey{Name: node.Name}, &result)
		if getErr != nil {
			contextLog.Errorf("failed to read node info, can't reschedule: %v", getErr)
			return getErr
		}
		result.Spec.Unschedulable = false
		updateErr := a.Client.Update(ctx, &result)
		if updateErr != nil {
			contextLog.Errorf("failed to reschedule node: %v", updateErr)
			return updateErr
		}
		return nil
	})
	if retryErr != nil {
		contextLog.Errorf("failed to reschedule node: %v", retryErr)
		return retryErr
	}
	return nil
}

func (a *ExistingInfraMachineReconciler) setNodeAnnotation(ctx context.Context, nodeName string, key, value string) error {
	err := a.modifyNode(ctx, nodeName, func(node *corev1.Node) {
		node.Annotations[key] = value
	})
	if err != nil {
		return gerrors.Wrapf(err, "Failed to set node annotation: %s for node: %s", key, nodeName)
	}
	return nil
}

func generateProviderID(nodeName string) string {
	return "existingInfra://" + nodeName
}

// Note: does not modify the Node passed in
func (a *ExistingInfraMachineReconciler) setNodeProviderIDIfNecessary(ctx context.Context, node *corev1.Node) error {
	if node.Spec.ProviderID != "" {
		return nil
	}
	err := a.modifyNode(ctx, node.Name, func(node *corev1.Node) {
		node.Spec.ProviderID = generateProviderID(node.Name)
	})
	if err != nil {
		return gerrors.Wrapf(err, "Failed to set providerID on node: %s", node.Name)
	}
	return nil
}

func (a *ExistingInfraMachineReconciler) setNodeLabel(ctx context.Context, nodeName string, label, value string) error {
	err := a.modifyNode(ctx, nodeName, func(node *corev1.Node) {
		node.Labels[label] = value
	})
	if err != nil {
		return gerrors.Wrapf(err, "Failed to set node label: %s for node: %s", label, nodeName)
	}
	return nil
}

func (a *ExistingInfraMachineReconciler) modifyNode(ctx context.Context, nodeName string, updater func(node *corev1.Node)) error {
	contextLog := log.WithFields(log.Fields{"node": nodeName})
	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var result corev1.Node
		getErr := a.Client.Get(ctx, client.ObjectKey{Name: nodeName}, &result)
		if getErr != nil {
			contextLog.Errorf("failed to read node info, assuming unsafe to update: %v", getErr)
			return getErr
		}
		updater(&result)
		updateErr := a.Client.Update(ctx, &result)
		if updateErr != nil {
			contextLog.Errorf("failed attempt to update node: %v", updateErr)
			return updateErr
		}
		return nil
	})
	if retryErr != nil {
		contextLog.Errorf("failed to update node annotation: %v", retryErr)
		return gerrors.Wrapf(retryErr, "Could not mark node %s as updated", nodeName)
	}
	return nil
}

func (a *ExistingInfraMachineReconciler) modifyEIM(ctx context.Context, eim *existinginfrav1.ExistingInfraMachine, updater func(*existinginfrav1.ExistingInfraMachine)) error {
	contextLog := log.WithFields(log.Fields{"eim": eim.Name})
	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var result existinginfrav1.ExistingInfraMachine
		getErr := a.Client.Get(ctx, client.ObjectKey{Namespace: eim.Namespace, Name: eim.Name}, &result)
		if getErr != nil {
			contextLog.Errorf("failed to read existinginframachine info, assuming unsafe to update: %v", getErr)
			return getErr
		}
		updater(&result)
		updateErr := a.Client.Update(ctx, &result)
		if updateErr != nil {
			contextLog.Errorf("failed attempt to update existinginframachine: %v", updateErr)
			return updateErr
		}
		return nil
	})
	if retryErr != nil {
		contextLog.Errorf("failed to update existinginframachine: %v", retryErr)
		return gerrors.Wrapf(retryErr, "Could not update existinginframachine: %s", eim.Name)
	}
	return nil
}

func (a *ExistingInfraMachineReconciler) checkMasterHAConstraint(ctx context.Context, nodeBeingUpdated *corev1.Node) error {
	// We check machines rather than nodes to establish quorum as nodes get deleted during update
	var machines clusterv1.MachineList
	err := a.Client.List(ctx, &machines)
	if err != nil {
		return gerrors.Wrap(err, "failed to list machines")
	}
	controlPlaneCount := 0
	for _, machine := range machines.Items {
		if machine.Labels["set"] == "master" {
			controlPlaneCount++
		}
	}

	nodes, err := a.getMasterNodes(ctx)
	if err != nil {
		// If we can't read the nodes, return the error so we don't
		// accidentally flush the sole master
		return err
	}

	avail := 0
	quorum := (controlPlaneCount + 1) / 2

	for _, node := range nodes {
		if sameNode(nodeBeingUpdated, node) {
			continue
		}
		if hasConditionTrue(node, corev1.NodeReady) && !hasNonMasterNoScheduleTaint(node) {
			log.Infof("available master: %v", getNodePrivateAddress(node))
			avail++
			if avail >= quorum {
				return nil
			}
		}
	}
	return fmt.Errorf("Fewer than %d control-plane nodes would be available", quorum)
}

// we compare Nodes by name, because name is required to be unique and
// uids will differ if we manage to delete and recreate the object.
func sameNode(a, b *corev1.Node) bool {
	return a.Name == b.Name
}

func hasConditionTrue(node *corev1.Node, typ corev1.NodeConditionType) bool {
	for _, cond := range node.Status.Conditions {
		if cond.Type == typ && cond.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func hasNonMasterNoScheduleTaint(node *corev1.Node) bool {
	effect := v1.TaintEffect("NoSchedule")

	for _, taint := range node.Spec.Taints {
		if taint.Key != masterLabel && taint.Effect == effect {
			return true
		}
	}
	return false
}

func (a *ExistingInfraMachineReconciler) findNodeByPrivateAddress(ctx context.Context, addr string) (*corev1.Node, error) {
	var nodes corev1.NodeList
	err := a.Client.List(ctx, &nodes)
	if err != nil {
		return nil, gerrors.Wrap(err, "failed to list nodes")
	}
	for _, node := range nodes.Items {
		if getNodePrivateAddress(&node) == addr {
			return &node, nil
		}
	}
	return nil, apierrs.NewNotFound(schema.GroupResource{Group: "", Resource: "nodes"}, "")
}

func (a *ExistingInfraMachineReconciler) findMachineByPrivateAddress(ctx context.Context, addr string) (*existinginfrav1.ExistingInfraMachine, error) {
	var machines existinginfrav1.ExistingInfraMachineList
	err := a.Client.List(ctx, &machines)
	if err != nil {
		return nil, gerrors.Wrap(err, "failed to list machines")
	}
	for _, machine := range machines.Items {
		if machine.Spec.Private.Address == addr {
			return &machine, nil
		}
	}
	return nil, fmt.Errorf("Could not locate machine with private address: %s", addr)
}

// getNodePrivateAddress looks through the addresses for a node and extracts the private address
func getNodePrivateAddress(node *corev1.Node) string {
	for _, addr := range node.Status.Addresses {
		if addr.Type == "InternalIP" {
			return addr.Address
		}
	}
	return ""
}

func (a *ExistingInfraMachineReconciler) getMasterNodes(ctx context.Context) ([]*corev1.Node, error) {
	var nodes corev1.NodeList
	err := a.Client.List(ctx, &nodes)
	if err != nil {
		return nil, gerrors.Wrap(err, "failed to list nodes")
	}
	masters := []*corev1.Node{}
	for _, node := range nodes.Items {
		if isMaster(&node) {
			n := node
			masters = append(masters, &n)
		}
	}
	return masters, nil
}

func (a *ExistingInfraMachineReconciler) getControllerNode(ctx context.Context) (*corev1.Node, error) {
	name, err := a.getControllerNodeName(ctx)
	if err != nil {
		return nil, err
	}
	nodes, err := a.getMasterNodes(ctx)
	if err != nil {
		return nil, err
	}
	for _, node := range nodes {
		if node.Name == name {
			return node, nil
		}
	}
	return nil, errors.New("Could not find controller node")
}

func (a *ExistingInfraMachineReconciler) isControllerNode(ctx context.Context, node *corev1.Node) (bool, error) {
	name, err := a.getControllerNodeName(ctx)
	if err != nil {
		return false, err
	}
	return node.Name == name, nil
}

func (a *ExistingInfraMachineReconciler) getControllerNodeName(ctx context.Context) (string, error) {
	var pods corev1.PodList
	err := a.Client.List(ctx, &pods, &client.ListOptions{Namespace: a.controllerNamespace})
	if err != nil {
		return "", err
	}
	for _, pod := range pods.Items {
		if pod.Labels["name"] == controllerName {
			return pod.Spec.NodeName, nil
		}
	}
	return "", err
}

func isMaster(node *corev1.Node) bool {
	_, isMaster := node.Labels[masterLabel]
	return isMaster
}

func getInternalAddress(node *corev1.Node) (string, error) {
	for _, address := range node.Status.Addresses {
		if address.Type == "InternalIP" {
			return address.Address, nil
		}
	}
	return "", errors.New("no InternalIP address found")
}

func (a *ExistingInfraMachineReconciler) recordEvent(object runtime.Object, eventType, reason, messageFmt string, args ...interface{}) {
	a.eventRecorder.Eventf(object, eventType, reason, messageFmt, args...)
	switch eventType {
	case corev1.EventTypeWarning:
		log.Warnf(messageFmt, args...)
	case corev1.EventTypeNormal:
		log.Infof(messageFmt, args...)
	default:
		log.Debugf(messageFmt, args...)
	}
}

func (a *ExistingInfraMachineReconciler) getMachineAddress(m *existinginfrav1.ExistingInfraMachine) string {
	return m.Spec.Private.Address
}

func (a *ExistingInfraMachineReconciler) SetupWithManagerOptions(mgr ctrl.Manager, options controller.Options) error {
	controller, err := ctrl.NewControllerManagedBy(mgr).
		WithOptions(options).
		For(&existinginfrav1.ExistingInfraMachine{}).
		Watches(
			&source.Kind{Type: &clusterv1.Machine{}},
			&handler.EnqueueRequestsFromMapFunc{
				ToRequests: util.MachineToInfrastructureMapFunc(existinginfrav1.GroupVersion.WithKind("ExistingInfraMachine")),
			},
		).
		Watches(
			// Process changes to a cluster spec that affect the machines; look up machines in config map
			// and queue them for reconcile when the cluster spec changes
			&source.Kind{Type: &existinginfrav1.ExistingInfraCluster{}},
			&handler.EnqueueRequestsFromMapFunc{
				ToRequests: MachineMapper{reconciler: a},
			},
		).
		// TODO: add watch to reconcile all machines that need it
		WithEventFilter(pausedPredicates()).
		Build(a)

	if err != nil {
		return err
	}
	_ = controller // not currently using it here, but it will run in the background
	return nil
}

func (a *ExistingInfraMachineReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return a.SetupWithManagerOptions(mgr, controller.Options{})
}

type MachineMapper struct {
	reconciler *ExistingInfraMachineReconciler
}

// Map processes changes to a cluster spec that affect the machines; look up machines in config map
// and queue them for reconcile when the cluster spec changes
func (m MachineMapper) Map(mo handler.MapObject) []reconcile.Request {
	ctx := context.Background()
	ns := mo.Meta.GetNamespace()
	name := mo.Meta.GetName()
	eic := &existinginfrav1.ExistingInfraCluster{}
	err := m.reconciler.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, eic)
	if err != nil {
		return nil
	}
	cmap, err := m.reconciler.getClusterConfigMap(ctx, eic)
	if err != nil {
		return nil
	}

	// Check if the cluster spec has changed
	specBytes, err := json.Marshal(eic.Spec)
	if err != nil {
		return nil
	}
	hash := sha256.Sum256(specBytes)
	specByteHash := base64.StdEncoding.EncodeToString(hash[:])
	existingSpecHash := cmap.Data["spec"]
	if len(specByteHash) == len(existingSpecHash) {
		differ := false
		for idx := range specByteHash {
			if specByteHash[idx] != existingSpecHash[idx] {
				differ = true
				break
			}
		}
		if !differ {
			return nil
		}
	}
	log.Info("Cluster configuration changed; marking machines as needing repaving")
	if err := m.reconciler.updateAPIServerArgs(ctx, &eic.Spec.APIServer.ExtraArguments); err != nil {
		log.Errorf("failed to update API server args: %v", err)
		return nil
	}

	// Find the machines needing update and mark them
	var machines existinginfrav1.ExistingInfraMachineList
	if err := m.reconciler.Client.List(ctx, &machines); err != nil {
		log.Errorf("failed to list machines: %v", err)
		return nil
	}

	result := []reconcile.Request{}
	for _, machine := range machines.Items {
		privateAddress := machine.Spec.Private.Address
		log.Infof("Marking: %s for repaving", privateAddress)
		node, err := m.reconciler.findNodeByPrivateAddress(ctx, privateAddress)
		if err != nil {
			log.Errorf("Couldn't find node matching machine: %s", machine.Name)
			continue
		}
		m.reconciler.setNodeAnnotation(ctx, node.Name, recipe.PlanKey, `{"cluster": "modified"}`)
		result = append(result, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: machine.Namespace, Name: machine.Name}})
	}

	// Update the config map with the new spec
	if err := m.reconciler.updateConfigMap(ctx, m.reconciler.controllerNamespace, eic.Name, func(configMap *v1.ConfigMap) error {
		configMap.Data["spec"] = specByteHash
		return nil
	}); err != nil {
		log.Errorf("Failed to update cluster config map: %v", err)
		return nil
	}

	return result
}

// updateAPIServerArgs updates the kubeadm-config config map with new apiserver arguments so that control plane nodes will pick them
// up when repaved.
func (a *ExistingInfraMachineReconciler) updateAPIServerArgs(ctx context.Context, apiServerArgs *[]existinginfrav1.ServerArgument) error {
	log.Infof("In updateAPIServerArgs: %v", *apiServerArgs)
	var configMap v1.ConfigMap
	if err := a.Client.Get(ctx, types.NamespacedName{Namespace: "kube-system", Name: "kubeadm-config"}, &configMap); err != nil {
		if kerrors.IsNotFound(err) {
			log.Info("No config map found")
			return nil
		}
		log.Info("Failed to retrieve config map")
		return err
	}
	log.Infof("After getting config map: %v", configMap)
	config := configMap.Data["ClusterConfiguration"]
	var confobj map[string]interface{}
	if err := yaml.Unmarshal([]byte(config), &confobj); err != nil {
		return err
	}
	log.Infof("After unmarshaling configuration: %v", confobj)
	apiServerData := confobj["apiServer"]
	if apiServerData == nil {
		apiServer := map[string]interface{}{}
		confobj["apiServer"] = apiServer
	}
	apiServer := apiServerData.(map[string]interface{})
	extraArgs := apiServer["extraArgs"]
	if extraArgs == nil {
		extraArgs = map[string]interface{}{}
		apiServer["extraArgs"] = extraArgs
	}
	emap := extraArgs.(map[string]interface{})
	for _, serverArg := range *apiServerArgs {
		emap[serverArg.Name] = serverArg.Value
	}
	apiServer["extraArgs"] = extraArgs
	bytes, err := yaml.Marshal(confobj)
	if err != nil {
		return err
	}
	return a.updateConfigMap(ctx, "kube-system", "kubeadm-config", func(configMap *v1.ConfigMap) error {
		configMap.Data["ClusterConfiguration"] = string(bytes)
		return nil
	})
}

// updateConfigMap updates a config map with retries for conflicts
func (a *ExistingInfraMachineReconciler) updateConfigMap(ctx context.Context, namespace, name string, updater func(*v1.ConfigMap) error) error {
	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var result v1.ConfigMap
		getErr := a.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &result)
		if getErr != nil {
			log.Errorf("failed to read config map, can't reschedule: %v", getErr)
			return getErr
		}
		if err := updater(&result); err != nil {
			log.Errorf("failed to update cluster: %v", err)
			return err
		}
		updateErr := a.Client.Update(ctx, &result)
		if updateErr != nil {
			log.Errorf("failed to reschedule config map: %v", updateErr)
			return updateErr
		}
		return nil
	})
	if retryErr != nil {
		log.Errorf("failed to update config map: %v", retryErr)
		return retryErr
	}
	return nil
}

// MachineControllerParams groups required inputs to create a machine actuator.
type MachineControllerParams struct {
	Client              client.Client
	Log                 logr.Logger
	Scheme              *runtime.Scheme
	ClientSet           *kubernetes.Clientset
	ControllerNamespace string
	EventRecorder       record.EventRecorder
	Verbose             bool
}

func NewMachineControllerWithLegacyParams(params *MachineControllerParams) *ExistingInfraMachineReconciler {
	return &ExistingInfraMachineReconciler{
		Client:              params.Client,
		Log:                 params.Log,
		Scheme:              params.Scheme,
		clientSet:           params.ClientSet,
		controllerNamespace: params.ControllerNamespace,
		eventRecorder:       params.EventRecorder,
		verbose:             params.Verbose,
	}
}

func (a *ExistingInfraMachineReconciler) kubeadmCertsExists(ctx context.Context) (bool, error) {
	namespace := "kube-system"
	name := "kubeadm-certs"
	kubeadmCertsSecret := &corev1.Secret{}
	err := a.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, kubeadmCertsSecret)
	if err != nil {
		return false, err
	}
	return true, nil
}
