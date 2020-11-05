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

package main

import (
	"flag"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	clusterv1alpha3 "sigs.k8s.io/cluster-api/api/v1alpha3"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	baremetalproviderspecv1alpha1 "github.com/weaveworks/cluster-api-provider-existinginfra/apis/baremetalproviderspec/v1alpha1"
	clusterweaveworksv1alpha3 "github.com/weaveworks/cluster-api-provider-existinginfra/apis/cluster.weave.works/v1alpha3"
	clusterweaveworkscontroller "github.com/weaveworks/cluster-api-provider-existinginfra/controllers/cluster.weave.works"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")

	// TODO: Concurrent reconciliations should not be limited, remove this when
	//  the ExistingInfra{Cluster,Machine} reconcilers have been refactored
	opts = controller.Options{MaxConcurrentReconciles: 1}
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(clusterv1alpha3.AddToScheme(scheme))

	utilruntime.Must(clusterweaveworksv1alpha3.AddToScheme(scheme))
	utilruntime.Must(baremetalproviderspecv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	// kubebuilder-generated flags
	var metricsAddr string
	var enableLeaderElection bool
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")

	// TODO: Legacy flags, these should be removed
	var verbose bool
	var providerName string
	flag.BoolVar(&verbose, "verbose", false, "Verbose log output [legacy].")
	flag.StringVar(&providerName, "provider-name", "wksctl", "The provider name for the controllers [legacy].")

	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	// Get the controller's namespace via downward API
	namespace := os.Getenv("POD_NAMESPACE")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "06d8e7cb.",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	cfg, err := config.GetConfig()
	if err != nil {
		setupLog.Error(err, "failed to get the coordinates of the API server")
		os.Exit(1)
	}

	clientSet, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		setupLog.Error(err, "failed to create Kubernetes client set")
		os.Exit(1)
	}

	if err = (&clusterweaveworkscontroller.ExistingInfraClusterReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("ExistingInfraCluster"),
		Scheme: mgr.GetScheme(),
		// TODO: The ControllerNamespace is originally obtained from some machines in wksctl,
		//  which is not portable for CAPEI. That needs to be changed as well.
		ControllerNamespace: namespace,
		EventRecorder:       mgr.GetEventRecorderFor(providerName + "-controller"),
	}).SetupWithManagerOptions(mgr, opts); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ExistingInfraCluster")
		os.Exit(1)
	}
	// TODO: Ported from wksctl, should be refactored
	if err = clusterweaveworkscontroller.NewMachineControllerWithLegacyParams(&clusterweaveworkscontroller.MachineControllerParams{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("ExistingInfraMachine"),
		Scheme: mgr.GetScheme(),
		// TODO: "Legacy" fields below, should be refactored/removed
		EventRecorder: mgr.GetEventRecorderFor(providerName + "-controller"),
		ClientSet:     clientSet,
		// TODO: The ControllerNamespace is originally obtained from some machines in wksctl,
		//  which is not portable for CAPEI. That needs to be changed as well.
		ControllerNamespace: namespace,
		Verbose:             verbose,
	}).SetupWithManagerOptions(mgr, opts); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ExistingInfraMachine")
		os.Exit(1)
	}
	if err = (&clusterweaveworkscontroller.ExistingInfraBootstrapReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("ExistingInfraBootstrap"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ExistingInfraBootstrap")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
