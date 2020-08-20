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
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	baremetalproviderspecv1alpha1 "github.com/weaveworks/cluster-api-provider-existinginfra/apis/baremetalproviderspec/v1alpha1"
	clusterweaveworksv1alpha3 "github.com/weaveworks/cluster-api-provider-existinginfra/apis/cluster.weave.works/v1alpha3"
	clusterweaveworkscontroller "github.com/weaveworks/cluster-api-provider-existinginfra/controllers/cluster.weave.works"
	// +kubebuilder:scaffold:imports
)

// TODO: Ported from wksctl, should be removed
const defaultNamespace = `weavek8sops`

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)

	_ = clusterweaveworksv1alpha3.AddToScheme(scheme)
	_ = baremetalproviderspecv1alpha1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var providerName string
	var enableLeaderElection bool
	var verbose bool
	// TODO: Get rid of the legacy flags
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&providerName, "provider-name", "wksctl", "The provider name for the controllers [legacy].")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&verbose, "verbose", false, "Verbose log output [legacy].")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

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
	}).SetupWithManagerOptions(mgr, controller.Options{MaxConcurrentReconciles: 1}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ExistingInfraCluster")
		os.Exit(1)
	}
	// TODO: Ported from wksctl, should be refactored
	if err = clusterweaveworkscontroller.NewMachineController(&clusterweaveworkscontroller.MachineControllerParams{
		EventRecorder: mgr.GetEventRecorderFor(providerName + "-controller"),
		Client:        mgr.GetClient(),
		Log:           ctrl.Log.WithName("controllers").WithName("ExistingInfraMachine"),
		ClientSet:     clientSet,
		// TODO: The ControllerNamespace is originally obtained from some machines in wksctl,
		//  which is not portable for CAPEI. This needs to be changed too.
		ControllerNamespace: defaultNamespace,
		Verbose:             verbose,
		Scheme:              mgr.GetScheme(),
	}).SetupWithManagerOptions(mgr, controller.Options{MaxConcurrentReconciles: 1}); err != nil {
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
