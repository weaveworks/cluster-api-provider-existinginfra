package manifest

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/weaveworks/libgitops/pkg/serializer"
)

const (
	namespaceYaml = `apiVersion: v1
kind: Namespace
metadata:
  name: foo
`
	secretYaml = `apiVersion: v1
kind: Secret
metadata:
  name: wks-controller-secrets
  namespace: system
type: Opaque
data:
  sshKey: "bXkgc2VjcmV0"
`
	secretJson = `{
    "apiVersion": "v1",
    "kind": "Secret",
    "metadata": {
        "name": "wks-controller-secrets",
        "namespace": "system"
    },
    "type": "Opaque",
    "data": {
        "sshKey": "bXkgc2VjcmV0"
    }
}`

	listYaml = `apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: Service
  metadata:
    name: test-list-service
    namespace: system
  spec:
    ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 80
    selector:
      app: test-list-service
- apiVersion: v1
  kind: Service
  metadata:
    name: test-list-service2
    namespace: system
  spec:
    ports:
    - name: httpproxy
      protocol: TCP
      port: 8080
      targetPort: 8080
    selector:
      app: test-list-service2
`

	rbacYaml = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wks-controller-role
rules:
- apiGroups:
  - cluster.k8s.io
  resources:
  - clusters
  - machines
  - machines/status
  - machinedeployments
  - machinesets
  verbs:
  - get
  - list
  - watch
  - create
  - update
  - patch
  - delete
- apiGroups:
  - ""
  resources:
  # pods/eviction is required for the WKS controller to be able to evict pods
  # upon machine deletions.
  - pods/eviction
  - pods
  - nodes
  - events
  - secrets
  verbs:
  - get
  - list
  - watch
  - create
  - update
  - patch
  - delete
# The below is required for the WKS controller to be able to delete daemonsets
# upon machine deletions.
- apiGroups:
  - apps
  resources:
  - daemonsets
  verbs:
  - get
  - delete
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: wks-controller-rolebinding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: wks-controller-role
subjects:
- kind: ServiceAccount
  name: default
  namespace: system
`
	clusteryaml = `apiVersion: cluster.x-k8s.io/v1alpha3
kind: Cluster
metadata:
  name: example
spec:
  clusterNetwork:
    services:
      cidrBlocks: [10.96.0.0/12]
    pods:
      cidrBlocks: [192.168.0.0/16]
    serviceDomain: cluster.local
    infrastructureRef:
      kind: ExistingInfraCluster
      name: example
---
apiVersion: cluster.weave.works/v1alpha3
kind: "ExistingInfraCluster"
metadata:
  name: example
spec:
      sshKeyPath: cluster-key
      user: root
      os:
        files:
        - source:
            configmap: repo
            key: kubernetes.repo
          destination: /etc/yum.repos.d/kubernetes.repo
        - source:
            configmap: repo
            key: docker-ce.repo
          destination: /etc/yum.repos.d/docker-ce.repo
        - source:
            configmap: docker
            key: daemon.json
          destination: /etc/docker/daemon.json
      cri:
        kind: docker
        package: docker-ce
        version: 19.03.8
`
	machinesyaml = `
  apiVersion: cluster.x-k8s.io/v1alpha3
  kind: Machine
  metadata:
    name: master-0
    labels:
      set: master
  spec:
    infrastructureRef:
      kind: ExistingInfraMachine
      name: master-0
---
  apiVersion: "cluster.weave.works/v1alpha3"
  kind: "ExistingInfraMachine"
  metadata:
    name: master-0
  spec:
        public:
          address: 127.0.0.1
          port: 2222
        private:
          address: 172.17.0.2
          port: 22
---
  apiVersion: cluster.x-k8s.io/v1alpha3
  kind: Machine
  metadata:
    name: node-0
    labels:
      set: node
  spec:
    infrastructureRef:
        kind: ExistingInfraMachine
        name: node-0
---
  apiVersion: "cluster.weave.works/v1alpha3"
  kind: "ExistingInfraMachine"
  metadata:
    name: node-0
  spec:
        public:
          address: 127.0.0.1
          port: 2223
        private:
          address: 172.17.0.3
          port: 22

`
	newNamespace = "testnamespace"

	imageUpdateYaml = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
        - name: nginx
          image: nginx:1.14.2
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
  labels:
    app: nginx
spec:
  containers:
    - name: nginx
      image: nginx:1.14.2
      ports:
        - containerPort: 80
---
apiVersion: v1
kind: List
items:
  - apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: nginx-deployment
      labels:
        app: nginx
    spec:
      replicas: 3
      selector:
        matchLabels:
          app: nginx
      template:
        metadata:
          labels:
            app: nginx
        spec:
          containers:
            - name: nginx
              image: nginx:1.14.2
              ports:
                - containerPort: 80
  - apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: nginx-deployment2
      labels:
        app: nginx
    spec:
      replicas: 3
      selector:
        matchLabels:
          app: nginx
      template:
        metadata:
          labels:
            app: nginx
        spec:
          containers:
            - name: nginx
              image: nginx:1.14.2
              ports:
                - containerPort: 80
`
	postProcessedImageUpdateYaml = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
        - name: nginx
          image: nginx:1.14.2-suffix628
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
  labels:
    app: nginx
spec:
  containers:
    - name: nginx
      image: nginx:1.14.2-suffix628
      ports:
        - containerPort: 80
---
apiVersion: v1
kind: List
items:
  - apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: nginx-deployment
      labels:
        app: nginx
    spec:
      replicas: 3
      selector:
        matchLabels:
          app: nginx
      template:
        metadata:
          labels:
            app: nginx
        spec:
          containers:
            - name: nginx
              image: nginx:1.14.2-suffix628
              ports:
                - containerPort: 80
  - apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: nginx-deployment2
      labels:
        app: nginx
    spec:
      replicas: 3
      selector:
        matchLabels:
          app: nginx
      template:
        metadata:
          labels:
            app: nginx
        spec:
          containers:
            - name: nginx
              image: nginx:1.14.2-suffix628
              ports:
                - containerPort: 80
`
)

func createFile(t *testing.T, content, fileName string) *os.File {
	cbytes := []byte(content)
	tmpfile, err := ioutil.TempFile("", fileName)
	assert.NoError(t, err)
	_, err = tmpfile.Write(cbytes)
	assert.NoError(t, err)
	err = tmpfile.Close()
	assert.NoError(t, err)
	return tmpfile
}

var nstests = []struct {
	name     string
	content  string
	fileName string
}{
	{"Kind:Namespace", namespaceYaml, "namespace.yaml"},
	{"Kind:Secret", secretYaml, "secret.yaml"},
	{"Kind:ServiceList", listYaml, "list.yaml"},
	{"Kind:SecretJson", secretJson, "secret.json"},
	{"Kinds:ClusterRoleAndBinding", rbacYaml, "rbac.yaml"},
	{"Kind:Cluster", clusteryaml, "cluster.yaml"},
	{"Kind:MachineList", machinesyaml, "machines.yaml"},
}

func TestManifestWithNamespace(t *testing.T) {
	for _, tt := range nstests {
		t.Run(tt.name, func(t *testing.T) {
			fname := createFile(t, tt.content, tt.fileName).Name()

			defer os.Remove(fname)

			updated, err := WithNamespace(serializer.FromFile(fname), newNamespace)
			assert.NoError(t, err)
			assert.NotEqual(t, tt.content, string(updated))
			assert.Contains(t, string(updated), newNamespace)
		})
	}
}

func TestImageSuffixUpdate(t *testing.T) {
	updated, err := WithImageTagUpdate(ioutil.NopCloser(bytes.NewReader([]byte(imageUpdateYaml))), func(tag string) (string, error) {
		return tag + "-suffix628", nil
	})
	assert.NoError(t, err)
	assert.Equal(
		t,
		string(updated),
		postProcessedImageUpdateYaml)
}
