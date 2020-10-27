VERSION=$(shell git describe --always --match "v*")
IMAGE_TAG := $(shell tools/image-tag)
# Produce CRDs that work back to Kubernetes 1.11 (no version conversion)
CRD_OPTIONS ?= "crd"

API_ROOT := ./apis
API_DIRS := ${API_ROOT}/baremetalproviderspec/v1alpha1,${API_ROOT}/cluster.weave.works/v1alpha3

GOOS=$(shell go env GOOS)
GOARCH=$(shell go env GOARCH)

export KUBEBUILDER_ASSETS=$(shell pwd)/bin/kubebuilder

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

all: manager

# Run tests
unit-tests: generate fmt vet manifests $(KUBEBUILDER_ASSETS)
	go test -v ./pkg/... ./controllers/... -coverprofile cover.out -race -covermode=atomic

# Generate CRDs
CRDS=$(shell find config/crd -name '*.yaml' -print)
pkg/apis/wksprovider/machine/crds/crds_vfsdata.go: $(CRDS)
	go generate ./pkg/apis/wksprovider/machine/crds

# Build manager binary
manager: pkg/apis/wksprovider/machine/crds/crds_vfsdata.go generate fmt vet
	go build -ldflags "-X github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/version.Version=$(VERSION) -X github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/version.ImageTag=$(IMAGE_TAG)" -o bin/manager main.go

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet manifests
	go run ./main.go

# Install CRDs into a cluster
install: manifests
	kustomize build config/crd | kubectl apply -f -

# Uninstall CRDs from a cluster
uninstall: manifests
	kustomize build config/crd | kubectl delete -f -

# Clean up images and binaries
clean:
	rm -f bin/manager
	docker rmi -f weaveworks/cluster-api-existinginfra-controller:${IMAGE_TAG}

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy: manifests
	cd config/manager && kustomize edit set image controller=weaveworks/cluster-api-existinginfra-controller:${IMAGE_TAG}
	kustomize build config/default | kubectl apply -f -

# Generate manifests e.g. CRD, RBAC etc.
manifests: controller-gen
	$(CONTROLLER_GEN) $(CRD_OPTIONS) rbac:roleName=manager-role webhook paths="./..." output:crd:artifacts:config=config/crd/bases

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

# Generate code
generate: controller-gen conversion-gen
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."
	$(CONVERSION_GEN) \
		--output-base ../../. \
		--input-dirs ${API_DIRS} \
		-O zz_generated.conversion \
		-h hack/boilerplate.go.txt

# Build the docker image
docker-build: unit-tests
	docker build . -t weaveworks/cluster-api-existinginfra-controller:${IMAGE_TAG}

# Push the docker image
push: docker-build
	docker push weaveworks/cluster-api-existinginfra-controller:${IMAGE_TAG}

# find or download controller-gen
# download controller-gen if necessary
controller-gen:
ifeq (, $(shell which controller-gen))
	@{ \
	set -e ;\
	CONTROLLER_GEN_TMP_DIR=$$(mktemp -d) ;\
	cd $$CONTROLLER_GEN_TMP_DIR ;\
	go mod init tmp ;\
	go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.2.5 ;\
	rm -rf $$CONTROLLER_GEN_TMP_DIR ;\
	}
CONTROLLER_GEN=$(GOBIN)/controller-gen
else
CONTROLLER_GEN=$(shell which controller-gen)
endif

conversion-gen:
ifeq (, $(shell which conversion-gen))
	@{ \
	set -e ;\
	CONVERSION_GEN_TMP_DIR=$$(mktemp -d) ;\
	cd $$CONVERSION_GEN_TMP_DIR ;\
	go mod init tmp ;\
	go get k8s.io/code-generator/cmd/conversion-gen ;\
	rm -rf $$CONVERSION_GEN_TMP_DIR ;\
	}
CONVERSION_GEN=$(GOBIN)/conversion-gen
else
CONVERSION_GEN=$(shell which conversion-gen)
endif

$(KUBEBUILDER_ASSETS):
	mkdir -p $@
	curl -sSL https://go.kubebuilder.io/dl/2.3.1/$(GOOS)/$(GOARCH) | tar -xz --strip-components=2 -C $@
