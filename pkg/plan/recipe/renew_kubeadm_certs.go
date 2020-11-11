package recipe

import (
	"context"
	"fmt"
	"strings"

	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/plan/resource"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/utilities/object"
)

func BuildGetKubeadmCertKeyPlan(ctx context.Context, certificateKey *string) (*plan.Plan, error) {
	b := plan.NewBuilder()

	b.AddResource(
		"renew-certs:kubeadm-alpha-certs-cert-key",
		&resource.Run{
			Script: object.String("kubeadm alpha certs certificate-key"),
			Output: certificateKey},
	)
	*certificateKey = strings.TrimSuffix(*certificateKey, "\n")

	p, err := b.Plan()
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func BuildUploadKubeadmCertsPlan(ctx context.Context, certificateKey string) (*plan.Plan, error) {
	b := plan.NewBuilder()

	// run kubeadm init phase upload-certs --upload-certs and certificate key output to env var
	b.AddResource(
		"renew-certs:kubeadm-upload-certs",
		&resource.Run{Script: object.String(fmt.Sprintf("kubeadm init phase upload-certs --upload-certs --certificate-key=%s", certificateKey))})

	p, err := b.Plan()
	if err != nil {
		return nil, err
	}
	return &p, nil
}
