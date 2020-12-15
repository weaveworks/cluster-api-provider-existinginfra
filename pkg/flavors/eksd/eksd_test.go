package eksd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestImageAndImageTag(t *testing.T) {
	// TODO replace with static text so we aren't relying on this URL
	e, err := New("https://distro.eks.amazonaws.com/kubernetes-1-18/kubernetes-1-18-eks-1.yaml")
	assert.NoError(t, err)
	tests := []struct {
		name    string
		expRepo string
		expTag  string
		expErr  bool
	}{
		{"etcd", "public.ecr.aws/eks-distro/etcd-io", "v3.4.14-eks-1-18-1", false},
		{"eTCd", "public.ecr.aws/eks-distro/etcd-io", "v3.4.14-eks-1-18-1", false},
		{"goober", "", "", true},
	}
	for _, test := range tests {
		repo, tag, err := e.ImageInfo(test.name)
		if test.expErr {
			assert.Error(t, err)
		} else {
			assert.Equal(t, test.expRepo, repo)
			assert.Equal(t, test.expTag, tag)
			assert.NoError(t, err)
		}
	}
}

func TestKubeBin(t *testing.T) {
	// TODO replace with static text so we aren't relying on this URL
	e, err := New("https://distro.eks.amazonaws.com/kubernetes-1-18/kubernetes-1-18-eks-1.yaml")
	assert.NoError(t, err)
	tests := []struct {
		name   string
		expErr bool
	}{
		{"kubelet", false},
		{"kubectl", false},
		{"goober", true},
	}
	for _, test := range tests {
		url, sha, err := e.KubeBinURL(test.name)
		if test.expErr {
			assert.Error(t, err)
		} else {
			assert.NotEqual(t, "", url)
			assert.NotEqual(t, "", sha)
			assert.NoError(t, err)
		}
	}
}

func TestKubeadmOverride(t *testing.T) {
	// TODO replace with static text so we aren't relying on this URL
	e, err := New("https://distro.eks.amazonaws.com/kubernetes-1-18/kubernetes-1-18-eks-1.yaml")
	assert.NoError(t, err)
	tests := []struct {
		name           string
		expManifestURL string
		expErr         bool
	}{
		{"kubeadm", "https://weaveworks-wkp.s3.amazonaws.com/eks-d/kubeadm", false},
	}
	for _, test := range tests {
		url, _, err := e.KubeBinURL(test.name)
		if test.expErr {
			assert.Error(t, err)
		} else {
			assert.NotEqual(t, "", url)
			assert.NoError(t, err)
		}
	}

}
