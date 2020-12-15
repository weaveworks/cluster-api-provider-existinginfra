package kubeadm

// Tells which images to retrieve and where to retrieve them for DNS, Etcd, and Kubernetes
type AssetDescription struct {
	ImageRepository string `json:"imageRepository,omitempty"`
	ImageTag        string `json:"imageTag,omitempty"`
}
