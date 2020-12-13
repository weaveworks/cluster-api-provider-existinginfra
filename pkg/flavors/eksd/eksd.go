package eksd

import (
	"fmt"
	"io/ioutil"
	"net/http"

	distrov1alpha1 "github.com/aws/eks-distro-build-tooling/release/api/v1alpha1"
	gerrors "github.com/pkg/errors"
	"sigs.k8s.io/yaml"
)

// EKSD is used to wrap the eks-d manifest and provide helper functions
type EKSD struct {
	releaseURL string
	release    *distrov1alpha1.Release
}

// New create an instance of EKSD with the manifest from the URL argument
func New(eksdURL string) (*EKSD, error) {
	m, err := readRelease(eksdURL)
	if err != nil {
		return nil, gerrors.Wrap(err, fmt.Sprintf("failed to create EKSD using manifest %s", eksdURL))
	}
	return &EKSD{
		releaseURL: eksdURL,
		release:    m,
	}, nil
}

// KubeBinURL looks through the eksd manifest and locates the URL for the
// binary
func (e *EKSD) KubeBinURL(binName string) (string, string, error) {
	for _, c := range e.release.Status.Components {
		if c.Name == "kubernetes" {
			for _, a := range c.Assets {
				if a.Name == "bin/linux/amd64/"+binName {
					return a.Archive.URI, a.Archive.SHA256, nil
				}
			}
		}

	}
	return "", "", fmt.Errorf("Binary %s not find in release %v", binName, e.release.Spec)
}

// readRelease given a release URL this reads the yaml from the URL and converts to an EKS-D release
func readRelease(releaseURL string) (*distrov1alpha1.Release, error) {
	res, err := http.Get(releaseURL)
	if err != nil {
		return nil, err
	}
	data, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil, err
	}
	r := distrov1alpha1.Release{}
	err = yaml.Unmarshal([]byte(data), &r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}
