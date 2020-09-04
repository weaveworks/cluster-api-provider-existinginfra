package version

import (
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/version"
)

func Jump(nodeVersion, machineVersion string) (bool, error) {
	nodemajor, nodeminor, err := parseVersion(nodeVersion)
	if err != nil {
		return false, err
	}
	machinemajor, machineminor, err := parseVersion(machineVersion)
	if err != nil {
		return false, err
	}
	return machinemajor == nodemajor && machineminor-nodeminor > 1, nil
}

func LessThan(s1, s2 string) (bool, error) {
	v1, err := version.ParseSemantic(s1)
	if err != nil {
		return false, err
	}
	v2, err := version.ParseSemantic(s2)
	if err != nil {
		return false, err
	}
	return v1.LessThan(v2), nil
}

func parseVersion(s string) (int, int, error) {
	v, err := version.ParseSemantic(s)
	if err != nil {
		return -1, -1, errors.Wrap(err, "invalid kubernetes version")
	}
	return int(v.Major()), int(v.Minor()), nil
}
