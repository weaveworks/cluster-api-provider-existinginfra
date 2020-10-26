package controllers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/weaveworks/cluster-api-provider-existinginfra/pkg/apis/wksprovider/machine/os"
	corev1 "k8s.io/api/core/v1"
	bootstrapapi "k8s.io/cluster-bootstrap/token/api"
)

func TestJoinTokenExpirationHandling(t *testing.T) {
	checks := []struct {
		nowOffset time.Duration
		exp       bool
		msg       string
	}{
		{nowOffset: (time.Hour * 1), exp: false, msg: "Token should be good for another hour"},
		{nowOffset: (time.Second * 1), exp: true, msg: "Token expires in 30 seconds"},
		{nowOffset: (time.Second * 59), exp: true, msg: "Token expires in 59 seconds"},
		{nowOffset: (time.Second * 61), exp: false, msg: "Token good for 61 seconds - expiration limit is 60"},
	}

	s := corev1.Secret{}
	for _, check := range checks {
		now := time.Now().Add(check.nowOffset)
		d := map[string][]byte{}
		d[bootstrapapi.BootstrapTokenExpirationKey] = []byte(now.Format(time.RFC3339))
		s.Data = d
		assert.Equal(t, check.exp, bootstrapTokenHasExpired(&s), check.msg)
	}
}

func TestMissingSSHkey(t *testing.T) {
	ip := "10.10.2.3"
	foundInfo := os.MachineInfo{PrivateIP: ip}
	info1 := os.MachineInfo{SSHUser: "1", PrivateIP: "1"}
	info2 := os.MachineInfo{SSHUser: "2", PrivateIP: "2"}
	info3 := os.MachineInfo{SSHUser: "3", PrivateIP: "3"}
	checks := []struct {
		mi       []os.MachineInfo
		ip       string
		i        os.MachineInfo
		hasError bool
		msg      string
	}{
		{mi: []os.MachineInfo{}, ip: "10.10.2.3", i: os.MachineInfo{}, hasError: true, msg: "No info objects"},
		{mi: []os.MachineInfo{foundInfo}, ip: ip, i: foundInfo, hasError: false, msg: "Matching info"},
		{mi: []os.MachineInfo{info1, info2, info3}, ip: ip, i: os.MachineInfo{}, hasError: true, msg: "No matching info and no common one"},
		{mi: []os.MachineInfo{info1, foundInfo, info2, info3}, ip: ip, i: foundInfo, hasError: false, msg: "Matching info in a list"},
		{mi: []os.MachineInfo{info1, info1, info1, info1}, ip: ip, i: info1, hasError: false, msg: "No matching info, but common info exists"},
		{mi: []os.MachineInfo{info1}, ip: ip, i: info1, hasError: false, msg: "No matching info, but common info exists"},
	}

	r := ExistingInfraMachineReconciler{}
	for _, check := range checks {
		t.Run(check.msg, func(t *testing.T) {
			i, err := r.getMachineInfoOrUseDefault(context.TODO(), &check.mi, check.ip)
			if check.hasError {
				assert.Error(t, err, check.msg)
			} else {
				assert.NoError(t, err, check.msg)
				assert.Equal(t, check.i, i, check.msg)
			}
		})
	}
}
