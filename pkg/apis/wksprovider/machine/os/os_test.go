package os

import (
	"strings"
	"testing"

	"github.com/pmezard/go-difflib/difflib"
)

func TestUpdateControllerImage(t *testing.T) {
	type args struct {
		manifest                string
		controllerImageOverride string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "basic",
			args: args{
				manifest:                controllerTestManifest,
				controllerImageOverride: "test:v0.1.0",
			},
			want: strings.Replace(controllerTestManifest, "test:v0.0.6", "test:v0.1.0", -1),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UpdateControllerImage([]byte(tt.args.manifest), tt.args.controllerImageOverride)
			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateControllerImage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if string(got) != tt.want {
				t.Errorf("%s", diff(tt.want, string(got)))
			}
		})
	}
}

const controllerTestManifest = `apiVersion: apps/v1
kind: Deployment
metadata:
  creationTimestamp: null
spec:
  replicas: 1
  selector:
    matchLabels:
      name: wks-controller
  strategy: {}
  template:
    metadata:
      creationTimestamp: null
      labels:
        name: wks-controller
    spec:
      containers:
      - args:
        - --verbose
        env:
        - name: EXISTINGINFRA_CONTROLLER_IMAGE
          value: test:v0.0.6
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        image: test:v0.0.6
        imagePullPolicy: Always
        name: controller
        resources: {}
status: {}
`

func diff(want, have string) string {
	text, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(want),
		B:        difflib.SplitLines(have),
		FromFile: "want",
		ToFile:   "have",
		Context:  3,
	})
	return text
}
