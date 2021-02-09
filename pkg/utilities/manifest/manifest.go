package manifest

import (
	"bytes"
	"io"

	"github.com/weaveworks/libgitops/pkg/serializer"
	kyaml "sigs.k8s.io/kustomize/kyaml/yaml"
	k8syaml "sigs.k8s.io/yaml"
)

const (
	corev1Version    = "v1"
	listKind         = "List"
	namespaceKind    = "Namespace"
	podKind          = "Pod"
	DefaultNamespace = "weavek8sops"
)

var DefaultAddonNamespaces = map[string]string{"weave-net": "kube-system"}

// WithNamespace applies a specified namespace to each manifest in a '---' separated list
func WithNamespace(rc io.ReadCloser, namespace string) ([]byte, error) {
	// Create a FrameReader and FrameWriter, using YAML document separators
	// The FrameWriter will write into buf
	fr := serializer.NewYAMLFrameReader(rc)
	buf := new(bytes.Buffer)
	fw := serializer.NewYAMLFrameWriter(buf)

	// Read all frames from the FrameReader
	frames, err := serializer.ReadFrameList(fr)
	if err != nil {
		return nil, err
	}

	// If namespace is "", just write all the read frames to buf through the framewriter, and exit
	if namespace == "" {
		if err := serializer.WriteFrameList(fw, frames); err != nil {
			return nil, err
		}

		return buf.Bytes(), nil
	}

	// Loop through all the frames
	for _, frame := range frames {
		// Parse the given frame's YAML. JSON also works
		obj, err := kyaml.Parse(string(frame))
		if err != nil {
			return nil, err
		}

		// Get the TypeMeta of the given object
		meta, err := obj.GetMeta()
		if err != nil {
			return nil, err
		}

		// Use special handling for the v1.List, as we need to traverse each item in the .items list
		// Otherwise, just run setNamespaceOnObject for the parsed object
		if meta.APIVersion == corev1Version && meta.Kind == listKind {
			// Visit each item under .items
			if err := visitElementsForPath(obj, func(item *kyaml.RNode) error {
				// Set namespace on the given item
				return setNamespaceOnObject(item, namespace)

			}, "items"); err != nil {
				return nil, err
			}

		} else {
			// Set namespace on the given object
			if err := setNamespaceOnObject(obj, namespace); err != nil {
				return nil, err
			}
		}

		// Convert the object to string, and write it to the FrameWriter
		str, err := obj.String()
		if err != nil {
			return nil, err
		}
		if _, err := fw.Write([]byte(str)); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// WithImageTagUpdate updates all image tags in containers within a top-level resource description or list of descriptions
func WithImageTagUpdate(rc io.ReadCloser, updater func(string) (string, error)) ([]byte, error) {
	// Create a FrameReader and FrameWriter, using YAML document separators
	// The FrameWriter will write into buf
	fr := serializer.NewYAMLFrameReader(rc)
	buf := new(bytes.Buffer)
	fw := serializer.NewYAMLFrameWriter(buf)

	// Read all frames from the FrameReader
	frames, err := serializer.ReadFrameList(fr)
	if err != nil {
		return nil, err
	}

	for _, frame := range frames {
		// Parse the given frame's YAML. JSON also works
		obj, err := kyaml.Parse(string(frame))
		if err != nil {
			return nil, err
		}

		if err := processImageSuffixEntry(obj, updater); err != nil {
			return nil, err
		}

		// Convert the object to string, and write it to the FrameWriter
		str, err := obj.String()
		if err != nil {
			return nil, err
		}
		if _, err := fw.Write([]byte(str)); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func processImageSuffixEntry(obj *kyaml.RNode, updater func(string) (string, error)) error {
	// Get the TypeMeta of the given object
	meta, err := obj.GetMeta()
	if err != nil {
		return err
	}

	// Use special handling for the v1.List, as we need to traverse each item in the .items list
	// Otherwise, just run processImageSuffixEntry for the parsed object
	if meta.APIVersion == corev1Version && meta.Kind == listKind {
		// Visit each item under .items
		if err := visitElementsForPath(obj, func(item *kyaml.RNode) error {
			// Set image suffix on any images associated with the item
			return processImageSuffixEntry(item, updater)
		}, "items"); err != nil {
			return err
		}
	} else {
		// Update image tags if we're looking at a resource that includes container specifications

		// Check for resources containing pod spec templates
		updated, err := updateImage(obj, kyaml.Lookup("spec", "template", "spec", "containers"), updater)
		if err != nil {
			return err
		}

		if !updated {
			// Check for explicit pods
			meta, err := obj.GetMeta()
			if err != nil {
				return err
			}
			if meta.APIVersion == corev1Version && meta.Kind == podKind {
				if _, err := updateImage(obj, kyaml.Lookup("spec", "containers"), updater); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func updateImage(obj *kyaml.RNode, lookup kyaml.PathGetter, updater func(string) (string, error)) (bool, error) {
	node, err := obj.Pipe(lookup)
	if err != nil {
		return false, err
	}

	elems, err := node.Elements()
	if err != nil {
		return false, err
	}

	for _, container := range elems {
		existingTag, err := container.Pipe(kyaml.Get("image"))
		if err != nil {
			return false, err
		}
		updated, err := updater(existingTag.YNode().Value)
		if err != nil {
			return false, err
		}
		container.Pipe(kyaml.SetField("image", kyaml.NewScalarRNode(updated)))
		return true, nil
	}

	return false, nil
}

func setNamespaceOnObject(obj *kyaml.RNode, namespace string) error {
	// Get the TypeMeta of the given object
	meta, err := obj.GetMeta()
	if err != nil {
		return err
	}

	// The default namespaceFilter sets the "namespace" field (on the metadata object)
	// to the desired namespace
	namespaceFilter := setNamespaceFilter(namespace)
	// However, if the given object IS a Namespace, we set the "name" field to the desired
	// namespace name instead.
	if meta.APIVersion == corev1Version && meta.Kind == namespaceKind {
		namespaceFilter = kyaml.SetField("name", kyaml.NewScalarRNode(namespace))
	}

	// Lookup and create .metadata (if it doesn't exist), and set its
	// namespace field to the desired value
	err = obj.PipeE(
		kyaml.LookupCreate(kyaml.MappingNode, "metadata"),
		namespaceFilter,
	)
	if err != nil {
		return err
	}

	// Visit .subjects (if it exists), and traverse its elements, setting
	// the namespace field on each item
	return visitElementsForPath(obj, func(node *kyaml.RNode) error {
		return node.PipeE(setNamespaceFilter(namespace))
	}, "subjects")
}

func visitElementsForPath(obj *kyaml.RNode, fn func(node *kyaml.RNode) error, paths ...string) error {
	list, err := obj.Pipe(kyaml.Lookup(paths...))
	if err != nil {
		return err
	}
	return list.VisitElements(fn)
}

func setNamespaceFilter(ns string) kyaml.FieldSetter {
	return kyaml.SetField("namespace", kyaml.NewScalarRNode(ns))
}

// Marshal takes one or more struts and uses sig.k8s.io/yaml to
// convert into a string.  The conversion adheres to the json
// comments in the struct
func Marshal(objs ...interface{}) ([]byte, error) {
	var buf bytes.Buffer
	fw := serializer.NewYAMLFrameWriter(&buf)
	data := [][]byte{}
	for _, obj := range objs {
		value, err := k8syaml.Marshal(obj)
		if err != nil {
			return nil, err
		}
		data = append(data, value)
	}
	if err := serializer.WriteFrameList(fw, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
