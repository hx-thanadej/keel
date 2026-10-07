// Package apply turns accepted Rightsizing Recommendations into pull
// requests against the Service's configuration, never live changes (#74,
// ADR-0013).
package apply

import (
	"bytes"
	"errors"
	"io"

	"go.yaml.in/yaml/v3"
)

var workloadKinds = map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true}

// PatchRequests sets resources.requests (cpu, memory) of one container of
// one workload in a (multi-document) Kubernetes YAML file. It reports
// whether the workload and container were found. Other documents,
// containers and limits are left as they are.
func PatchRequests(src []byte, workload, container, cpu, memory string) ([]byte, bool, error) {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	var docs []*yaml.Node
	for {
		var n yaml.Node
		err := dec.Decode(&n)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, false, err
		}
		docs = append(docs, &n)
	}
	found := false
	for _, d := range docs {
		if len(d.Content) == 0 {
			continue
		}
		root := d.Content[0]
		if !workloadKinds[scalar(get(root, "kind"))] || scalar(get(get(root, "metadata"), "name")) != workload {
			continue
		}
		for _, c := range seq(get(get(get(get(root, "spec"), "template"), "spec"), "containers")) {
			if scalar(get(c, "name")) != container {
				continue
			}
			res := ensureMap(c, "resources")
			req := ensureMap(res, "requests")
			set(req, "cpu", cpu)
			set(req, "memory", memory)
			found = true
		}
	}
	if !found {
		return src, false, nil
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	for _, d := range docs {
		if err := enc.Encode(d); err != nil {
			return nil, false, err
		}
	}
	if err := enc.Close(); err != nil {
		return nil, false, err
	}
	return buf.Bytes(), true, nil
}

func get(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func seq(n *yaml.Node) []*yaml.Node {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}

func ensureMap(n *yaml.Node, key string) *yaml.Node {
	if v := get(n, key); v != nil && v.Kind == yaml.MappingNode {
		return v
	}
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, m)
	return m
}

func set(n *yaml.Node, key, value string) {
	if v := get(n, key); v != nil {
		v.Kind, v.Tag, v.Value, v.Style = yaml.ScalarNode, "!!str", value, 0
		return
	}
	n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
}
