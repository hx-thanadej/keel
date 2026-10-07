package promotion

import (
	"bytes"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Image is one image of a Release.
type Image struct {
	Name   string `json:"name"`   // e.g. ccr.ccs.tencentyun.com/tat/crm-api
	Digest string `json:"digest"` // sha256:...
}

// PatchKustomization pins each image's digest in a kustomization.yaml
// `images:` list, keeping comments and order; a newTag on a pinned image is
// removed so the digest wins. Images not yet listed are appended.
func PatchKustomization(src []byte, images []Image) ([]byte, bool, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, false, fmt.Errorf("parse kustomization: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, false, fmt.Errorf("kustomization is not a mapping")
	}
	root := doc.Content[0]
	var list *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "images" {
			list = root.Content[i+1]
		}
	}
	if list == nil {
		list = &yaml.Node{Kind: yaml.SequenceNode}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "images"}, list)
	}
	if list.Kind != yaml.SequenceNode {
		return nil, false, fmt.Errorf("images is not a list")
	}
	changed := false
	for _, img := range images {
		var entry *yaml.Node
		for _, e := range list.Content {
			if e.Kind == yaml.MappingNode && field(e, "name") == img.Name {
				entry = e
			}
		}
		if entry == nil {
			entry = &yaml.Node{Kind: yaml.MappingNode}
			set(entry, "name", img.Name)
			list.Content = append(list.Content, entry)
			changed = true
		}
		if field(entry, "digest") != img.Digest {
			set(entry, "digest", img.Digest)
			changed = true
		}
		if remove(entry, "newTag") {
			changed = true
		}
	}
	if !changed {
		return src, false, nil
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, false, err
	}
	_ = enc.Close()
	out := buf.Bytes()
	if !strings.HasSuffix(string(src), "\n") {
		out = bytes.TrimSuffix(out, []byte("\n"))
	}
	return out, true, nil
}

func field(m *yaml.Node, k string) string {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == k {
			return m.Content[i+1].Value
		}
	}
	return ""
}

func set(m *yaml.Node, k, v string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == k {
			m.Content[i+1].Value, m.Content[i+1].Tag, m.Content[i+1].Kind = v, "!!str", yaml.ScalarNode
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: k}, &yaml.Node{Kind: yaml.ScalarNode, Value: v})
}

func remove(m *yaml.Node, k string) bool {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == k {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return true
		}
	}
	return false
}
