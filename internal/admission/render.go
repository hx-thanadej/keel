// Package admission renders and delivers each Environment's Kubernetes
// admission policies (#113, ADR-0010): images must be digests from the
// Project's registry namespace, signed by Keel's builder with SLSA
// provenance. Kyverno ImageValidatingPolicy checks signatures; a
// ValidatingAdmissionPolicy rejects tag references. Rollout is warn, then
// enforce, per Environment; policies reach clusters through the config
// repository like any other change (ADR-0008).
package admission

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"text/template"
)

// Params are the per-Environment inputs.
type Params struct {
	Project, Environment string // slugs, also the namespace labels
	Registry             string // e.g. acme.tencentcloudcr.com
	Namespace            string // the Project's registry namespace
	BuilderSubject       string // e.g. https://github.com/acme/keel-workflows/.github/workflows/keel-build.yml@*
	Mode                 string // warn | enforce
	RekorURL             string // transparency log; default public-good
}

const policies = `# Managed by Keel ({{.Version}}). Do not edit: changes are made in Keel and arrive by pull request.
# Environment {{.Project}}/{{.Environment}}, mode {{.Mode}}.
apiVersion: policies.kyverno.io/v1
kind: ImageValidatingPolicy
metadata:
  name: keel-{{.Project}}-{{.Environment}}-images
  labels:
    app.kubernetes.io/managed-by: keel
spec:
  validationActions: [{{if eq .Mode "enforce"}}Deny{{else}}Audit{{end}}]
  webhookConfiguration:
    timeoutSeconds: 15
  matchConstraints:
    namespaceSelector:
      matchLabels:
        keel.dev/project: {{.Project}}
        keel.dev/environment: {{.Environment}}
    resourceRules:
      - apiGroups: [""]
        apiVersions: [v1]
        operations: [CREATE, UPDATE]
        resources: [pods]
  matchImageReferences:
    - glob: "{{.Registry}}/{{.Namespace}}/*"
  validationConfigurations:
    mutateDigest: false
    verifyDigest: true
    required: true
  attestors:
    - name: builder
      cosign:
        keyless:
          identities:
            - subject: "{{.BuilderSubject}}"
              issuer: https://token.actions.githubusercontent.com
        ctlog:
          url: {{.RekorURL}}
  attestations:
    - name: slsa
      intoto:
        type: https://slsa.dev/provenance/v1
  validations:
    - expression: >-
        images.containers.map(image, verifyImageSignatures(image, [attestors.builder])).all(e, e > 0)
      message: image is not signed by Keel's builder
    - expression: >-
        images.containers.map(image, verifyAttestationSignatures(image, attestations.slsa, [attestors.builder])).all(e, e > 0)
      message: image has no SLSA provenance from Keel's builder
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: keel-{{.Project}}-{{.Environment}}-digests
  labels:
    app.kubernetes.io/managed-by: keel
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: [v1]
        operations: [CREATE, UPDATE]
        resources: [pods]
  validations:
    - expression: >-
        object.spec.containers.all(c, c.image.contains('@sha256:')) &&
        (!has(object.spec.initContainers) || object.spec.initContainers.all(c, c.image.contains('@sha256:'))) &&
        (!has(object.spec.ephemeralContainers) || object.spec.ephemeralContainers.all(c, c.image.contains('@sha256:')))
      message: images must be referenced by digest (image@sha256:...), not by tag
    - expression: >-
        object.spec.containers.all(c, c.image.startsWith('{{.Registry}}/{{.Namespace}}/'))
      message: images must come from {{.Registry}}/{{.Namespace}}
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: keel-{{.Project}}-{{.Environment}}-digests
  labels:
    app.kubernetes.io/managed-by: keel
spec:
  policyName: keel-{{.Project}}-{{.Environment}}-digests
  validationActions: [{{if eq .Mode "enforce"}}Deny{{else}}Warn, Audit{{end}}]
  matchResources:
    namespaceSelector:
      matchLabels:
        keel.dev/project: {{.Project}}
        keel.dev/environment: {{.Environment}}
`

var tmpl = template.Must(template.New("admission").Parse(policies))

// Version names the rendered policy set.
const Version = "keel-admission@1"

// Render returns the multi-document YAML and its content hash.
func Render(p Params) ([]byte, string, error) {
	if p.Mode != "warn" && p.Mode != "enforce" {
		return nil, "", fmt.Errorf("mode %q is not warn or enforce", p.Mode)
	}
	if p.Registry == "" || p.Namespace == "" || p.BuilderSubject == "" {
		return nil, "", fmt.Errorf("registry, namespace and builder are required")
	}
	if p.RekorURL == "" {
		p.RekorURL = "https://rekor.sigstore.dev"
	}
	var b bytes.Buffer
	if err := tmpl.Execute(&b, struct {
		Params
		Version string
	}{p, Version}); err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(b.Bytes())
	return b.Bytes(), hex.EncodeToString(sum[:8]), nil
}
