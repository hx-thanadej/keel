package apply_test

import (
	"strings"
	"testing"

	"github.com/hx-thanadej/keel/internal/apply"
)

const manifests = `apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  ports:
    - port: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: tat-crm-prod
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: app
          image: ghcr.io/hx/api@sha256:abc
          resources:
            requests:
              cpu: 2000m
              memory: 4Gi
            limits:
              memory: 4Gi
        - name: sidecar
          image: envoy
          resources:
            requests:
              cpu: 100m
`

func TestPatchRequests(t *testing.T) {
	out, ok, err := apply.PatchRequests([]byte(manifests), "api", "tat-crm-prod", "app", "410m", "1531Mi")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	s := string(out)
	for _, want := range []string{"cpu: 410m", "memory: 1531Mi", "kind: Service", "name: sidecar", "cpu: 100m", "image: ghcr.io/hx/api@sha256:abc", "replicas: 2"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "cpu: 2000m") {
		t.Error("old request still present")
	}
	if !strings.Contains(s, "limits:\n              memory: 4Gi") {
		t.Errorf("limits must be untouched:\n%s", s)
	}
}

func TestPatchRequestsNoMatch(t *testing.T) {
	_, ok, err := apply.PatchRequests([]byte(manifests), "api", "tat-crm-prod", "nope", "1m", "1Mi")
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	_, ok, _ = apply.PatchRequests([]byte(manifests), "other", "tat-crm-prod", "app", "1m", "1Mi")
	if ok {
		t.Fatal("wrong workload matched")
	}
	_, ok, _ = apply.PatchRequests([]byte(manifests), "api", "tat-crm-dev", "app", "1m", "1Mi")
	if ok {
		t.Fatal("wrong namespace matched")
	}
}

func TestPatchRequestsAddsMissingResources(t *testing.T) {
	src := "apiVersion: apps/v1\nkind: StatefulSet\nmetadata:\n  name: db\n  namespace: data\nspec:\n  template:\n    spec:\n      containers:\n        - name: postgres\n          image: postgres:18\n"
	out, ok, err := apply.PatchRequests([]byte(src), "db", "data", "postgres", "500m", "1024Mi")
	if err != nil || !ok || !strings.Contains(string(out), "requests:") || !strings.Contains(string(out), "cpu: 500m") {
		t.Fatalf("ok=%v err=%v\n%s", ok, err, out)
	}
}
