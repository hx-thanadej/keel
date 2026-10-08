package apply

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/hx-thanadej/keel/internal/rightsize"
)

// Schedule is a working window: the workload runs with Replicas between
// Start and Stop (whole local hours, Stop may be 24) on Days ("Mon–Fri" or
// "Daily") in TimeZone, and scales to zero otherwise.
type Schedule struct {
	Workload, Namespace, Kind string // Kind is Deployment or StatefulSet
	TimeZone, Days            string
	Start, Stop, Replicas     int
}

// ScaledObject renders a KEDA ScaledObject whose cron trigger keeps the
// workload at its current replicas during the window and at zero outside it.
func ScaledObject(s Schedule) ([]byte, error) {
	dow := map[string]string{"Mon–Fri": "1-5", "Daily": "*"}[s.Days]
	if dow == "" || s.Start < 0 || s.Stop <= s.Start || s.Stop > 24 || s.Replicas < 1 {
		return nil, fmt.Errorf("invalid schedule %+v", s)
	}
	end := fmt.Sprintf("0 %d * * %s", s.Stop, dow)
	if s.Stop == 24 {
		end = "59 23 * * " + dow
	}
	type meta struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace,omitempty"`
	}
	type ref struct {
		APIVersion string `yaml:"apiVersion,omitempty"`
		Kind       string `yaml:"kind,omitempty"`
		Name       string `yaml:"name"`
	}
	type cron struct {
		Timezone        string `yaml:"timezone"`
		Start           string `yaml:"start"`
		End             string `yaml:"end"`
		DesiredReplicas string `yaml:"desiredReplicas"`
	}
	type trigger struct {
		Type     string `yaml:"type"`
		Metadata cron   `yaml:"metadata"`
	}
	type spec struct {
		ScaleTargetRef  ref       `yaml:"scaleTargetRef"`
		MinReplicaCount int       `yaml:"minReplicaCount"`
		Triggers        []trigger `yaml:"triggers"`
	}
	target := ref{Name: s.Workload}
	if s.Kind == "StatefulSet" { // KEDA targets Deployments by default
		target.APIVersion, target.Kind = "apps/v1", "StatefulSet"
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	err := enc.Encode(struct {
		APIVersion string `yaml:"apiVersion"`
		Kind       string `yaml:"kind"`
		Metadata   meta   `yaml:"metadata"`
		Spec       spec   `yaml:"spec"`
	}{"keda.sh/v1alpha1", "ScaledObject", meta{Name: s.Workload + "-offhours", Namespace: s.Namespace}, spec{
		ScaleTargetRef: target, MinReplicaCount: 0,
		Triggers: []trigger{{Type: "cron", Metadata: cron{Timezone: s.TimeZone, Start: fmt.Sprintf("0 %d * * %s", s.Start, dow), End: end, DesiredReplicas: strconv.Itoa(s.Replicas)}}},
	}})
	if err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var scalableKinds = map[string]bool{"Deployment": true, "StatefulSet": true}

// offHoursSchedule adds a KEDA ScaledObject next to the workload's
// manifest. The workload's own manifest is never changed. The engine never
// schedules production, but the Environment is checked again here so a
// stale or hand-made recommendation can't either.
func (a Applier) offHoursSchedule(ctx context.Context, tenant string, r rightsize.Recommendation) (change, error) {
	workload, _ := r.Evidence["workload"].(string)
	namespace, _ := r.Evidence["namespace"].(string)
	sched, _ := r.Recommended["schedule"].(map[string]any)
	zone, _ := sched["timezone"].(string)
	days, _ := sched["days"].(string)
	start, startErr := hour(sched["start"])
	stop, stopErr := hour(sched["stop"])
	replicas, _ := r.Current["replicas"].(float64)
	if workload == "" || namespace == "" || zone == "" || days == "" || startErr != nil || stopErr != nil || replicas < 1 || r.ProjectID == nil {
		return change{}, fmt.Errorf("%w: the recommendation lacks workload/namespace/schedule details", ErrUnsupported)
	}
	if r.EnvironmentID == nil {
		return change{}, fmt.Errorf("%w: the recommendation has no Environment, so Keel can't confirm it is not production", ErrUnsupported)
	}
	switch prod, err := a.Recs.IsProduction(ctx, tenant, *r.EnvironmentID); {
	case err != nil:
		return change{}, err
	case prod:
		return change{}, fmt.Errorf("%w: Keel never schedules production workloads to scale to zero", ErrUnsupported)
	}
	t, err := a.target(ctx, tenant, r, workload)
	if err != nil {
		return change{}, err
	}
	m, err := a.manifest(ctx, t, scalableKinds, workload, namespace)
	if err != nil {
		return change{}, err
	}
	c := change{repo: t.repo, base: t.base, branch: "keel/offhours", path: path.Join(path.Dir(m.path), "keda-offhours-"+workload+".yaml")}
	s := Schedule{Workload: workload, Namespace: namespace, Kind: m.kind, TimeZone: zone, Days: days, Start: start, Stop: stop, Replicas: int(replicas)}
	if slices.Contains(t.files, c.path) {
		return change{}, fmt.Errorf("%w: %s already exists in %s", ErrUnsupported, c.path, t.repo)
	}
	if c.content, err = ScaledObject(s); err != nil {
		return change{}, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	text, _ := sched["text"].(string)
	c.title = fmt.Sprintf("Off-hours schedule for %s: %s", workload, text)
	c.body = fmt.Sprintf("Scale `%s` to zero outside %s and back to %d replica(s) inside it, with a KEDA `ScaledObject` cron trigger in `%s`. "+
		"The workload's own manifest is unchanged.\n\n"+
		"**Requires KEDA installed in the cluster.** KEDA manages the replica count through an HPA it creates; remove any existing HorizontalPodAutoscaler for this workload first.\n\n"+
		"**Expected saving:** about %s %s/month (%s cost), **only if node autoscaling (the cluster autoscaler) removes the idle nodes**; otherwise the nodes keep billing.\n\n"+
		"**Evidence:** %v days, %v off hours a week, %v replica(s). Confidence %.2f.\n\n"+
		"Merge to apply; Keel marks the recommendation applied and tracks realised savings.",
		workload, text, s.Replicas, c.path, r.MonthlySavings, r.Currency, r.SavingsBasis,
		r.Evidence["lookback_days"], r.Evidence["off_hours_per_week"], r.Evidence["replicas"], r.Confidence)
	return c, nil
}

// hour parses "HH:00".
func hour(v any) (int, error) {
	s, _ := v.(string)
	h, ok := strings.CutSuffix(s, ":00")
	if !ok {
		return 0, fmt.Errorf("not a whole hour: %q", s)
	}
	return strconv.Atoi(h)
}
