// Package cgroupsignals_test checks the chart's rendered DaemonSet against the
// contract in values.yaml and the README: the pod runs as root with a
// read-only root filesystem and no capability, mounts the host's cgroupfs
// read-write, reads no API token, and is pinned to the image by digest. A
// template that drops one of them fails here.
package cgroupsignals_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type object = map[string]any

func get(o any, path ...string) any {
	for _, p := range path {
		m, ok := o.(object)
		if !ok {
			return nil
		}
		o = m[p]
	}
	return o
}

func render(t *testing.T, file string) []object {
	t.Helper()
	data, err := os.ReadFile(file) // rules_go runs a test in its package's directory
	if err != nil {
		t.Fatal(err)
	}
	var out []object
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var o object
		err := dec.Decode(&o)
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if o != nil {
			out = append(out, o)
		}
	}
}

// daemonSet is the one object the chart renders, after checking that nothing
// else is: no Service, ServiceAccount, RBAC or ServiceMonitor.
func daemonSet(t *testing.T, file string) object {
	t.Helper()
	objs := render(t, file)
	if len(objs) != 1 || objs[0]["kind"] != "DaemonSet" {
		var kinds []any
		for _, o := range objs {
			kinds = append(kinds, o["kind"])
		}
		t.Fatalf("%s renders %v, want exactly one DaemonSet", file, kinds)
	}
	return objs[0]
}

func container(t *testing.T, ds object) object {
	t.Helper()
	cs, _ := get(ds, "spec", "template", "spec", "containers").([]any)
	if len(cs) != 1 {
		t.Fatalf("%d containers, want 1", len(cs))
	}
	return cs[0].(object)
}

func args(t *testing.T, c object) []string {
	t.Helper()
	var out []string
	for _, a := range c["args"].([]any) {
		out = append(out, a.(string))
	}
	return out
}

func TestDefaults(t *testing.T) {
	ds := daemonSet(t, "rendered_default.yaml")
	spec := get(ds, "spec", "template", "spec")
	c := container(t, ds)
	check := func(ok bool, what string) {
		t.Helper()
		if !ok {
			t.Error(what)
		}
	}

	check(get(ds, "metadata", "namespace") == "cgroup-signals", "namespace is the release's")
	for _, labels := range []any{get(ds, "metadata", "labels"), get(ds, "spec", "template", "metadata", "labels")} {
		for _, k := range []string{"app.kubernetes.io/name", "app.kubernetes.io/instance", "app.kubernetes.io/version", "app.kubernetes.io/managed-by"} {
			check(get(labels, k) != nil, "label "+k+" is missing")
		}
		check(get(labels, "app.kubernetes.io/name") == "cgroup-signals", "app.kubernetes.io/name must be cgroup-signals")
	}

	check(get(spec, "automountServiceAccountToken") == false, "automountServiceAccountToken must be false")
	check(get(spec, "serviceAccountName") == nil, "no ServiceAccount")
	for _, k := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		check(get(spec, k) == nil || get(spec, k) == false, k+" must be off")
	}
	check(get(spec, "priorityClassName") == nil, "no priorityClassName by default")
	check(reflect.DeepEqual(get(spec, "tolerations"), []any{object{"operator": "Exists"}}), "tolerations must default to [{operator: Exists}]")
	check(get(spec, "terminationGracePeriodSeconds") == 30, "terminationGracePeriodSeconds must be 30")
	check(get(ds, "spec", "updateStrategy", "type") == "RollingUpdate" &&
		get(ds, "spec", "updateStrategy", "rollingUpdate", "maxUnavailable") == 1, "updateStrategy must be RollingUpdate with maxUnavailable 1")

	check(get(spec, "securityContext", "runAsUser") == 0, "pod runAsUser must be 0")
	check(get(spec, "securityContext", "runAsGroup") == 0, "pod runAsGroup must be 0")
	check(get(spec, "securityContext", "seccompProfile", "type") == "RuntimeDefault", "pod seccompProfile must be RuntimeDefault")

	sc := get(c, "securityContext")
	check(get(sc, "allowPrivilegeEscalation") == false, "allowPrivilegeEscalation must be false")
	check(get(sc, "readOnlyRootFilesystem") == true, "readOnlyRootFilesystem must be true")
	check(get(sc, "privileged") == nil, "privileged must not be set by default")
	check(reflect.DeepEqual(get(sc, "capabilities"), object{"drop": []any{"ALL"}}), "capabilities must be exactly drop [ALL]")

	// The image is pinned by digest. A literal "{@" is an unreplaced stamp.
	img, _ := c["image"].(string)
	check(bytes.HasPrefix([]byte(img), []byte("ghcr.io/bpalermo/cgroup-signals@sha256:")) && len(img) == len("ghcr.io/bpalermo/cgroup-signals@sha256:")+64,
		"image must be ghcr.io/bpalermo/cgroup-signals@sha256:<64 hex>, is "+img)

	want := []string{
		"--listen=:9102",
		"--cgroup-root=/host/sys/fs/cgroup",
		"--psi-threshold-us=100000",
		"--psi-window-us=2000000",
		"--rescan-interval=15s",
		"--max-tracked-cgroups=512",
		"--log-level=info",
	}
	check(slices.Equal(args(t, c), want), "args are not the defaults")

	ports, _ := c["ports"].([]any)
	check(len(ports) == 1 && get(ports[0], "name") == "metrics" && get(ports[0], "containerPort") == 9102, "one port, metrics, 9102")

	// Never a probe on /metrics: a GET resets every memory peak.
	for _, k := range []string{"livenessProbe", "readinessProbe", "startupProbe"} {
		if p := get(c, k); p != nil {
			check(get(p, "httpGet", "path") == "/healthz", k+" must use /healthz, never /metrics")
		}
	}
	check(get(c, "livenessProbe") != nil && get(c, "readinessProbe") != nil, "probes are on /healthz by default")

	check(get(c, "resources", "requests", "cpu") == "10m" && get(c, "resources", "requests", "memory") == "32Mi" &&
		get(c, "resources", "limits", "memory") == "96Mi" && get(c, "resources", "limits", "cpu") == nil, "default resources")

	vols, _ := get(spec, "volumes").([]any)
	check(len(vols) == 1 && reflect.DeepEqual(get(vols[0], "hostPath"), object{"path": "/sys/fs/cgroup", "type": "Directory"}), "the only volume is hostPath /sys/fs/cgroup, Directory")
	mounts, _ := c["volumeMounts"].([]any)
	check(len(mounts) == 1 && get(mounts[0], "mountPath") == "/host/sys/fs/cgroup" && get(mounts[0], "readOnly") == nil, "mounted read-write at /host/sys/fs/cgroup")
}

func TestOptions(t *testing.T) {
	ds := daemonSet(t, "rendered_privileged.yaml")
	spec := get(ds, "spec", "template", "spec")
	c := container(t, ds)
	if get(c, "securityContext", "privileged") != true {
		t.Error("privileged=true must set the container's privileged")
	}
	if get(c, "securityContext", "allowPrivilegeEscalation") != false || get(c, "securityContext", "readOnlyRootFilesystem") != true {
		t.Error("privileged keeps the rest of the hardening")
	}
	if get(spec, "priorityClassName") != "system-node-critical" {
		t.Error("priorityClassName")
	}
	if get(ds, "spec", "template", "metadata", "labels", "team") != "o11y" ||
		get(ds, "spec", "template", "metadata", "annotations", "example") != "one" {
		t.Error("podLabels and podAnnotations belong on the pod template")
	}
	got := args(t, c)
	if !slices.Contains(got, "--psi-window-us=1000000") || got[len(got)-1] != "--some-flag=x" {
		t.Errorf("args: %v", got)
	}
}

// daemonSets is every DaemonSet of a render, by name without the release's, after checking that
// nothing else is rendered.
func daemonSets(t *testing.T, file string) map[string]object {
	t.Helper()
	out := map[string]object{}
	for _, o := range render(t, file) {
		if o["kind"] != "DaemonSet" {
			t.Fatalf("%s renders a %v, want DaemonSets only", file, o["kind"])
		}
		out[strings.TrimPrefix(get(o, "metadata", "name").(string), "release-name-")] = o // helm template's release name
	}
	return out
}

func TestRunqueueIsOffByDefault(t *testing.T) {
	// daemonSet fails unless the render is exactly one DaemonSet.
	ds := daemonSet(t, "rendered_default.yaml")
	if strings.HasSuffix(get(ds, "metadata", "name").(string), "-runqueue") {
		t.Error("the default render is the run-queue DaemonSet")
	}
	data, err := os.ReadFile("rendered_default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("runqueue")) || bytes.Contains(data, []byte("BPF")) {
		t.Error("the default render mentions the run-queue exporter or BPF")
	}
}

func TestRunqueue(t *testing.T) {
	sets := daemonSets(t, "rendered_runqueue.yaml")
	if len(sets) != 2 || sets["cgroup-signals"] == nil || sets["cgroup-signals-runqueue"] == nil {
		t.Fatalf("want the exporter and the run-queue DaemonSet, have %v", sets)
	}

	// Enabling it changes nothing about the exporter's own pod.
	exporter := container(t, sets["cgroup-signals"])
	if !reflect.DeepEqual(get(exporter, "securityContext", "capabilities"), object{"drop": []any{"ALL"}}) ||
		get(exporter, "securityContext", "privileged") != nil {
		t.Error("the exporter's security context changed: it must keep no capability at all")
	}

	ds := sets["cgroup-signals-runqueue"]
	spec := get(ds, "spec", "template", "spec")
	c := container(t, ds)
	check := func(ok bool, what string) {
		t.Helper()
		if !ok {
			t.Error(what)
		}
	}

	// The selectors of the two DaemonSets match only their own pods.
	own := get(ds, "spec", "selector", "matchLabels")
	other := get(sets["cgroup-signals"], "spec", "selector", "matchLabels")
	check(get(own, "app.kubernetes.io/name") == "cgroup-signals-runqueue", "the run-queue selector names cgroup-signals-runqueue")
	check(get(other, "app.kubernetes.io/name") == "cgroup-signals", "the exporter's selector is unchanged")
	podLabels := get(ds, "spec", "template", "metadata", "labels").(object)
	for k, v := range own.(object) {
		check(podLabels[k] == v, "the pod template does not carry the selector label "+k)
	}
	check(podLabels["app.kubernetes.io/name"] != "cgroup-signals", "the run-queue pod must not match the exporter's selector")

	check(get(spec, "automountServiceAccountToken") == false && get(spec, "serviceAccountName") == nil, "no API token, no ServiceAccount")
	for _, k := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		check(get(spec, k) == nil || get(spec, k) == false, k+" must be off")
	}
	check(get(spec, "securityContext", "runAsUser") == 0, "pod runAsUser must be 0: capabilities are effective only for root")
	check(get(spec, "securityContext", "seccompProfile", "type") == "RuntimeDefault", "pod seccompProfile must be RuntimeDefault")

	sc := get(c, "securityContext")
	check(get(sc, "privileged") == nil, "the run-queue container must not be privileged")
	check(get(sc, "allowPrivilegeEscalation") == false, "allowPrivilegeEscalation must be false")
	check(get(sc, "readOnlyRootFilesystem") == true, "readOnlyRootFilesystem must be true")
	check(reflect.DeepEqual(get(sc, "capabilities"), object{"drop": []any{"ALL"}, "add": []any{"BPF", "PERFMON"}}),
		"capabilities must be exactly drop [ALL], add [BPF, PERFMON]")

	img, _ := c["image"].(string)
	check(bytes.HasPrefix([]byte(img), []byte("ghcr.io/bpalermo/cgroup-signals@sha256:")), "image is pinned by digest, the same repository: "+img)
	check(img == container(t, sets["cgroup-signals"])["image"], "both DaemonSets run the same image")

	want := []string{
		"--runqueue",
		"--listen=:9103",
		"--cgroup-root=/host/sys/fs/cgroup",
		"--rescan-interval=15s",
		"--max-tracked-cgroups=512",
		"--log-level=info",
	}
	check(slices.Equal(args(t, c), want), fmt.Sprintf("args are %v, want %v", args(t, c), want))
	for _, a := range args(t, c) {
		check(!strings.HasPrefix(a, "--psi-"), "the run-queue exporter takes no PSI flag: "+a)
	}

	ports, _ := c["ports"].([]any)
	check(len(ports) == 1 && get(ports[0], "name") == "runqueue" && get(ports[0], "containerPort") == 9103, "one port, runqueue, 9103")
	for _, k := range []string{"livenessProbe", "readinessProbe", "startupProbe"} {
		if p := get(c, k); p != nil {
			check(get(p, "httpGet", "path") == "/healthz", k+" must use /healthz, never /metrics")
		}
	}
	check(get(c, "livenessProbe") != nil && get(c, "readinessProbe") != nil, "probes are on /healthz by default")

	vols, _ := get(spec, "volumes").([]any)
	check(len(vols) == 1 && reflect.DeepEqual(get(vols[0], "hostPath"), object{"path": "/sys/fs/cgroup", "type": "Directory"}), "the only volume is hostPath /sys/fs/cgroup, Directory")
	mounts, _ := c["volumeMounts"].([]any)
	check(len(mounts) == 1 && get(mounts[0], "mountPath") == "/host/sys/fs/cgroup" && get(mounts[0], "readOnly") == true, "cgroupfs is mounted READ-ONLY at /host/sys/fs/cgroup")
	check(reflect.DeepEqual(get(spec, "tolerations"), []any{object{"operator": "Exists"}}), "tolerations default to every node")
}

func TestRunqueueOptions(t *testing.T) {
	sets := daemonSets(t, "rendered_runqueue_options.yaml")
	ds := sets["cgroup-signals-runqueue"]
	if ds == nil {
		t.Fatalf("no run-queue DaemonSet in %v", sets)
	}
	c := container(t, ds)
	got := args(t, c)
	for _, w := range []string{"--listen=:9200", "--max-tracked-cgroups=64", "--rescan-interval=30s"} {
		if !slices.Contains(got, w) {
			t.Errorf("args %v lack %s", got, w)
		}
	}
	if got[len(got)-1] != "--some-flag=y" {
		t.Errorf("extraArgs are last: %v", got)
	}
	if get(ds, "spec", "template", "spec", "securityContext", "seccompProfile", "type") != "Unconfined" {
		t.Error("runqueue.seccompProfile")
	}
	if get(ds, "spec", "template", "spec", "priorityClassName") != "system-node-critical" ||
		get(ds, "spec", "template", "metadata", "labels", "team") != "o11y" {
		t.Error("the top-level priorityClassName and podLabels apply to the run-queue pod too")
	}
	if get(c, "securityContext", "privileged") != nil {
		t.Error("no option makes the run-queue container privileged")
	}
	if ns, _ := get(ds, "spec", "template", "spec", "nodeSelector").(map[string]any); len(ns) != 1 || ns["node"] != "n1" {
		t.Errorf("runqueue.nodeSelector replaces the top-level one for the run-queue pod: %v", ns)
	}
	if exp := sets["cgroup-signals"]; exp == nil || get(exp, "spec", "template", "spec", "nodeSelector", "zone") != "a" ||
		get(exp, "spec", "template", "spec", "nodeSelector", "node") != nil {
		t.Error("the exporter keeps the top-level nodeSelector")
	}
	ports, _ := c["ports"].([]any)
	if len(ports) != 1 || get(ports[0], "containerPort") != 9200 || get(c, "livenessProbe", "httpGet", "port") != "runqueue" {
		t.Error("the port follows runqueue.port, and the probes use its name")
	}
}

// affinityKey is the key of the first matchExpression of a required node
// affinity: enough to tell the fixtures' "top" and "rq" affinities apart.
func affinityKey(ds object) any {
	terms, _ := get(ds, "spec", "template", "spec", "affinity", "nodeAffinity",
		"requiredDuringSchedulingIgnoredDuringExecution", "nodeSelectorTerms").([]any)
	if len(terms) == 0 {
		return nil
	}
	exprs, _ := get(terms[0], "matchExpressions").([]any)
	if len(exprs) == 0 {
		return nil
	}
	return get(exprs[0], "key")
}

func TestRunqueueScheduling(t *testing.T) {
	// Overrides empty: the run-queue pod inherits the top-level scheduling.
	sets := daemonSets(t, "rendered_runqueue_inherit.yaml")
	for _, name := range []string{"cgroup-signals", "cgroup-signals-runqueue"} {
		ds := sets[name]
		if ds == nil {
			t.Fatalf("no %s DaemonSet in %v", name, sets)
		}
		if get(ds, "spec", "template", "spec", "nodeSelector", "zone") != "a" || affinityKey(ds) != "top" {
			t.Errorf("%s: want the top-level nodeSelector and affinity", name)
		}
	}

	// Overrides set: the run-queue pod takes its own, the exporter keeps the top-level ones.
	sets = daemonSets(t, "rendered_runqueue_options.yaml")
	if got := affinityKey(sets["cgroup-signals-runqueue"]); got != "rq" {
		t.Errorf("runqueue.affinity replaces the top-level one for the run-queue pod, have %v", got)
	}
	if got := affinityKey(sets["cgroup-signals"]); got != "top" {
		t.Errorf("the exporter keeps the top-level affinity, have %v", got)
	}
}
