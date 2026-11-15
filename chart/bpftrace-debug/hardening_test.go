// Package bpftracedebug_test checks the chart's rendered Pod against the
// contract in values.yaml and the README: one Pod on the named node,
// privileged with the host's PID namespace and nothing else opened, no API
// token, a deadline, the host mounts the README lists, and the image pinned by
// digest. A template that drops one of them fails here.
package bpftracedebug_test

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

// objects is every object of a render keyed by kind.
func objects(t *testing.T, file string) map[string]object {
	t.Helper()
	out := map[string]object{}
	for _, o := range render(t, file) {
		k, _ := o["kind"].(string)
		if _, dup := out[k]; dup {
			t.Fatalf("%s renders two %s", file, k)
		}
		out[k] = o
	}
	return out
}

// pod is the one Pod of a render; the only other object allowed is the
// program file's ConfigMap (and then only when wantConfigMap).
func pod(t *testing.T, file string, wantConfigMap bool) object {
	t.Helper()
	objs := objects(t, file)
	_, hasCM := objs["ConfigMap"]
	if objs["Pod"] == nil || len(objs) != 1+btoi(hasCM) || hasCM != wantConfigMap {
		var kinds []string
		for k := range objs {
			kinds = append(kinds, k)
		}
		t.Fatalf("%s renders %v, want one Pod (and a ConfigMap: %v)", file, kinds, wantConfigMap)
	}
	return objs["Pod"]
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func container(t *testing.T, p object) object {
	t.Helper()
	cs, _ := get(p, "spec", "containers").([]any)
	if len(cs) != 1 {
		t.Fatalf("%d containers, want 1", len(cs))
	}
	return cs[0].(object)
}

func strs(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, a := range l {
		out = append(out, a.(string))
	}
	return out
}

func checker(t *testing.T) func(bool, string) {
	return func(ok bool, what string) {
		t.Helper()
		if !ok {
			t.Error(what)
		}
	}
}

// mounts is the container's volumeMounts: name -> {path, readOnly}.
func mounts(c object) map[string][2]any {
	out := map[string][2]any{}
	l, _ := c["volumeMounts"].([]any)
	for _, m := range l {
		out[get(m, "name").(string)] = [2]any{get(m, "mountPath"), get(m, "readOnly") == true}
	}
	return out
}

func hostPaths(p object) map[string]string {
	out := map[string]string{}
	l, _ := get(p, "spec", "volumes").([]any)
	for _, v := range l {
		if hp := get(v, "hostPath", "path"); hp != nil {
			out[get(v, "name").(string)] = hp.(string)
		}
	}
	return out
}

func TestPodContract(t *testing.T) {
	p := pod(t, "rendered_default.yaml", false)
	spec := get(p, "spec")
	c := container(t, p)
	check := checker(t)

	check(get(p, "metadata", "namespace") == "bpftrace-debug", "namespace is the release's")
	check(get(p, "metadata", "labels", "app.kubernetes.io/name") == "bpftrace-debug", "app.kubernetes.io/name")
	check(get(spec, "nodeName") == "main-worker-02", "nodeName is the node value")
	check(get(spec, "hostPID") == true, "hostPID must be on")
	for _, k := range []string{"hostNetwork", "hostIPC"} {
		check(get(spec, k) == nil || get(spec, k) == false, k+" must be off")
	}
	check(get(spec, "automountServiceAccountToken") == false, "automountServiceAccountToken must be false")
	check(get(spec, "serviceAccountName") == nil, "no ServiceAccount")
	check(get(spec, "enableServiceLinks") == false, "enableServiceLinks must be false")
	check(get(spec, "restartPolicy") == "Never", "restartPolicy must be Never")
	check(get(spec, "activeDeadlineSeconds") == 3600, "activeDeadlineSeconds must default to 3600")
	check(get(spec, "terminationGracePeriodSeconds") == 5, "terminationGracePeriodSeconds must be small")
	check(get(spec, "priorityClassName") == nil, "no priorityClassName by default")
	check(reflect.DeepEqual(get(spec, "tolerations"), []any{object{"operator": "Exists"}}), "tolerations must default to [{operator: Exists}]")
	check(get(spec, "securityContext", "runAsUser") == 0, "runAsUser must be 0")

	check(get(c, "securityContext", "privileged") == true, "the container must be privileged")
	check(get(c, "resources", "requests", "memory") == "256Mi" && get(c, "resources", "limits", "memory") == "1Gi", "default resources")
	check(get(c, "livenessProbe") == nil && get(c, "readinessProbe") == nil, "no probes on a debug pod")

	img, _ := c["image"].(string)
	const repo = "ghcr.io/bpalermo/cgroup-signals-bpftrace@sha256:"
	check(strings.HasPrefix(img, repo) && len(img) == len(repo)+64, "image must be "+repo+"<64 hex>, is "+img)

	// Sleep mode: no bpftrace run, a shell that ends on TERM.
	cmd := strs(c["command"])
	check(len(cmd) == 3 && cmd[0] == "/busybox/sh" && strings.Contains(cmd[2], "trap") && strings.Contains(cmd[2], "sleep"), fmt.Sprintf("sleep mode command: %v", cmd))
	check(c["args"] == nil, "sleep mode has no args")

	want := map[string][2]any{
		"debugfs": {"/sys/kernel/debug", false},
		"tracefs": {"/sys/kernel/tracing", false},
		"btf":     {"/sys/kernel/btf", true},
		"cgroup":  {"/sys/fs/cgroup", true},
		"modules": {"/lib/modules", true},
	}
	check(reflect.DeepEqual(mounts(c), want), fmt.Sprintf("mounts are %v, want %v", mounts(c), want))
	hp := map[string]string{"debugfs": "/sys/kernel/debug", "tracefs": "/sys/kernel/tracing", "btf": "/sys/kernel/btf", "cgroup": "/sys/fs/cgroup", "modules": "/lib/modules"}
	check(reflect.DeepEqual(hostPaths(p), hp), fmt.Sprintf("hostPaths are %v, want %v", hostPaths(p), hp))
	vols, _ := get(spec, "volumes").([]any)
	check(len(vols) == len(hp), "no volume but the host paths")
}

func TestProgram(t *testing.T) {
	p := pod(t, "rendered_program.yaml", false)
	c := container(t, p)
	check := checker(t)
	check(slices.Equal(strs(c["command"]), []string{"/usr/local/bin/bpftrace"}), "command is bpftrace")
	check(slices.Equal(strs(c["args"]), []string{"-q", "--no-warnings", "-e", "tracepoint:sched:sched_switch { @[comm] = count(); }"}),
		fmt.Sprintf("args: %v", strs(c["args"])))
	check(get(c, "securityContext", "privileged") == true && get(p, "spec", "restartPolicy") == "Never", "still privileged, still Never")
}

func TestProgramFile(t *testing.T) {
	p := pod(t, "rendered_programfile.yaml", true)
	cm := objects(t, "rendered_programfile.yaml")["ConfigMap"]
	c := container(t, p)
	check := checker(t)
	check(get(cm, "data", "program.bt") == "BEGIN { printf(\"hi\"); exit(); }", fmt.Sprintf("the program file is the ConfigMap's program.bt: %v", get(cm, "data")))
	check(get(cm, "metadata", "name") == get(p, "metadata", "name"), "the ConfigMap is named like the pod")
	check(slices.Equal(strs(c["args"]), []string{"/etc/bpftrace/program.bt"}), fmt.Sprintf("args: %v", strs(c["args"])))
	m := mounts(c)
	check(m["program"] == [2]any{"/etc/bpftrace", true}, "the program is mounted read-only at /etc/bpftrace")
	vols, _ := get(p, "spec", "volumes").([]any)
	check(len(vols) == 6 && get(vols[5], "configMap", "name") == get(cm, "metadata", "name"), "the program volume is the ConfigMap")
}

func TestOptions(t *testing.T) {
	p := pod(t, "rendered_options.yaml", false)
	spec := get(p, "spec")
	check := checker(t)
	check(get(spec, "activeDeadlineSeconds") == 600, "activeDeadlineSeconds")
	check(get(spec, "terminationGracePeriodSeconds") == 10, "terminationGracePeriodSeconds")
	check(get(spec, "priorityClassName") == "system-node-critical", "priorityClassName")
	check(get(container(t, p), "resources", "limits", "memory") == "2Gi", "resources.limits.memory")
	check(get(p, "metadata", "labels", "team") == "o11y" && get(p, "metadata", "annotations", "example") == "one", "podLabels and podAnnotations belong on the pod")
	check(get(p, "metadata", "labels", "app.kubernetes.io/name") == "bpftrace-debug", "podLabels do not replace the chart's")
}
