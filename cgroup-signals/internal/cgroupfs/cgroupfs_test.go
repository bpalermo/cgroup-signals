package cgroupfs

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

// mkTree creates the directories under a new temporary root.
func mkTree(t *testing.T, dirs ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestDiscover(t *testing.T) {
	root := mkTree(t,
		"kubepods/pod0b0c5e2f-1a2b-4c3d-8e9f-0123456789ab/container1",
		"kubepods/burstable/pod11111111_2222_3333_4444_555555555555/c",
		"kubepods/besteffort/podDEADBEEF-0000-0000-0000-000000000000",
		"kubepods/burstable/not-a-pod",
		"kubepods/burstable/podxyz",
		"podruntime/kubelet",
		"podruntime/runtime",
		"system/apid",
		"init",
		"user.slice",
	)
	// A file named like a pod is not a pod.
	if err := os.WriteFile(filepath.Join(root, "kubepods/besteffort/pod12345678"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := Discover(os.DirFS(root))
	if err != nil {
		t.Fatal(err)
	}
	want := []Cgroup{
		{Path: "kubepods/pod0b0c5e2f-1a2b-4c3d-8e9f-0123456789ab", PodUID: "0b0c5e2f-1a2b-4c3d-8e9f-0123456789ab", QoS: "guaranteed"},
		{Path: "kubepods/burstable/pod11111111_2222_3333_4444_555555555555", PodUID: "11111111-2222-3333-4444-555555555555", QoS: "burstable"},
		{Path: "kubepods/besteffort/podDEADBEEF-0000-0000-0000-000000000000", PodUID: "deadbeef-0000-0000-0000-000000000000", QoS: "besteffort"},
		{Path: "podruntime/kubelet", Service: "kubelet"},
		{Path: "podruntime/runtime", Service: "runtime"},
		{Path: "system", Service: "system"},
		{Path: "init", Service: "init"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Discover =\n%+v\nwant\n%+v", got, want)
	}
}

func TestDiscoverMissingDirectoriesAreNotErrors(t *testing.T) {
	root := mkTree(t, "kubepods/burstable/pod11111111-2222-3333-4444-555555555555", "system")
	got, err := Discover(os.DirFS(root))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, cg := range got {
		paths = append(paths, cg.Path)
	}
	want := []string{"kubepods/burstable/pod11111111-2222-3333-4444-555555555555", "system"}
	if !slices.Equal(paths, want) {
		t.Errorf("Discover paths = %v, want %v", paths, want)
	}
}

func TestDiscoverReportsErrorsAndKeepsTheRest(t *testing.T) {
	root := mkTree(t, "kubepods/pod11111111-2222-3333-4444-555555555555", "init")
	// "burstable" is a file, not a directory: ReadDir fails with something
	// other than ErrNotExist.
	if err := os.WriteFile(filepath.Join(root, "kubepods/burstable"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Discover(os.DirFS(root))
	if err == nil {
		t.Error("Discover returned no error for an unreadable QoS directory")
	}
	if len(got) != 2 {
		t.Errorf("Discover = %+v, want the guaranteed pod and init", got)
	}
}

func TestPodUID(t *testing.T) {
	for name, want := range map[string]string{
		"pod0b0c5e2f-1a2b-4c3d-8e9f-0123456789ab": "0b0c5e2f-1a2b-4c3d-8e9f-0123456789ab",
		"pod0b0c5e2f_1a2b_4c3d_8e9f_0123456789ab": "0b0c5e2f-1a2b-4c3d-8e9f-0123456789ab",
		"pod0B0C5E2F_1A2B_4C3D_8E9F_0123456789AB": "0b0c5e2f-1a2b-4c3d-8e9f-0123456789ab",
		"pod5f3c1d0e9a8b7c6d5e4f3a2b1c0d9e8f":     "5f3c1d0e9a8b7c6d5e4f3a2b1c0d9e8f", // static pod
		"pod":                                     "",
		"burstable":                               "",
		"podnot-hex":                              "",
		"kubepods-pod0b0c5e2f.slice":              "",
	} {
		got, ok := PodUID(name)
		if got != want || ok != (want != "") {
			t.Errorf("PodUID(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
}

func TestParseFlatKeyed(t *testing.T) {
	got, err := ParseFlatKeyed([]byte("low 0\nhigh 12\nmax 3\noom 1\noom_kill 1\noom_group_kill 0\nsock_throttled 7\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]uint64{"low": 0, "high": 12, "max": 3, "oom": 1, "oom_kill": 1, "oom_group_kill": 0, "sock_throttled": 7}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseFlatKeyed = %v, want %v", got, want)
	}
	for _, bad := range []string{"low\n", "low x\n", "low -1\n"} {
		if _, err := ParseFlatKeyed([]byte(bad)); err == nil {
			t.Errorf("ParseFlatKeyed(%q) returned no error", bad)
		}
	}
}

func TestParseUint(t *testing.T) {
	if v, err := ParseUint([]byte("1234567\n")); err != nil || v != 1234567 {
		t.Errorf("ParseUint = %d, %v", v, err)
	}
	if _, err := ParseUint([]byte("max\n")); err == nil {
		t.Error("ParseUint(max) returned no error")
	}
}
