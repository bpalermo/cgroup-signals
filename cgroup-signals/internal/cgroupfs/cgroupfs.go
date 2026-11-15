// Package cgroupfs finds the cgroups cgroup-signals tracks under a cgroup v2
// root and parses the files it reads from them.
//
// The layout is the kubelet's with the cgroupfs driver, as on Talos:
//
//	kubepods/pod<uid>/              Guaranteed pods
//	kubepods/burstable/pod<uid>/    Burstable pods
//	kubepods/besteffort/pod<uid>/   BestEffort pods
//	podruntime/kubelet/             the kubelet
//	podruntime/runtime/             containerd and the shims
//	system/                         Talos system services
//	init/                           machined
//
// Only pod-level cgroups are tracked, not the containers under them.
package cgroupfs

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Cgroup is one tracked cgroup: a pod or a node service.
type Cgroup struct {
	// Path is the cgroup's directory relative to the cgroup root,
	// slash-separated, e.g. "kubepods/burstable/pod<uid>". It identifies the
	// cgroup.
	Path string
	// PodUID is the pod's UID in the dashed form (as in the API's
	// metadata.uid); empty for a node service.
	PodUID string
	// QoS is guaranteed, burstable or besteffort; empty for a node service.
	QoS string
	// Service is kubelet, runtime, system or init; empty for a pod.
	Service string
}

// The QoS directories, each holding pod<uid> cgroups.
var qosDirs = []struct{ dir, qos string }{
	{"kubepods", "guaranteed"},
	{"kubepods/burstable", "burstable"},
	{"kubepods/besteffort", "besteffort"},
}

// The node-service cgroups, by path and label.
var services = []struct{ path, name string }{
	{"podruntime/kubelet", "kubelet"},
	{"podruntime/runtime", "runtime"},
	{"system", "system"},
	{"init", "init"},
}

// Discover lists the pod and node-service cgroups under fsys, the cgroup
// root. A directory that does not exist (no BestEffort pods yet, a node
// without one of the services) is not an error. On an error Discover still
// returns everything it could list, and the error says what it could not.
func Discover(fsys fs.FS) ([]Cgroup, error) {
	var (
		found []Cgroup
		errs  []error
	)
	for _, q := range qosDirs {
		pods, err := podsIn(fsys, q.dir, q.qos)
		if err != nil {
			errs = append(errs, err)
		}
		found = append(found, pods...)
	}
	for _, s := range services {
		ok, err := isDir(fsys, s.path)
		if err != nil {
			errs = append(errs, err)
		}
		if ok {
			found = append(found, Cgroup{Path: s.path, Service: s.name})
		}
	}
	return found, errors.Join(errs...)
}

func podsIn(fsys fs.FS, dir, qos string) ([]Cgroup, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var pods []Cgroup
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if uid, ok := PodUID(e.Name()); ok {
			pods = append(pods, Cgroup{Path: path.Join(dir, e.Name()), PodUID: uid, QoS: qos})
		}
	}
	return pods, nil
}

func isDir(fsys fs.FS, name string) (bool, error) {
	info, err := fs.Stat(fsys, name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

// PodUID returns the pod UID in a pod cgroup's directory name, "pod" followed
// by the UID, in the dashed lower-case form of metadata.uid. Depending on the
// driver the kubelet writes the UID's dashes as underscores. A name that is
// not a pod cgroup's returns false.
//
// The UID is not required to be a UUID: a static pod's UID is the hash of its
// manifest, 32 hex digits.
func PodUID(name string) (string, bool) {
	rest, ok := strings.CutPrefix(name, "pod")
	if !ok || rest == "" {
		return "", false
	}
	uid := strings.ToLower(strings.ReplaceAll(rest, "_", "-"))
	for _, r := range uid {
		if r != '-' && (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", false
		}
	}
	return uid, true
}

// MemoryEventNames are the memory.events keys cgroup-signals exports. Other
// keys (sock_throttled, and any a later kernel adds) are ignored.
var MemoryEventNames = []string{"low", "high", "max", "oom", "oom_kill", "oom_group_kill"}

// ParseFlatKeyed parses a cgroup flat-keyed file such as memory.events: one
// "<key> <unsigned value>" pair per line.
func ParseFlatKeyed(data []byte) (map[string]uint64, error) {
	values := make(map[string]uint64)
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			return nil, fmt.Errorf("malformed line %q", sc.Text())
		}
		v, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", key, err)
		}
		values[key] = v
	}
	return values, sc.Err()
}

// ParseUint parses a single-value file such as memory.peak.
func ParseUint(data []byte) (uint64, error) {
	return strconv.ParseUint(string(bytes.TrimSpace(data)), 10, 64)
}

// CheckV2 returns an error unless root is on a cgroup v2 filesystem.
func CheckV2(root string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(root, &st); err != nil {
		return fmt.Errorf("statfs %s: %w", root, err)
	}
	if st.Type != unix.CGROUP2_SUPER_MAGIC {
		return fmt.Errorf("%s is not a cgroup v2 filesystem (magic %#x)", root, st.Type)
	}
	return nil
}

// IsRemoved reports whether err says the cgroup was removed under an open
// file: kernfs answers ENODEV once a removed cgroup's files are deactivated.
func IsRemoved(err error) bool {
	return errors.Is(err, unix.ENODEV)
}
