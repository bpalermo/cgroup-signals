// Package psi arms PSI triggers on cgroup pressure files and waits for their
// events, all from one epoll loop.
//
// A trigger is "some <threshold_us> <window_us>" written to an open
// cpu.pressure or memory.pressure: the kernel raises POLLPRI on that file
// descriptor when the tasks of the cgroup were stalled for at least the
// threshold within a window (Documentation/accounting/psi.rst). Each file
// descriptor holds one trigger, which lives until the descriptor is closed.
package psi

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Resource is a pressure file a trigger is armed on.
type Resource string

// The resources cgroup-signals arms triggers on.
const (
	CPU    Resource = "cpu"
	Memory Resource = "memory"
)

// Resources lists every Resource, in a stable order.
var Resources = []Resource{CPU, Memory}

// File is the resource's pressure file in a cgroup directory.
func (r Resource) File() string { return string(r) + ".pressure" }

// The window limits, from kernel/sched/psi.c (psi_trigger_create) as of 6.18.
const (
	// MaxWindowUS is WINDOW_MAX_US, the longest window the kernel accepts.
	MaxWindowUS = 10_000_000
	// UnprivilegedWindowStepUS: without CAP_SYS_RESOURCE, the window must be
	// a multiple of 2 s, so that the trigger rides the averaging worker
	// instead of a real-time "psimon" thread.
	UnprivilegedWindowStepUS = 2_000_000
	// MinWindowUS is not the kernel's: it accepted nothing under 500 ms
	// until 6.4 and still documents that floor. cgroup-signals keeps it,
	// because the polling thread wakes every window/10 while a cgroup is
	// stalled, once per tracked cgroup.
	MinWindowUS = 500_000
)

// Trigger is a "some" stall threshold within a window, in microseconds.
type Trigger struct {
	ThresholdUS uint32
	WindowUS    uint32
}

// String is the trigger as written to the pressure file.
func (t Trigger) String() string {
	return fmt.Sprintf("some %d %d", t.ThresholdUS, t.WindowUS)
}

// Validate checks t against the limits the kernel enforces on a writer with
// (privileged) or without CAP_SYS_RESOURCE, and cgroup-signals' own floor on
// the window.
func (t Trigger) Validate(privileged bool) error {
	if t.WindowUS < MinWindowUS || t.WindowUS > MaxWindowUS {
		return fmt.Errorf("PSI window %d us is outside [%d, %d] us", t.WindowUS, MinWindowUS, MaxWindowUS)
	}
	if !privileged && t.WindowUS%UnprivilegedWindowStepUS != 0 {
		return fmt.Errorf("PSI window %d us is not a multiple of %d us, which the kernel requires without CAP_SYS_RESOURCE", t.WindowUS, UnprivilegedWindowStepUS)
	}
	if t.ThresholdUS == 0 || t.ThresholdUS > t.WindowUS {
		return fmt.Errorf("PSI threshold %d us must be in (0, window %d us]", t.ThresholdUS, t.WindowUS)
	}
	return nil
}

// Privileged reports whether this process has CAP_SYS_RESOURCE in its
// effective set, which is what the kernel checks on the opener of a pressure
// file to allow windows that are not multiples of 2 s.
func Privileged() (bool, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false, fmt.Errorf("capget: %w", err)
	}
	const bit = unix.CAP_SYS_RESOURCE
	return data[bit/32].Effective&(1<<(bit%32)) != 0, nil
}

// Arm opens path (a pressure file), writes t to it and returns the file
// descriptor, open O_RDWR|O_NONBLOCK, which carries the trigger.
func Arm(path string, t Trigger) (int, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, &os.PathError{Op: "open", Path: path, Err: err}
	}
	// The trailing NUL is what psi.rst's example writes. The cgroup file
	// does not need it, but /proc/pressure/* overwrites the last byte of
	// the write with one, so a trigger written without it loses a digit.
	if _, err := unix.Write(fd, append([]byte(t.String()), 0)); err != nil {
		_ = unix.Close(fd)
		return -1, &os.PathError{Op: "write trigger", Path: path, Err: err}
	}
	return fd, nil
}
