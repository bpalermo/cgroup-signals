package runqlat

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// TestMeasure measures what each program of an object costs, under a
// scheduler load it generates, and prints one BENCH line per program. It is
// how a change to bpf/runqlat.bpf.c is compared with the one before (CI runs
// it on both objects, see .github/workflows/ci.yml); it asserts nothing, and
// skips unless RUNQLAT_BENCH_OBJECT names an object file. Needs root.
//
//	RUNQLAT_BENCH_OBJECT=path/to/runqlat.bpf.o RUNQLAT_BENCH_SECONDS=10 \
//	  sudo env RUNQLAT_BENCH_OBJECT=... runqlat_test -test.run '^TestMeasure$' -test.v
//
// The load tracks this process's cgroup in histogram 1 first, so the
// attribution path runs as it does for a pod. Run cost is measured by the
// kernel (BPF_ENABLE_STATS), which itself adds a clock read per run: compare
// objects, not absolute numbers with other tools'.
func TestMeasure(t *testing.T) {
	path := os.Getenv("RUNQLAT_BENCH_OBJECT")
	if path == "" {
		t.Skip("RUNQLAT_BENCH_OBJECT is not set")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	secs, _ := strconv.Atoi(os.Getenv("RUNQLAT_BENCH_SECONDS"))
	if secs <= 0 {
		secs = 10
	}
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	if m := coll.Maps["tracked"]; m != nil {
		if err := m.Put(ownCgroupID(t), uint32(1)); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
	if err != nil {
		t.Fatal(err)
	}
	defer stats.Close()

	names := []string{"sched_wakeup", "sched_wakeup_new", "sched_switch"}
	for _, n := range names {
		l, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs[n]})
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
	}
	before := map[string]*ebpf.ProgramStats{}
	for _, n := range names {
		if before[n], err = coll.Programs[n].Stats(); err != nil {
			t.Fatal(err)
		}
	}
	generateLoad(time.Duration(secs) * time.Second)
	for _, n := range names {
		after, err := coll.Programs[n].Stats()
		if err != nil {
			t.Fatal(err)
		}
		info, err := coll.Programs[n].Info()
		if err != nil {
			t.Fatal(err)
		}
		verified, _ := info.VerifiedInstructions()
		xlated, _ := info.Instructions()
		runs := after.RunCount - before[n].RunCount
		ns := uint64((after.Runtime - before[n].Runtime).Nanoseconds())
		var per float64
		if runs > 0 {
			per = float64(ns) / float64(runs)
		}
		fmt.Printf("BENCH object=%s prog=%s runs_per_s=%.0f ns_per_run=%.1f verified_insns=%d xlated_insns=%d\n",
			path, n, float64(runs)/float64(secs), per, verified, len(xlated))
	}
}

// generateLoad keeps the scheduler busy for d: pairs of goroutines passing a
// token (every hop is a wakeup of a thread that slept), and as many spinners
// as CPUs so that some tasks are preempted while still runnable.
func generateLoad(d time.Duration) {
	cpus := runtime.NumCPU()
	runtime.GOMAXPROCS(2 * cpus)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < cpus; i++ {
		a, b := make(chan struct{}), make(chan struct{})
		wg.Add(4)
		go func() { // a thread of its own that sleeps: a kernel wakeup each time
			defer wg.Done()
			runtime.LockOSThread()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = unix.Nanosleep(&unix.Timespec{Nsec: 20_000}, nil)
			}
		}()
		go func() {
			defer wg.Done()
			for {
				select {
				case a <- struct{}{}:
				case <-stop:
					return
				}
				select {
				case <-b:
				case <-stop:
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for {
				select {
				case <-a:
				case <-stop:
					return
				}
				select {
				case b <- struct{}{}:
				case <-stop:
					return
				}
			}
		}()
		go func() { // a spinner that sleeps a little now and then
			defer wg.Done()
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				if n%50000 == 0 {
					time.Sleep(50 * time.Microsecond)
				}
			}
		}()
	}
	time.Sleep(d)
	close(stop)
	wg.Wait()
}
