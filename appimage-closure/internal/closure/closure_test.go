package closure_test

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/bpalermo/cgroup-signals/appimage-closure/internal/closure"
	"github.com/bpalermo/cgroup-signals/appimage-closure/internal/tree"
)

// fakeTree is an in-memory tree: files and symlinks by path; directories are
// implied by their children.
type fakeTree struct {
	files map[string][]byte
	links map[string]string
}

func newTree() *fakeTree {
	return &fakeTree{files: map[string][]byte{}, links: map[string]string{}}
}

func (f *fakeTree) isDir(name string) bool {
	if name == "" {
		return true
	}
	for _, m := range []map[string]struct{}{keys(f.files), keysS(f.links)} {
		for p := range m {
			if strings.HasPrefix(p, name+"/") {
				return true
			}
		}
	}
	return false
}

func keys(m map[string][]byte) map[string]struct{} {
	o := map[string]struct{}{}
	for k := range m {
		o[k] = struct{}{}
	}
	return o
}

func keysS(m map[string]string) map[string]struct{} {
	o := map[string]struct{}{}
	for k := range m {
		o[k] = struct{}{}
	}
	return o
}

func (f *fakeTree) Lstat(name string) (tree.Node, error) {
	if t, ok := f.links[name]; ok {
		return tree.Node{Mode: fs.ModeSymlink | 0o777, Target: t}, nil
	}
	if _, ok := f.files[name]; ok {
		return tree.Node{Mode: 0o555}, nil
	}
	if f.isDir(name) {
		return tree.Node{Mode: fs.ModeDir | 0o755}, nil
	}
	return tree.Node{}, fs.ErrNotExist
}

func (f *fakeTree) ReadFile(name string) ([]byte, error) {
	d, ok := f.files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return d, nil
}

func (f *fakeTree) ReadDir(name string) ([]string, error) {
	seen := map[string]bool{}
	for p := range keys(f.files) {
		addChild(seen, name, p)
	}
	for p := range keysS(f.links) {
		addChild(seen, name, p)
	}
	var out []string
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func addChild(seen map[string]bool, dir, p string) {
	if dir != "" {
		if !strings.HasPrefix(p, dir+"/") {
			return
		}
		p = strings.TrimPrefix(p, dir+"/")
	}
	seen[strings.SplitN(p, "/", 2)[0]] = true
}

// elfObject is a minimal dynamically linked ELF64 object: an interpreter, the
// NEEDED libraries and a DT_RUNPATH, which is all the walk reads.
func elfObject(interp string, needed []string, runpath string) []byte {
	const (
		ehsize, phsize, shsize = 64, 56, 64
	)
	strtab := []byte{0}
	add := func(s string) uint64 {
		off := uint64(len(strtab))
		strtab = append(append(strtab, s...), 0)
		return off
	}
	type dyn struct{ tag, val uint64 }
	var dynamic []dyn
	for _, n := range needed {
		dynamic = append(dynamic, dyn{1, add(n)}) // DT_NEEDED
	}
	if runpath != "" {
		dynamic = append(dynamic, dyn{29, add(runpath)}) // DT_RUNPATH
	}
	dynamic = append(dynamic, dyn{0, 0})

	interpBytes := append([]byte(interp), 0)
	phnum := 0
	if interp != "" {
		phnum = 1
	}
	interpOff := uint64(ehsize + phsize*phnum)
	if interp == "" {
		interpBytes = nil
	}
	strOff := interpOff + uint64(len(interpBytes))
	dynOff := strOff + uint64(len(strtab))
	dynSize := uint64(16 * len(dynamic))
	shOff := dynOff + dynSize

	le := binary.LittleEndian
	b := make([]byte, ehsize)
	copy(b, "\x7fELF\x02\x01\x01")
	le.PutUint16(b[16:], 2)  // ET_EXEC
	le.PutUint16(b[18:], 62) // EM_X86_64
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[32:], uint64(ehsize)) // phoff
	le.PutUint64(b[40:], shOff)
	le.PutUint16(b[52:], ehsize)
	le.PutUint16(b[54:], phsize)
	le.PutUint16(b[56:], uint16(phnum))
	le.PutUint16(b[58:], shsize)
	le.PutUint16(b[60:], 3) // null, .dynstr, .dynamic
	if interp != "" {
		ph := make([]byte, phsize)
		le.PutUint32(ph[0:], 3) // PT_INTERP
		le.PutUint32(ph[4:], 4)
		le.PutUint64(ph[8:], interpOff)
		le.PutUint64(ph[32:], uint64(len(interpBytes)))
		le.PutUint64(ph[40:], uint64(len(interpBytes)))
		b = append(b, ph...)
	}
	b = append(b, interpBytes...)
	b = append(b, strtab...)
	for _, d := range dynamic {
		e := make([]byte, 16)
		le.PutUint64(e[0:], d.tag)
		le.PutUint64(e[8:], d.val)
		b = append(b, e...)
	}
	b = append(b, make([]byte, shsize)...) // SHN_UNDEF
	sh := make([]byte, shsize)
	le.PutUint32(sh[4:], 3) // SHT_STRTAB
	le.PutUint64(sh[24:], strOff)
	le.PutUint64(sh[32:], uint64(len(strtab)))
	b = append(b, sh...)
	sh = make([]byte, shsize)
	le.PutUint32(sh[4:], 6) // SHT_DYNAMIC
	le.PutUint64(sh[24:], dynOff)
	le.PutUint64(sh[32:], dynSize)
	le.PutUint32(sh[40:], 1) // sh_link: .dynstr
	le.PutUint64(sh[56:], 16)
	return append(b, sh...)
}

const (
	prog  = "nix/store/aaa-prog"
	foo   = "nix/store/bbb-foo"
	glibc = "nix/store/ccc-glibc"
)

// sample: prog -> libfoo.so.1 (a symlink in a symlinked-to file) and libc;
// foo -> libc; everything loaded through an absolute RUNPATH, as Nix does.
func sample() *fakeTree {
	t := newTree()
	t.links["entrypoint"] = "/" + prog + "/bin/prog"
	t.files[prog+"/bin/prog"] = elfObject("/"+glibc+"/lib/ld-2.so.2", []string{"libfoo.so.1", "libc.so.6"},
		"/"+foo+"/lib:/"+glibc+"/lib")
	t.files[prog+"/share/bpftrace/tools/a.bt"] = []byte("tracepoint:x { }")
	t.links[foo+"/lib/libfoo.so.1"] = "libfoo.so.1.2"
	t.files[foo+"/lib/libfoo.so.1.2"] = elfObject("", []string{"libc.so.6"}, "/"+glibc+"/lib")
	t.files[glibc+"/lib/libc-2.so"] = elfObject("", nil, "")
	t.links[glibc+"/lib/libc.so.6"] = "libc-2.so"
	t.files[glibc+"/lib/ld-2.so.2"] = elfObject("", nil, "")
	// Not in the closure: reachable only through a script's text.
	t.files["nix/store/ddd-python/bin/python"] = elfObject("", nil, "")
	t.files[foo+"/lib/unneeded.so"] = elfObject("", nil, "")
	return t
}

func TestCompute(t *testing.T) {
	res, err := closure.Compute(sample())
	if err != nil {
		t.Fatal(err)
	}
	if res.Root != prog || res.Entry != prog+"/bin/prog" {
		t.Errorf("root %q, entry %q", res.Root, res.Entry)
	}
	got := res.Sorted()
	for _, want := range []string{
		prog + "/bin/prog", prog + "/share/bpftrace/tools/a.bt",
		foo + "/lib/libfoo.so.1", foo + "/lib/libfoo.so.1.2", // the link AND what it leads to
		glibc + "/lib/libc.so.6", glibc + "/lib/libc-2.so", glibc + "/lib/ld-2.so.2",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("%s is not in the closure %v", want, got)
		}
	}
	for _, not := range []string{"nix/store/ddd-python/bin/python", foo + "/lib/unneeded.so"} {
		if slices.Contains(got, not) {
			t.Errorf("%s must not be in the closure", not)
		}
	}
}

func TestComputeMissingLibrary(t *testing.T) {
	tr := sample()
	delete(tr.files, foo+"/lib/libfoo.so.1.2")
	delete(tr.links, foo+"/lib/libfoo.so.1")
	_, err := closure.Compute(tr)
	if err == nil || !strings.Contains(err.Error(), "libfoo.so.1") {
		t.Errorf("a library in no run path must fail the build, got %v", err)
	}
}

func TestComputeNotInStore(t *testing.T) {
	tr := newTree()
	tr.links["entrypoint"] = "/usr/bin/prog"
	if _, err := closure.Compute(tr); err == nil {
		t.Error("an entry point outside /nix/store must fail")
	}
}

func TestWriteTar(t *testing.T) {
	tr := sample()
	res, err := closure.Compute(tr)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	extra := []closure.Link{{Name: "usr/local/bin/prog", Target: "/" + res.Entry}}
	if err := closure.WriteTar(&buf, tr, res, extra); err != nil {
		t.Fatal(err)
	}
	var names []string
	types := map[string]byte{}
	links := map[string]string{}
	rd := tar.NewReader(&buf)
	for {
		h, err := rd.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		n := strings.TrimSuffix(h.Name, "/")
		names = append(names, n)
		types[n] = h.Typeflag
		links[n] = h.Linkname
		if h.Uid != 0 || h.Gid != 0 || h.ModTime.Unix() != 0 {
			t.Errorf("%s: owner %d:%d time %v, want root and the epoch", h.Name, h.Uid, h.Gid, h.ModTime)
		}
	}
	// Every parent comes before its children: the layer extracts in order.
	seen := map[string]bool{}
	for _, n := range names {
		if p := path.Dir(n); p != "." && !seen[p] && n != "usr/local/bin/prog" {
			t.Errorf("%s comes before its parent %s", n, p)
		}
		seen[n] = true
	}
	if types["nix/store"] != tar.TypeDir || types[glibc+"/lib/libc.so.6"] != tar.TypeSymlink || links[glibc+"/lib/libc.so.6"] != "libc-2.so" {
		t.Errorf("types: %v", types)
	}
	if types["usr/local/bin/prog"] != tar.TypeSymlink || links["usr/local/bin/prog"] != "/"+prog+"/bin/prog" {
		t.Error("the extra link")
	}

	var again bytes.Buffer
	if err := closure.WriteTar(&again, tr, res, extra); err != nil {
		t.Fatal(err)
	}
	var first bytes.Buffer
	if err := closure.WriteTar(&first, tr, res, extra); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), again.Bytes()) {
		t.Error("the same input gave different bytes")
	}
}
