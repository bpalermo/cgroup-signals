// Package closure computes what a Nix-built program needs at run time, from a
// filesystem image that holds a /nix/store: the program's own store path, plus
// every shared library it loads, found the way the dynamic linker finds them
// (DT_RUNPATH or DT_RPATH, then each library's own), plus the interpreter.
//
// It is Nix's reference scanning narrowed to what ld.so follows: scanning for
// store hashes in file contents would pull in everything a script mentions
// (here, a Python and a Perl that bpftrace never runs).
package closure

import (
	"archive/tar"
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/bpalermo/cgroup-signals/appimage-closure/internal/tree"
)

// maxLinkHops bounds symlink resolution of one path (the kernel's is 40).
const maxLinkHops = 40

// Result is what must be copied: every path (files, symlinks, directories
// of the entry's store path) and the entry point's identity.
type Result struct {
	// Root is the entry point's store path, "nix/store/<hash>-<name>".
	Root string
	// Entry is the entry point's target, "nix/store/<hash>-<name>/bin/<program>".
	Entry string
	// Nodes is every included path except the implied parent directories.
	Nodes map[string]tree.Node
}

type walker struct {
	t        tree.Tree
	nodes    map[string]tree.Node
	analyzed map[string]bool
	work     []string
}

// Compute walks t from its "entrypoint" symlink, the AppImage convention for
// the program to run.
func Compute(t tree.Tree) (*Result, error) {
	n, err := t.Lstat("entrypoint")
	if err != nil {
		return nil, fmt.Errorf("no entrypoint: %w", err)
	}
	entry := tree.Clean(n.Target)
	root, err := storePath(entry)
	if err != nil {
		return nil, err
	}
	w := &walker{t: t, nodes: map[string]tree.Node{}, analyzed: map[string]bool{}}
	if err := w.addTree(root); err != nil {
		return nil, err
	}
	if _, err := w.add(entry); err != nil {
		return nil, err
	}
	for len(w.work) > 0 {
		p := w.work[len(w.work)-1]
		w.work = w.work[:len(w.work)-1]
		if err := w.analyze(p); err != nil {
			return nil, err
		}
	}
	return &Result{Root: root, Entry: entry, Nodes: w.nodes}, nil
}

// storePath is "nix/store/<hash>-<name>" of a path under the store.
func storePath(p string) (string, error) {
	c := strings.Split(p, "/")
	if len(c) < 4 || c[0] != "nix" || c[1] != "store" {
		return "", fmt.Errorf("%q is not under /nix/store", p)
	}
	return strings.Join(c[:3], "/"), nil
}

// resolve follows every symlink of p, intermediate ones included, and returns
// the real path and the symlinks passed on the way.
func (w *walker) resolve(p string) (string, []string, error) {
	var links []string
	pending := strings.Split(tree.Clean(p), "/")
	cur := ""
	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			cur = path.Dir(cur)
			if cur == "." {
				cur = ""
			}
			continue
		}
		next := path.Join(cur, c)
		n, err := w.t.Lstat(next)
		if err != nil {
			return "", nil, err
		}
		if n.Mode&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		if len(links) >= maxLinkHops {
			return "", nil, fmt.Errorf("%s: too many symbolic links", p)
		}
		links = append(links, next)
		if strings.HasPrefix(n.Target, "/") {
			cur = ""
		}
		pending = append(strings.Split(n.Target, "/"), pending...)
	}
	return cur, links, nil
}

// add includes p: the symlinks on the way and what they lead to. It returns
// the real path, queued for analysis when it is a regular file not seen yet.
func (w *walker) add(p string) (string, error) {
	real, links, err := w.resolve(p)
	if err != nil {
		return "", err
	}
	for _, l := range append(links, real) {
		n, err := w.t.Lstat(l)
		if err != nil {
			return "", err
		}
		w.nodes[l] = n
	}
	if n := w.nodes[real]; n.Mode.IsRegular() && !w.analyzed[real] {
		w.analyzed[real] = true
		w.work = append(w.work, real)
	}
	return real, nil
}

// addTree includes a whole directory, such as the program's own store path.
func (w *walker) addTree(dir string) error {
	n, err := w.t.Lstat(dir)
	if err != nil {
		return err
	}
	w.nodes[dir] = n
	if !n.Mode.IsDir() {
		if n.Mode&fs.ModeSymlink != 0 {
			_, err = w.add(dir)
		} else if n.Mode.IsRegular() && !w.analyzed[dir] {
			w.analyzed[dir] = true
			w.work = append(w.work, dir)
		}
		return err
	}
	names, err := w.t.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := w.addTree(path.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

// analyze reads one regular file; if it is an ELF object it includes the
// interpreter and the libraries it needs.
func (w *walker) analyze(p string) error {
	data, err := w.t.ReadFile(p)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(data, []byte(elf.ELFMAG)) {
		return nil
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	defer f.Close()
	if interp := interpreter(f); interp != "" {
		if _, err := w.add(interp); err != nil {
			return fmt.Errorf("%s: interpreter: %w", p, err)
		}
	}
	return w.addLibs(p, f)
}

func (w *walker) addLibs(p string, f *elf.File) error {
	libs, err := f.ImportedLibraries()
	if err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	dirs, err := searchDirs(f, path.Dir(p))
	if err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	// glibc's libc.so.6 names ld.so as NEEDED and has no run path: the
	// interpreter is already loaded, and sits beside it. Look in the object's
	// own directory last.
	dirs = append(dirs, path.Dir(p))
	for _, lib := range libs {
		found := ""
		for _, d := range dirs {
			if _, err := w.t.Lstat(path.Join(d, lib)); err == nil {
				found = path.Join(d, lib)
				break
			}
		}
		if found == "" && w.loaded(lib) {
			continue // satisfied by the soname of an object already loaded
		}
		if found == "" {
			return fmt.Errorf("%s needs %s, which is in none of its run paths %v", p, lib, dirs)
		}
		if _, err := w.add(found); err != nil {
			return err
		}
	}
	return nil
}

// loaded is whether a library of that soname is already included: the dynamic
// linker satisfies a NEEDED by the soname of a loaded object before it
// searches, which is how a library with no run path (libgcc_s) finds libc.
func (w *walker) loaded(soname string) bool {
	for p := range w.nodes {
		if path.Base(p) == soname {
			return true
		}
	}
	return false
}

func interpreter(f *elf.File) string {
	for _, p := range f.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		b := make([]byte, p.Filesz)
		if _, err := p.ReadAt(b, 0); err != nil && !errors.Is(err, io.EOF) {
			return ""
		}
		return strings.TrimRight(string(b), "\x00")
	}
	return ""
}

// searchDirs is the libraries' search path of an object in dir: DT_RUNPATH,
// or DT_RPATH if there is none, with $ORIGIN expanded. The system directories
// are not searched: a Nix program has none.
func searchDirs(f *elf.File, dir string) ([]string, error) {
	var raw []string
	for _, tag := range []elf.DynTag{elf.DT_RUNPATH, elf.DT_RPATH} {
		v, err := f.DynString(tag)
		if err != nil {
			return nil, err
		}
		if len(v) > 0 {
			raw = v
			break
		}
	}
	var out []string
	for _, r := range raw {
		for _, d := range strings.Split(r, ":") {
			d = strings.NewReplacer("${ORIGIN}", "/"+dir, "$ORIGIN", "/"+dir).Replace(d)
			if d = tree.Clean(d); d != "" {
				out = append(out, d)
			}
		}
	}
	return out, nil
}

// Link is a symlink to add to the layer: Name relative to the root, Target
// as the link holds it.
type Link struct {
	Name, Target string
}

// WriteTar writes the result as a tar: parents first, every owner root, every
// time the epoch, so the same input gives the same bytes. Extra links are
// added after the walk's own entries.
func WriteTar(w io.Writer, t tree.Tree, r *Result, extra []Link) error {
	tw := tar.NewWriter(w)
	paths := make([]string, 0, len(r.Nodes))
	dirs := map[string]bool{}
	for p := range r.Nodes {
		paths = append(paths, p)
		addParents(dirs, p)
	}
	for _, l := range extra {
		addParents(dirs, l.Name)
	}
	for d := range dirs {
		if _, ok := r.Nodes[d]; !ok {
			paths = append(paths, d)
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		if err := writeEntry(tw, t, p, r.Nodes[p], dirs[p]); err != nil {
			return err
		}
	}
	for _, l := range extra {
		h := &tar.Header{Typeflag: tar.TypeSymlink, Name: l.Name, Linkname: l.Target, Mode: 0o777, ModTime: time.Unix(0, 0)}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
	}
	return tw.Close()
}

func addParents(dirs map[string]bool, p string) {
	for d := path.Dir(p); d != "." && d != "/"; d = path.Dir(d) {
		dirs[d] = true
	}
}

func writeEntry(tw *tar.Writer, t tree.Tree, p string, n tree.Node, implied bool) error {
	h := &tar.Header{Name: p, ModTime: time.Unix(0, 0), Format: tar.FormatPAX}
	var data []byte
	switch {
	case n.Mode.IsDir() || implied && n.Mode == 0:
		h.Typeflag, h.Name, h.Mode = tar.TypeDir, p+"/", 0o755
	case n.Mode&fs.ModeSymlink != 0:
		h.Typeflag, h.Linkname, h.Mode = tar.TypeSymlink, n.Target, 0o777
	case n.Mode.IsRegular():
		d, err := t.ReadFile(p)
		if err != nil {
			return err
		}
		data = d
		h.Typeflag, h.Size, h.Mode = tar.TypeReg, int64(len(d)), int64(n.Mode.Perm())
	default:
		return fmt.Errorf("%s: unsupported file type %v", p, n.Mode.Type())
	}
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// Sorted is the included paths, for a listing.
func (r *Result) Sorted() []string {
	out := make([]string, 0, len(r.Nodes))
	for p := range r.Nodes {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}
