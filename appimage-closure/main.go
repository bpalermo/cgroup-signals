// Command appimage-closure turns a Nix-built AppImage (a static runtime and a
// squashfs holding a /nix/store) into a tar layer of just what the program
// inside needs, laid out at /nix/store so the program runs as it is, with no
// FUSE, no user namespace and no extraction at start-up.
//
//	appimage-closure -appimage bpftrace-x86_64 -out layer.tar \
//	    -link usr/local/bin/bpftrace=@entry \
//	    -link usr/share/bpftrace/tools=@root/share/bpftrace/tools
//
// A link target may begin with @entry (the program) or @root (its store path).
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bpalermo/cgroup-signals/appimage-closure/internal/closure"
	"github.com/bpalermo/cgroup-signals/appimage-closure/internal/tree"
)

type links []string

func (l *links) String() string     { return strings.Join(*l, ",") }
func (l *links) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	appimage := flag.String("appimage", "", "the AppImage")
	out := flag.String("out", "", "the tar to write")
	var ls links
	flag.Var(&ls, "link", "name=target, a symlink to add (repeatable)")
	flag.Parse()
	if err := run(*appimage, *out, ls); err != nil {
		fmt.Fprintln(os.Stderr, "appimage-closure:", err)
		os.Exit(1)
	}
}

func run(appimage, out string, ls links) error {
	if appimage == "" || out == "" {
		return fmt.Errorf("-appimage and -out are required")
	}
	t, err := tree.OpenAppImage(appimage)
	if err != nil {
		return err
	}
	res, err := closure.Compute(t)
	if err != nil {
		return err
	}
	extra, err := parseLinks(ls, res)
	if err != nil {
		return err
	}
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(f, 1<<20)
	if err := closure.WriteTar(bw, t, res, extra); err != nil {
		f.Close()
		return err
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		return err
	}
	fmt.Fprintf(os.Stderr, "appimage-closure: %d paths from %s, entry /%s\n", len(res.Nodes), res.Root, res.Entry)
	return f.Close()
}

func parseLinks(ls links, res *closure.Result) ([]closure.Link, error) {
	var out []closure.Link
	for _, l := range ls {
		name, target, ok := strings.Cut(l, "=")
		if !ok || name == "" || target == "" {
			return nil, fmt.Errorf("-link %q is not name=target", l)
		}
		target = strings.Replace(target, "@entry", "/"+res.Entry, 1)
		target = strings.Replace(target, "@root", "/"+res.Root, 1)
		out = append(out, closure.Link{Name: name, Target: target})
	}
	return out, nil
}
