// Package tree is the read-only view of a filesystem that the closure walk
// needs: no symlink is followed by the methods, so the walker sees links.
package tree

import (
	"io/fs"
	"strings"
)

// Node is one entry as lstat would report it.
type Node struct {
	// Mode has the type bits (fs.ModeSymlink, fs.ModeDir) and the permission bits.
	Mode fs.FileMode
	// Target is the link target of a symlink, verbatim.
	Target string
}

// Tree is a filesystem whose paths are slash-separated and have no leading
// slash ("nix/store/...").
type Tree interface {
	// Lstat describes name without following it if it is a symlink.
	Lstat(name string) (Node, error)
	// ReadFile reads a regular file (not a symlink).
	ReadFile(name string) ([]byte, error)
	// ReadDir lists a directory's entry names, sorted.
	ReadDir(name string) ([]string, error)
}

// Clean makes p a Tree path: no leading or trailing slash, no "." or ".."
// components left to resolve against the filesystem.
func Clean(p string) string {
	var out []string
	for _, c := range strings.Split(p, "/") {
		switch c {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, c)
		}
	}
	return strings.Join(out, "/")
}
