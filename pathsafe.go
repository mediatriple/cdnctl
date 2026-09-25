package main

// Name and path checks for folder transfers.
//
// A tar from the server, a tree listing and a local folder all hand cdnctl
// names it will join onto a path on this machine or send to the pod. A name
// with "..", a leading "/" or a backslash can climb out of the target folder
// once joined; a newline breaks the pod's line-based sums file; and on Windows
// "CON.txt" or "a:b" are not files at all. Such names are refused and reported,
// never written.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"
)

// reservedName marks names the server and cdnctl keep for themselves: temp
// files of put() and upload sessions (.cdn-upload.*), and cdnctl's own temp
// files and control members (.cdnctl-*). They are never listed, transferred,
// written or deleted by a transfer.
func reservedName(segment string) bool {
	return strings.HasPrefix(segment, ".cdn-upload.") || strings.HasPrefix(segment, ".cdnctl-")
}

// hasReservedSegment reports whether any segment of a slash path is reserved.
func hasReservedSegment(rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		if reservedName(seg) {
			return true
		}
	}
	return false
}

// cleanTarName drops the "./" GNU tar writes in front of every member and a
// directory's trailing slash. "" is the archived folder itself.
func cleanTarName(name string) string {
	name = withoutDotSlash(name)
	name = strings.TrimRight(name, "/")
	if name == "." {
		return ""
	}
	return name
}

// checkRelName validates a slash-separated path relative to a transfer root.
// windows adds the rules of Windows file names; callers pass it when the path
// is about to become a local file on Windows.
func checkRelName(rel string, windows bool) error {
	if rel == "" {
		return errors.New("empty name")
	}
	if !utf8.ValidString(rel) {
		return errors.New("name is not valid UTF-8")
	}
	if strings.HasPrefix(rel, "/") {
		return errors.New("absolute path")
	}
	if strings.Contains(rel, `\`) {
		return errors.New("backslash in name")
	}
	for _, r := range rel {
		if unicode.IsControl(r) {
			return errors.New("control character in name")
		}
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return errors.New("empty, \".\" or \"..\" path segment")
		}
		if reservedName(seg) {
			return fmt.Errorf("reserved name %q", seg)
		}
		if windows {
			if err := checkWindowsSegment(seg); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkWindowsSegment applies the Windows file-name rules to one segment. It is
// a plain function (not behind a build tag) so every OS runs its tests.
func checkWindowsSegment(seg string) error {
	if strings.ContainsAny(seg, `<>:"|?*`) {
		return errors.New(`name contains one of <>:"|?* (not allowed on Windows)`)
	}
	if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
		return errors.New("name ends with a dot or space (not allowed on Windows)")
	}
	base := seg
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL":
		return fmt.Errorf("%q is a reserved device name on Windows", seg)
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
		return fmt.Errorf("%q is a reserved device name on Windows", seg)
	}
	return nil
}

// localNameRules says whether names that become local files must follow the
// Windows rules on this machine.
func localNameRules() bool {
	return runtime.GOOS == "windows"
}

// ensureLocalDirs makes every directory of rel below root exist as a real
// directory. A component that is a symlink is refused rather than followed: a
// link placed in the target folder (by anyone) must not redirect a download
// somewhere else on the disk. created collects what was made, for cleanup.
func ensureLocalDirs(root, rel string, created *[]string) error {
	if rel == "" {
		return nil
	}
	cur := root
	for _, seg := range strings.Split(rel, "/") {
		cur = filepath.Join(cur, seg)
		info, err := os.Lstat(cur)
		switch {
		case err == nil && info.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("%s is a symlink; not written through", cur)
		case err == nil && !info.IsDir():
			return fmt.Errorf("%s is in the way (not a folder)", cur)
		case err == nil:
			continue
		case os.IsNotExist(err):
			if err := os.Mkdir(cur, 0o755); err != nil {
				return fmt.Errorf("cannot create %s: %w", cur, err)
			}
			if created != nil {
				*created = append(*created, cur)
			}
		default:
			return err
		}
	}
	return nil
}

// noSymlinkParents checks, without creating anything, that every directory
// between root and rel's parent is a real directory.
func noSymlinkParents(root, rel string) error {
	dir := filepath.Dir(filepath.FromSlash(rel))
	if dir == "." {
		return nil
	}
	cur := root
	for _, seg := range strings.Split(filepath.ToSlash(dir), "/") {
		cur = filepath.Join(cur, seg)
		info, err := os.Lstat(cur)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%s is not a plain folder", cur)
		}
	}
	return nil
}
