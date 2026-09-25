package main

// The part of `cdnctl sync` that decides, without touching anything: which
// entries of SRC are new or changed in DST, which entries of DST SRC lacks
// (for --delete), and what is skipped. Both listings are maps of slash paths
// relative to their roots, so the same planner serves both directions.

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// excludeRule is one --exclude pattern, the subset of rsync's rules people
// actually use: no "/" matches a name at any depth, a leading "/" anchors at
// the SRC root, a trailing "/" matches directories only, "*" and "?" stay
// within one path segment, "**" crosses segments.
type excludeRule struct {
	raw      string
	dirOnly  bool
	fullPath bool
	re       *regexp.Regexp
}

func compileExclude(pattern string) (excludeRule, error) {
	rule := excludeRule{raw: pattern}
	p := pattern
	if strings.HasSuffix(p, "/") {
		rule.dirOnly = true
		p = strings.TrimRight(p, "/")
	}
	anchored := strings.HasPrefix(p, "/")
	p = strings.TrimLeft(p, "/")
	if p == "" {
		return rule, fmt.Errorf("--exclude %q matches nothing", pattern)
	}
	rule.fullPath = anchored || strings.Contains(p, "/") || strings.Contains(p, "**")
	body, err := globToRegexp(p)
	if err != nil {
		return rule, fmt.Errorf("--exclude %q: %v", pattern, err)
	}
	switch {
	case anchored || !rule.fullPath:
		body = "^" + body + "$"
	default:
		// "a/b" without a leading "/" may sit at any depth, as in rsync
		body = "^(?:.*/)?" + body + "$"
	}
	rule.re, err = regexp.Compile(body)
	if err != nil {
		return rule, fmt.Errorf("--exclude %q: %v", pattern, err)
	}
	return rule, nil
}

func globToRegexp(p string) (string, error) {
	var sb strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch c {
		case '*':
			if i+1 < len(p) && p[i+1] == '*' {
				sb.WriteString(".*")
				i++
			} else {
				sb.WriteString("[^/]*")
			}
		case '?':
			sb.WriteString("[^/]")
		case '\\':
			if i+1 < len(p) {
				i++
				sb.WriteString(regexp.QuoteMeta(string(p[i])))
			} else {
				sb.WriteString(`\\`)
			}
		case '[':
			end := strings.IndexByte(p[i+1:], ']')
			if end < 0 {
				sb.WriteString(`\[`)
				continue
			}
			class := p[i+1 : i+1+end]
			if class == "" {
				return "", errors.New("empty [] class")
			}
			if class[0] == '!' {
				class = "^" + class[1:]
			}
			sb.WriteString("[" + strings.ReplaceAll(class, `\`, `\\`) + "]")
			i += end + 1
		default:
			sb.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return sb.String(), nil
}

func (r excludeRule) matches(path, name string, isDir bool) bool {
	if r.dirOnly && !isDir {
		return false
	}
	if r.fullPath {
		return r.re.MatchString(path)
	}
	return r.re.MatchString(name)
}

// isExcluded checks rel and every folder above it: an excluded folder
// excludes everything inside it.
func isExcluded(rules []excludeRule, rel string, isDir bool) bool {
	if len(rules) == 0 {
		return false
	}
	parts := strings.Split(rel, "/")
	for i := 1; i <= len(parts); i++ {
		path := strings.Join(parts[:i], "/")
		dir := i < len(parts) || isDir
		for _, r := range rules {
			if r.matches(path, parts[i-1], dir) {
				return true
			}
		}
	}
	return false
}

type syncOptions struct {
	Delete       bool
	MaxDelete    int // < 0: no limit
	DryRun       bool
	Checksum     bool
	ModifyWindow int64
	Excludes     []excludeRule
	// Windows applies the Windows name rules to what is transferred (a
	// download onto a Windows machine).
	Windows bool
}

type planOp struct {
	Op     byte // + new, ~ update, - delete, ! skip
	Path   string
	Reason string
	Dir    bool
}

type syncPlan struct {
	Ops      []planOp // every line of the plan, sorted by path
	Transfer []string // new folders and new/changed files, sorted
	Deletes  []string // DST entries SRC lacks (only with --delete), sorted
	Skipped  []pathNote
	Failed   []pathNote
	Bytes    int64 // size of the files in Transfer
	// SourceCount is the number of files and folders SRC offers after
	// excludes; zero refuses --delete (an empty or wrong SRC would empty DST).
	SourceCount int
}

// checksumFunc returns the SHA-256 of rel on one side (0 = SRC, 1 = DST).
type checksumFunc func(side int, rel string) (string, error)

func sortedKeys(m map[string]fsEntry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func entryIsDir(e fsEntry) bool { return e.Type == 'd' }

func typeWord(t byte) string {
	switch t {
	case 'f':
		return "file"
	case 'd':
		return "folder"
	case 'l':
		return "symlink"
	}
	return "special"
}

// planSync compares src with dst. It never touches either side.
func planSync(src, dst map[string]fsEntry, opts syncOptions, sum checksumFunc) syncPlan {
	var plan syncPlan
	// blocked: SRC paths whose DST counterparts and contents must be left alone
	// (a symlink or special file in SRC, a refused name, a conflict).
	blocked := map[string]bool{}
	skip := func(rel, reason string, dir bool) {
		plan.Ops = append(plan.Ops, planOp{Op: '!', Path: rel, Reason: reason, Dir: dir})
		plan.Skipped = append(plan.Skipped, pathNote{rel, reason})
		blocked[rel] = true
	}
	fail := func(rel, reason string) {
		plan.Ops = append(plan.Ops, planOp{Op: '!', Path: rel, Reason: reason})
		plan.Failed = append(plan.Failed, pathNote{rel, reason})
		blocked[rel] = true
	}

	for _, rel := range sortedKeys(src) {
		e := src[rel]
		if isExcluded(opts.Excludes, rel, entryIsDir(e)) {
			continue
		}
		if under(blocked, rel) {
			continue
		}
		if hasReservedSegment(rel) {
			skip(rel, "name", entryIsDir(e))
			continue
		}
		if e.Type != 'f' && e.Type != 'd' {
			skip(rel, typeWord(e.Type), false)
			continue
		}
		if err := checkRelName(rel, opts.Windows); err != nil {
			skip(rel, "name", entryIsDir(e))
			continue
		}
		plan.SourceCount++
		d, exists := dst[rel]
		switch {
		case !exists:
			plan.Ops = append(plan.Ops, planOp{Op: '+', Path: rel, Dir: entryIsDir(e)})
			plan.Transfer = append(plan.Transfer, rel)
			if e.Type == 'f' {
				plan.Bytes += e.Size
			}
		case d.Type == 'l' || (d.Type != 'f' && d.Type != 'd'):
			// DST has a symlink or special file here; it is neither replaced nor deleted
			skip(rel, typeWord(d.Type)+" in the destination", entryIsDir(e))
		case d.Type != e.Type:
			fail(rel, fmt.Sprintf("a %s in the source, a %s in the destination", typeWord(e.Type), typeWord(d.Type)))
		case e.Type == 'd':
			// same folder on both sides: nothing to do
		default:
			reason := ""
			switch {
			case e.Size != d.Size:
				reason = "size"
			case opts.Checksum:
				a, errA := sum(0, rel)
				b, errB := sum(1, rel)
				if errA != nil || errB != nil {
					fail(rel, "checksum unavailable")
					continue
				}
				if a != b {
					reason = "checksum"
				}
			case absDiff(e.Mtime, d.Mtime) > opts.ModifyWindow:
				reason = "mtime"
			}
			if reason != "" {
				plan.Ops = append(plan.Ops, planOp{Op: '~', Path: rel, Reason: reason})
				plan.Transfer = append(plan.Transfer, rel)
				plan.Bytes += e.Size
			}
		}
	}

	if opts.Delete {
		for _, rel := range sortedKeys(dst) {
			if _, inSrc := src[rel]; inSrc {
				continue
			}
			d := dst[rel]
			if isExcluded(opts.Excludes, rel, entryIsDir(d)) || hasReservedSegment(rel) || under(blocked, rel) {
				continue
			}
			if d.Type != 'f' && d.Type != 'd' {
				plan.Ops = append(plan.Ops, planOp{Op: '!', Path: rel, Reason: typeWord(d.Type)})
				plan.Skipped = append(plan.Skipped, pathNote{rel, typeWord(d.Type) + " (not deleted)"})
				continue
			}
			plan.Ops = append(plan.Ops, planOp{Op: '-', Path: rel, Dir: entryIsDir(d)})
			plan.Deletes = append(plan.Deletes, rel)
		}
	}

	sort.SliceStable(plan.Ops, func(i, j int) bool { return plan.Ops[i].Path < plan.Ops[j].Path })
	return plan
}

// under reports whether rel or a folder above it is in set.
func under(set map[string]bool, rel string) bool {
	if len(set) == 0 {
		return false
	}
	for p := rel; ; {
		if set[p] {
			return true
		}
		i := strings.LastIndexByte(p, '/')
		if i < 0 {
			return false
		}
		p = p[:i]
	}
}

func absDiff(a, b int64) int64 {
	if a > b {
		return a - b
	}
	return b - a
}

// deletionRefusal is checked before anything is transferred: a --delete that
// would empty DST because SRC is empty (a wrong or unmounted path), or that
// would remove more than --max-delete allows, stops the whole run.
func deletionRefusal(plan syncPlan, opts syncOptions) string {
	if !opts.Delete {
		return ""
	}
	if plan.SourceCount == 0 {
		return "the source is empty; refusing --delete (it would empty the destination)"
	}
	if opts.MaxDelete >= 0 && len(plan.Deletes) > opts.MaxDelete {
		return fmt.Sprintf("--delete would remove %d entries, more than --max-delete %d; nothing was changed", len(plan.Deletes), opts.MaxDelete)
	}
	return ""
}

// deletionSkipReason is checked after the transfer: any failure in the run
// (a listing with errors, a refused or failed file, a tar that did not end
// cleanly) means the picture of SRC may be incomplete, so nothing is deleted —
// rsync's "IO error encountered -- skipping file deletion".
func deletionSkipReason(listingErrors bool, failures int) string {
	if listingErrors {
		return "a listing had errors; skipping deletion"
	}
	if failures > 0 {
		return "something in this run failed; skipping deletion"
	}
	return ""
}

func (op planOp) String() string {
	path := op.Path
	if op.Dir {
		path += "/"
	}
	switch op.Op {
	case '~':
		return fmt.Sprintf("~ %s (%s)", path, op.Reason)
	case '!':
		return fmt.Sprintf("! %s (%s)", path, op.Reason)
	default:
		return fmt.Sprintf("%c %s", op.Op, path)
	}
}

// protectCaseTwins keeps --delete from removing a local entry whose name differs
// from a source entry only in letter case. On a case-insensitive disk (macOS,
// Windows) README.md and readme.md are one file: the download replaces it, and
// deleting "readme.md" afterwards would remove what was just downloaded.
func protectCaseTwins(plan *syncPlan, src map[string]fsEntry) {
	if len(plan.Deletes) == 0 {
		return
	}
	folded := make(map[string]bool, len(src))
	for rel := range src {
		folded[strings.ToLower(rel)] = true
	}
	const reason = "differs from a source entry only in letter case; not deleted"
	keep := plan.Deletes[:0]
	protected := map[string]bool{}
	for _, rel := range plan.Deletes {
		if folded[strings.ToLower(rel)] {
			protected[rel] = true
			plan.Skipped = append(plan.Skipped, pathNote{rel, reason})
			continue
		}
		keep = append(keep, rel)
	}
	plan.Deletes = keep
	for i, op := range plan.Ops {
		if op.Op == '-' && protected[op.Path] {
			plan.Ops[i] = planOp{Op: '!', Path: op.Path, Reason: reason, Dir: op.Dir}
		}
	}
}
