package main

// `cdnctl sync SRC DST` — rsync-like, one direction per run: exactly one side
// is remote (scp syntax, ":path" for the default account), and the CONTENTS of
// SRC go into DST whether or not SRC ends with a slash (rsync's trailing-slash
// rule trips people up more than it helps; the mapping is printed instead).
//
// Both sides are listed first (remote: one tree call), compared by type, size
// and whole-second mtime (or SHA-256 with --checksum), and only what differs
// moves — as one tar either way. --delete is opt-in and deliberately timid: it
// is refused when SRC is empty or the count exceeds --max-delete, and skipped
// entirely when anything in the run failed, because a partial picture of SRC
// looks exactly like "these files were removed".

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// syncTarBatch is how many names one download request carries (a var so tests
// can shrink it).
var syncTarBatch = 2000

const syncUsage = "usage: cdnctl sync <src> <dst> [--account <uuid>] [--delete] [--max-delete N] [--dry-run] [-c|--checksum] [--exclude PATTERN ...] [--modify-window N]\n" +
	"       one side is remote: <account_uuid>:path or :path (default account)"

// sync takes --delete/--dry-run/--checksum as switches and never lets them
// swallow the next word: with the generic parser `--dry-run ./site :www`
// would read "./site" as the value of --dry-run and run for real.
var (
	syncSwitches = map[string]bool{"delete": true, "dry_run": true, "checksum": true}
	syncValued   = map[string]bool{"max_delete": true, "exclude": true, "modify_window": true, "account": true, "lang": true}
)

func parseSyncArgs(raw []string) (parsedArgs, error) {
	out := parsedArgs{Options: map[string]string{}, Bools: map[string]bool{}, Multi: map[string][]string{}}
	for i := 0; i < len(raw); i++ {
		arg := raw[i]
		switch {
		case arg == "--":
			out.Positionals = append(out.Positionals, raw[i+1:]...)
			return out, nil
		case arg == "-c":
			out.Bools["checksum"] = true
			continue
		case !strings.HasPrefix(arg, "-") || arg == "-":
			out.Positionals = append(out.Positionals, arg)
			continue
		case !strings.HasPrefix(arg, "--"):
			return out, fmt.Errorf("unknown option %s", arg)
		}
		name, value, hasValue := strings.Cut(arg[2:], "=")
		key := strings.ReplaceAll(name, "-", "_")
		switch {
		case syncSwitches[key]:
			if hasValue {
				return out, fmt.Errorf("--%s takes no value", name)
			}
			out.Bools[key] = true
			out.Options[key] = "true"
		case syncValued[key]:
			if !hasValue {
				if i+1 >= len(raw) {
					return out, fmt.Errorf("--%s needs a value", name)
				}
				i++
				value = raw[i]
			}
			out.Options[key] = value
			out.Multi[key] = append(out.Multi[key], value)
		default:
			return out, fmt.Errorf("unknown option --%s", name)
		}
	}
	return out, nil
}

func syncOptionsFrom(args parsedArgs) (syncOptions, error) {
	opts := syncOptions{
		Delete:    args.Bools["delete"],
		DryRun:    args.Bools["dry_run"],
		Checksum:  args.Bools["checksum"],
		MaxDelete: -1,
	}
	if v, ok := args.Options["max_delete"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return opts, fmt.Errorf("--max-delete must be a whole number ≥ 0")
		}
		opts.MaxDelete = n
	}
	if v, ok := args.Options["modify_window"]; ok {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return opts, fmt.Errorf("--modify-window must be a whole number of seconds ≥ 0")
		}
		opts.ModifyWindow = n
	}
	for _, p := range args.Multi["exclude"] {
		rule, err := compileExclude(p)
		if err != nil {
			return opts, err
		}
		opts.Excludes = append(opts.Excludes, rule)
	}
	return opts, nil
}

// remoteSide reads one sync operand the way cp does: an existing local path
// whose name merely contains a colon stays local.
func remoteSide(s string) (account, remotePath string, remote bool) {
	account, remotePath, remote = parseRemoteSpec(s)
	if remote && account != "" && localPathExists(s) {
		return "", "", false
	}
	return account, remotePath, remote
}

func remoteFolder(p string) string {
	p = strings.Trim(p, "/")
	if p == "." {
		return ""
	}
	return p
}

// walkLocal lists everything under root without following symlinks (root
// itself may be one). Entries that cannot be read are returned as problems.
func walkLocal(root string) (map[string]fsEntry, []pathNote, error) {
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, nil, err
	}
	info, err := os.Stat(real)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("%s is not a folder", root)
	}
	entries := map[string]fsEntry{}
	var problems []pathNote
	err = filepath.WalkDir(real, func(p string, d fs.DirEntry, walkErr error) error {
		if p == real {
			return walkErr
		}
		relOS, relErr := filepath.Rel(real, p)
		if relErr != nil {
			return relErr
		}
		rel := filepath.ToSlash(relOS)
		if walkErr != nil {
			problems = append(problems, pathNote{rel, walkErr.Error()})
			return nil
		}
		fi, infoErr := d.Info()
		if infoErr != nil {
			problems = append(problems, pathNote{rel, infoErr.Error()})
			return nil
		}
		e := fsEntry{Type: 'o', Mtime: fi.ModTime().Unix()}
		switch mode := fi.Mode(); {
		case mode.IsDir():
			e.Type = 'd'
		case mode&fs.ModeSymlink != 0:
			e.Type = 'l'
		case mode.IsRegular():
			e.Type = 'f'
			e.Size = fi.Size()
		}
		entries[rel] = e
		return nil
	})
	return entries, problems, err
}

type syncReport struct {
	direction, source, destination string
	transferred                    int
	bytes                          int64
	deleted                        int
	skipped, failed                []pathNote
	dryRun                         bool
	message                        string
}

func (r syncReport) print() error {
	ok := len(r.failed) == 0 && r.message == ""
	skipped, failed := r.skipped, r.failed
	if skipped == nil {
		skipped = []pathNote{}
	}
	if failed == nil {
		failed = []pathNote{}
	}
	summary := map[string]any{
		"status":      ok,
		"direction":   r.direction,
		"source":      r.source,
		"destination": r.destination,
		"transferred": r.transferred,
		"bytes":       r.bytes,
		"deleted":     r.deleted,
		"skipped":     skipped,
		"failed":      failed,
		"dry_run":     r.dryRun,
	}
	if r.message != "" {
		summary["message"] = r.message
	}
	if err := printJSON(summary); err != nil {
		return err
	}
	if !ok {
		return errExit(1)
	}
	return nil
}

func countFiles(paths []string, entries map[string]fsEntry) int {
	n := 0
	for _, p := range paths {
		if entries[p].Type == 'f' {
			n++
		}
	}
	return n
}

func cmdSync(raw []string) error {
	args, err := parseSyncArgs(raw)
	if err != nil {
		return errExitMessage(2, err.Error()+"\n"+syncUsage)
	}
	if len(args.Positionals) != 2 {
		return errExitMessage(2, syncUsage)
	}
	opts, err := syncOptionsFrom(args)
	if err != nil {
		return errExitMessage(2, err.Error())
	}
	src, dst := args.Positionals[0], args.Positionals[1]
	srcAccount, srcPath, srcRemote := remoteSide(src)
	dstAccount, dstPath, dstRemote := remoteSide(dst)
	if srcRemote == dstRemote {
		return errExitMessage(2, "exactly one of <src> and <dst> must be remote (<account_uuid>:path or :path)\n"+syncUsage)
	}
	account := srcAccount
	if dstRemote {
		account = dstAccount
	}
	if account == "" {
		if account, err = resolveAccountE(args); err != nil {
			return err
		}
	}
	if srcRemote {
		return syncDownload(account, remoteFolder(srcPath), src, dst, opts)
	}
	return syncUpload(account, src, remoteFolder(dstPath), dst, opts)
}

func printPlan(plan syncPlan) {
	for _, op := range plan.Ops {
		fmt.Fprintln(os.Stderr, op.String())
	}
}

// listingProblems turns find's exit code into a report line.
func listingProblems(rc int, side string) []pathNote {
	if rc == 0 {
		return nil
	}
	return []pathNote{{Path: "(" + side + ")", Reason: fmt.Sprintf("the listing had errors (find exit code %d)", rc)}}
}

func serverProblem(answer map[string]any) pathNote {
	reason := firstNonEmpty(strval(answer["message"]), strval(answer["error"]), strval(answer["raw_body"]), "request failed")
	if code := strval(answer["error_code"]); code != "" {
		reason = code + ": " + reason
	}
	return pathNote{Path: "(server)", Reason: reason}
}

func syncDownload(account, folder, src, dst string, opts syncOptions) error {
	rep := syncReport{direction: "download", source: src, destination: dst, dryRun: opts.DryRun}
	fmt.Fprintf(os.Stderr, "sync (download): the contents of %s go into %s\n", displayRemote(folder), dst)

	tree, answer, err := fetchTree(account, folder, opts.Checksum)
	if err != nil {
		rep.failed = []pathNote{{Path: "(remote listing)", Reason: err.Error()}}
		return rep.print()
	}
	if answer != nil {
		if streamUnsupported(answer) {
			fmt.Fprintln(os.Stderr, "This account's server cannot list a folder in one call yet; `cdnctl cp -r` still copies file by file.")
		}
		return printFileResponse(answer)
	}
	if tree.Missing {
		// A typo in the remote path must not look like "already in sync".
		rep.failed = []pathNote{{Path: displayRemote(folder), Reason: "the source folder does not exist on the server"}}
		return rep.print()
	}
	local := map[string]fsEntry{}
	var localErrs []pathNote
	if info, statErr := os.Stat(dst); statErr == nil {
		if !info.IsDir() {
			return errExitMessage(1, dst+" is not a folder")
		}
		if local, localErrs, err = walkLocal(dst); err != nil {
			rep.failed = []pathNote{{Path: "(local listing)", Reason: err.Error()}}
			return rep.print()
		}
	} else if !os.IsNotExist(statErr) {
		return statErr
	}

	opts.Windows = localNameRules()
	plan := planSync(tree.Entries, local, opts, func(side int, rel string) (string, error) {
		if side == 0 {
			if s, ok := tree.Sums[rel]; ok {
				return s, nil
			}
			return "", errors.New("no checksum from the server")
		}
		return fileSHA256(filepath.Join(dst, filepath.FromSlash(rel)))
	})
	protectCaseTwins(&plan, tree.Entries)
	printPlan(plan)
	listingErrs := append(listingProblems(tree.RC, "remote"), localErrs...)
	rep.skipped = plan.Skipped
	rep.failed = append(append([]pathNote{}, plan.Failed...), listingErrs...)

	if refusal := deletionRefusal(plan, opts); refusal != "" {
		rep.message = refusal
		return rep.print()
	}
	if opts.DryRun {
		rep.transferred = countFiles(plan.Transfer, tree.Entries)
		rep.bytes = plan.Bytes
		if deletionSkipReason(len(listingErrs) > 0, len(rep.failed)) == "" {
			rep.deleted = len(plan.Deletes)
		}
		return rep.print()
	}

	if len(plan.Transfer) > 0 {
		fmt.Fprintf(os.Stderr, "Downloading %d entries (%s) as one archive…\n", len(plan.Transfer), humanBytes(plan.Bytes))
		only := map[string]bool{}
		for _, rel := range plan.Transfer {
			only[rel] = true
		}
		// The names travel in the request body, which the panel logs and PHP caps
		// (post_max_size); a first sync of a big site can list tens of thousands.
		// So ask in batches: each is its own verified archive.
		for start := 0; start < len(plan.Transfer); start += syncTarBatch {
			batch := plan.Transfer[start:min(start+syncTarBatch, len(plan.Transfer))]
			if len(plan.Transfer) > syncTarBatch {
				fmt.Fprintf(os.Stderr, "  archive %d–%d of %d\n", start+1, start+len(batch), len(plan.Transfer))
			}
			res, answer, err := downloadTar(account, folder, batch, extractOptions{root: dst, force: true, only: only, windows: opts.Windows})
			switch {
			case answer != nil:
				rep.failed = append(rep.failed, serverProblem(answer))
			case err != nil:
				rep.failed = append(rep.failed, pathNote{Path: "(download)", Reason: err.Error()})
			default:
				rep.transferred += countFiles(res.Placed, tree.Entries)
				rep.bytes += res.Bytes
				rep.failed = append(rep.failed, res.Failed...)
				rep.failed = append(rep.failed, tarProblems(res)...)
				for _, n := range res.Skipped {
					if n.Reason != "not requested" {
						rep.skipped = append(rep.skipped, n)
					}
				}
				for _, rel := range batch {
					if !res.Received[rel] {
						rep.failed = append(rep.failed, pathNote{rel, "not in the archive (vanished or unreadable on the server)"})
					}
				}
			}
		}
	}

	if opts.Delete && len(plan.Deletes) > 0 {
		if reason := deletionSkipReason(len(listingErrs) > 0, len(rep.failed)); reason != "" {
			fmt.Fprintln(os.Stderr, "--delete: "+reason)
		} else {
			deleted, problems := deleteLocal(dst, plan.Deletes)
			rep.deleted = deleted
			rep.failed = append(rep.failed, problems...)
		}
	}
	fmt.Fprintln(os.Stderr)
	return rep.print()
}

// deleteLocal removes DST entries SRC lacks: files first, then folders deepest
// first and only when empty. Nothing is removed through a symlinked folder, and
// an entry that is no longer what the listing said is left alone.
func deleteLocal(root string, rels []string) (int, []pathNote) {
	deleted := 0
	var problems []pathNote
	var dirs []string
	for _, rel := range rels {
		if err := noSymlinkParents(root, rel); err != nil {
			problems = append(problems, pathNote{rel, "not deleted: " + err.Error()})
			continue
		}
		p := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Lstat(p)
		switch {
		case os.IsNotExist(err):
			continue
		case err != nil:
			problems = append(problems, pathNote{rel, err.Error()})
		case info.IsDir():
			dirs = append(dirs, rel)
		case info.Mode().IsRegular():
			if err := os.Remove(p); err != nil {
				problems = append(problems, pathNote{rel, err.Error()})
				continue
			}
			deleted++
			fmt.Fprintf(os.Stderr, "  deleted   %s\n", rel)
		}
	}
	sort.Slice(dirs, func(i, j int) bool {
		di, dj := strings.Count(dirs[i], "/"), strings.Count(dirs[j], "/")
		if di != dj {
			return di > dj
		}
		return dirs[i] > dirs[j]
	})
	for _, rel := range dirs {
		// a folder that still holds something (excluded, a symlink) stays
		if err := os.Remove(filepath.Join(root, filepath.FromSlash(rel))); err == nil {
			deleted++
			fmt.Fprintf(os.Stderr, "  deleted   %s/\n", rel)
		}
	}
	return deleted, problems
}

func syncUpload(account, src, folder, dst string, opts syncOptions) error {
	rep := syncReport{direction: "upload", source: src, destination: dst, dryRun: opts.DryRun}
	fmt.Fprintf(os.Stderr, "sync (upload): the contents of %s go into %s\n", src, displayRemote(folder))

	local, localErrs, err := walkLocal(src)
	if err != nil {
		return errExitMessage(1, fmt.Sprintf("cannot read the source folder %s: %v", src, err))
	}
	tree, answer, err := fetchTree(account, folder, opts.Checksum)
	if err != nil {
		rep.failed = []pathNote{{Path: "(remote listing)", Reason: err.Error()}}
		return rep.print()
	}
	if answer != nil {
		if streamUnsupported(answer) {
			fmt.Fprintln(os.Stderr, "This account's server cannot list a folder in one call yet; `cdnctl cp -r` still copies file by file.")
		}
		return printFileResponse(answer)
	}

	plan := planSync(local, tree.Entries, opts, func(side int, rel string) (string, error) {
		if side == 0 {
			return fileSHA256(filepath.Join(src, filepath.FromSlash(rel)))
		}
		if s, ok := tree.Sums[rel]; ok {
			return s, nil
		}
		return "", errors.New("no checksum from the server")
	})
	printPlan(plan)
	listingErrs := append(append([]pathNote{}, localErrs...), listingProblems(tree.RC, "remote")...)
	rep.skipped = plan.Skipped
	rep.failed = append(append([]pathNote{}, plan.Failed...), listingErrs...)

	if refusal := deletionRefusal(plan, opts); refusal != "" {
		rep.message = refusal
		return rep.print()
	}
	var deletes []string
	if opts.Delete && len(plan.Deletes) > 0 {
		if reason := deletionSkipReason(len(listingErrs) > 0, len(rep.failed)); reason != "" {
			fmt.Fprintln(os.Stderr, "--delete: "+reason)
		} else {
			deletes = plan.Deletes
		}
	}
	if opts.DryRun {
		rep.transferred = countFiles(plan.Transfer, local)
		rep.bytes = plan.Bytes
		rep.deleted = len(deletes)
		return rep.print()
	}
	if len(plan.Transfer) == 0 && len(deletes) == 0 {
		fmt.Fprintln(os.Stderr)
		return rep.print()
	}

	items := make([]uploadItem, 0, len(plan.Transfer))
	for _, rel := range plan.Transfer {
		items = append(items, uploadItem{Rel: rel, Local: filepath.Join(src, filepath.FromSlash(rel)), Dir: local[rel].Type == 'd'})
	}
	fmt.Fprintf(os.Stderr, "Uploading %d entries (%s) as one archive…\n", len(items), humanBytes(plan.Bytes))
	out, answer, err := uploadTar(account, folder, items, deletes, true, os.Stderr)
	switch {
	case err != nil:
		rep.failed = append(rep.failed, pathNote{Path: "(upload)", Reason: err.Error()})
	case answer != nil:
		rep.failed = append(rep.failed, serverProblem(answer))
	default:
		rep.failed = append(rep.failed, out.Build.Failed...)
		for _, p := range out.BadSum {
			rep.failed = append(rep.failed, pathNote{p, "checksum mismatch on the server; not placed"})
		}
		for _, p := range out.NotPlaced {
			rep.failed = append(rep.failed, pathNote{p, "not placed"})
		}
		for _, p := range out.Conflicts {
			rep.failed = append(rep.failed, pathNote{p, "something else is in the way on the server"})
		}
		if !responseOK(out.Answer) && len(out.BadSum)+len(out.NotPlaced)+len(out.Conflicts) == 0 {
			rep.failed = append(rep.failed, serverProblem(out.Answer))
		}
		rep.transferred = out.Placed
		rep.bytes = out.Build.Bytes
		rep.deleted = out.Deleted
		if len(deletes) > 0 && !out.DeleteListed {
			fmt.Fprintln(os.Stderr, "--delete: a file failed while it was being read; skipping deletion")
		}
	}
	fmt.Fprintln(os.Stderr)
	return rep.print()
}
