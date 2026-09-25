package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func writeLocal(t *testing.T, root, rel, body string, mtime time.Time) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func exists(root, rel string) bool {
	_, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel)))
	return err == nil
}

func syncRun(t *testing.T, args ...string) (map[string]any, string, error) {
	t.Helper()
	stdout, stderr, err := captureOutput(t, func() error { return run(append([]string{"sync"}, args...)) })
	if strings.TrimSpace(stdout) == "" {
		return nil, stderr, err
	}
	return lastJSON(t, stdout), stderr, err
}

// downloadFixture: server site/ vs a local copy that is partly out of date.
func downloadFixture(t *testing.T) (*tarServer, string) {
	s := newTarServer(t)
	s.write("site/same.txt", "same", 0o644, fixedTime)
	s.write("site/changed.txt", "new content", 0o644, fixedTime.Add(time.Hour))
	s.write("site/new/c.txt", "c", 0o755, fixedTime)
	s.write("site/debug.log", "log", 0o644, fixedTime)
	dst := t.TempDir()
	writeLocal(t, dst, "same.txt", "same", fixedTime)
	writeLocal(t, dst, "changed.txt", "old", fixedTime)
	writeLocal(t, dst, "stale.txt", "stale", fixedTime)
	writeLocal(t, dst, "staledir/x", "x", fixedTime)
	writeLocal(t, dst, "local.log", "keep me", fixedTime)
	return s, dst
}

func TestSyncDownloadMovesOnlyTheDifferenceAndDeletes(t *testing.T) {
	s, dst := downloadFixture(t)
	sum, stderr, err := syncRun(t, "--delete", "--exclude", "*.log", "acct-uuid:site/", dst)
	if err != nil {
		t.Fatalf("sync failed: %v\n%s", err, stderr)
	}
	if strings.Join(s.tarFiles, ",") != "changed.txt,new,new/c.txt" {
		t.Fatalf("tar asked for %v", s.tarFiles)
	}
	for _, line := range []string{"~ changed.txt (size)", "+ new/", "+ new/c.txt", "- stale.txt", "- staledir/", "- staledir/x", "the contents of :site go into"} {
		if !strings.Contains(stderr, line) {
			t.Errorf("plan line %q missing:\n%s", line, stderr)
		}
	}
	if strings.Contains(stderr, "same.txt") || strings.Contains(stderr, ".log") {
		t.Errorf("unchanged or excluded entries in the plan:\n%s", stderr)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "changed.txt")); string(b) != "new content" {
		t.Error("changed.txt not updated")
	}
	info, _ := os.Stat(filepath.Join(dst, "changed.txt"))
	if !info.ModTime().Equal(fixedTime.Add(time.Hour)) {
		t.Errorf("mtime not preserved: %v", info.ModTime())
	}
	if exists(dst, "stale.txt") || exists(dst, "staledir") {
		t.Error("--delete did not remove what the source lacks")
	}
	if !exists(dst, "local.log") || exists(dst, "debug.log") {
		t.Error("an excluded file was deleted or transferred")
	}
	if sum["status"] != true || sum["direction"] != "download" || sum["transferred"] != float64(2) || sum["deleted"] != float64(3) || sum["dry_run"] != false {
		t.Errorf("summary %v", sum)
	}

	// a second run finds nothing to do and asks only for the listing
	before := len(s.callList())
	sum, stderr, err = syncRun(t, "--delete", "--exclude", "*.log", "acct-uuid:site", dst)
	if err != nil || sum["transferred"] != float64(0) || sum["deleted"] != float64(0) {
		t.Fatalf("second run: %v %v\n%s", err, sum, stderr)
	}
	if calls := s.callList()[before:]; len(calls) != 1 || !strings.HasPrefix(calls[0], "tree ") {
		t.Errorf("second run calls %v", calls)
	}
}

func TestSyncDryRunChangesNothingAndSendsNoTransfer(t *testing.T) {
	s, dst := downloadFixture(t)
	sum, stderr, err := syncRun(t, "--dry-run", "acct-uuid:site", dst, "--delete")
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}
	if calls := s.callList(); len(calls) != 1 || calls[0] != "tree site" {
		t.Fatalf("a dry run sent %v", calls)
	}
	if !exists(dst, "stale.txt") || exists(dst, "new") {
		t.Fatal("a dry run changed the destination")
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "changed.txt")); string(b) != "old" {
		t.Fatal("a dry run changed a file")
	}
	if sum["dry_run"] != true || sum["transferred"] != float64(3) || sum["deleted"] != float64(4) {
		t.Errorf("summary %v", sum)
	}
	if !strings.Contains(stderr, "+ debug.log") || !strings.Contains(stderr, "- local.log") {
		t.Errorf("plan:\n%s", stderr)
	}
}

func TestSyncSkipsDeletionWhenTheTarReportsErrors(t *testing.T) {
	s, dst := downloadFixture(t)
	s.tarRC = 2
	s.tarStderr = "tar: ./new/c.txt: Cannot open: Permission denied\n"
	sum, stderr, err := syncRun(t, "--delete", "acct-uuid:site", dst)
	if exitCode(err) != 1 {
		t.Fatalf("expected exit 1, got %v", err)
	}
	if !exists(dst, "stale.txt") {
		t.Fatal("deleted although the tar reported errors")
	}
	if sum["deleted"] != float64(0) || !strings.Contains(stderr, "skipping deletion") {
		t.Errorf("summary %v\n%s", sum, stderr)
	}
}

func TestSyncSkipsDeletionWhenARequestedFileNeverArrives(t *testing.T) {
	s, dst := downloadFixture(t)
	s.dropFromTar = map[string]bool{"new/c.txt": true}
	sum, _, err := syncRun(t, "--delete", "acct-uuid:site", dst)
	if exitCode(err) != 1 || !exists(dst, "stale.txt") {
		t.Fatalf("deletion ran after a missing file: %v %v", err, sum)
	}
	if !strings.Contains(strings.Join(failedPaths(sum), ","), "new/c.txt") {
		t.Errorf("the missing file was not reported: %v", sum["failed"])
	}
}

func failedPaths(sum map[string]any) []string {
	var out []string
	list, _ := sum["failed"].([]any)
	for _, it := range list {
		m, _ := it.(map[string]any)
		out = append(out, strval(m["path"]))
	}
	return out
}

func TestSyncMaxDeleteRefusesTheWholeRun(t *testing.T) {
	s, dst := downloadFixture(t)
	sum, _, err := syncRun(t, "--delete", "--max-delete", "2", "acct-uuid:site", dst)
	if exitCode(err) != 1 {
		t.Fatalf("expected exit 1, got %v", err)
	}
	if s.called("tar") != 0 || !exists(dst, "stale.txt") {
		t.Fatal("something was transferred or deleted despite --max-delete")
	}
	if !strings.Contains(strval(sum["message"]), "--max-delete 2") {
		t.Errorf("summary %v", sum)
	}
}

func TestSyncRefusesDeleteFromAnEmptyOrMissingSource(t *testing.T) {
	s := newTarServer(t)
	dst := t.TempDir()
	writeLocal(t, dst, "precious.txt", "x", fixedTime)
	sum, _, err := syncRun(t, "--delete", "acct-uuid:does-not-exist", dst)
	if exitCode(err) != 1 || !exists(dst, "precious.txt") {
		t.Fatalf("an empty source emptied the destination: %v", err)
	}
	if !strings.Contains(fmt.Sprint(sum["failed"]), "does not exist on the server") {
		t.Errorf("summary %v", sum)
	}
	// without --delete a missing source is an error too: a typo in the remote
	// path must not look like "already in sync"
	sum, _, err = syncRun(t, "acct-uuid:does-not-exist", dst)
	if exitCode(err) != 1 || sum["status"] != false || s.called("tar") != 0 || !exists(dst, "precious.txt") {
		t.Fatalf("%v %v", err, sum)
	}
	if !strings.Contains(fmt.Sprint(sum["failed"]), "does not exist on the server") {
		t.Errorf("summary %v", sum)
	}
}

func TestSyncChecksumCatchesSameSizeSameMtimeChanges(t *testing.T) {
	s := newTarServer(t)
	s.write("site/a.txt", "AAAA", 0o644, fixedTime)
	dst := t.TempDir()
	writeLocal(t, dst, "a.txt", "BBBB", fixedTime)
	if _, _, err := syncRun(t, "acct-uuid:site", dst); err != nil || s.called("tar") != 0 {
		t.Fatalf("without -c an equal size and mtime should count as equal: %v", err)
	}
	if _, stderr, err := syncRun(t, "-c", "acct-uuid:site", dst); err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "a.txt")); string(b) != "AAAA" {
		t.Fatal("-c did not update a file with different content")
	}
}

func TestSyncUploadMirrorsAndIsIdempotent(t *testing.T) {
	withPartSize(t, 2048)
	s := newTarServer(t)
	s.write("www/stale.php", "old", 0o644, fixedTime)
	s.write("www/stale-dir/y", "y", 0o644, fixedTime)
	s.write("www/keep.log", "server log", 0o644, fixedTime)
	s.write("www/changed.css", "a{}", 0o644, fixedTime)
	src := t.TempDir()
	writeLocal(t, src, "index.php", strings.Repeat("<?php ?>", 1000), fixedTime)
	writeLocal(t, src, "changed.css", "a{color:red}", fixedTime.Add(time.Minute))
	writeLocal(t, src, "sub/deep.txt", "deep", fixedTime)
	writeLocal(t, src, "local.log", "never sent", fixedTime)
	if runtime.GOOS != "windows" {
		_ = os.Symlink("index.php", filepath.Join(src, "link.php"))
	}

	sum, stderr, err := syncRun(t, src, "acct-uuid:www", "--delete", "--exclude", "*.log")
	if err != nil {
		t.Fatalf("upload sync failed: %v\n%s", err, stderr)
	}
	if s.applyReq["delete"] != true || s.applyReq["overwrite"] != true {
		t.Errorf("apply request %v", s.applyReq)
	}
	if len(s.parts) < 2 {
		t.Errorf("expected several parts, got %v", s.parts)
	}
	for rel, want := range map[string]string{"www/changed.css": "a{color:red}", "www/sub/deep.txt": "deep", "www/keep.log": "server log"} {
		if got, _ := s.read(rel); got != want {
			t.Errorf("%s = %q", rel, got)
		}
	}
	if _, ok := s.read("www/local.log"); ok {
		t.Error("an excluded file was uploaded")
	}
	if exists(s.root, "www/stale.php") || exists(s.root, "www/stale-dir") {
		t.Error("--delete did not remove the remote leftovers")
	}
	if exists(s.root, "www/link.php") {
		t.Error("a symlink was uploaded")
	}
	if sum["direction"] != "upload" || sum["transferred"] != float64(3) || sum["deleted"] != float64(2) {
		t.Errorf("summary %v", sum)
	}
	if runtime.GOOS != "windows" {
		if skipped, _ := sum["skipped"].([]any); len(skipped) != 1 || !strings.Contains(stderr, "! link.php (symlink)") {
			t.Errorf("the symlink was not reported as skipped: %v\n%s", sum["skipped"], stderr)
		}
	}

	parts := len(s.parts)
	sum, stderr, err = syncRun(t, src, "acct-uuid:www", "--delete", "--exclude", "*.log")
	if err != nil || sum["transferred"] != float64(0) || len(s.parts) != parts || s.called("tar-apply") != 1 {
		t.Fatalf("second run was not a no-op: %v %v parts %d→%d\n%s", err, sum, parts, len(s.parts), stderr)
	}
}

func TestSyncUploadSkipsDeletionAfterAFailure(t *testing.T) {
	s := newTarServer(t)
	s.write("www/x/inside", "dir on the server", 0o644, fixedTime)
	s.write("www/stale.txt", "stale", 0o644, fixedTime)
	src := t.TempDir()
	writeLocal(t, src, "x", "a file locally", fixedTime) // file vs folder: a conflict
	writeLocal(t, src, "ok.txt", "ok", fixedTime)
	sum, stderr, err := syncRun(t, "--delete", src, "acct-uuid:www")
	if exitCode(err) != 1 {
		t.Fatalf("expected exit 1, got %v", err)
	}
	if !exists(s.root, "www/stale.txt") {
		t.Fatal("deleted on the server although the run had a failure")
	}
	if got, _ := s.read("www/ok.txt"); got != "ok" {
		t.Error("the unaffected file was not uploaded")
	}
	if s.applyReq["delete"] != false || !strings.Contains(stderr, "skipping deletion") {
		t.Errorf("apply %v\n%s", s.applyReq, stderr)
	}
	if sum["deleted"] != float64(0) {
		t.Errorf("summary %v", sum)
	}
}

func TestSyncArgumentHandling(t *testing.T) {
	a, err := parseSyncArgs([]string{"--dry-run", "./site", ":www", "--delete", "-c", "--exclude", "*.log", "--exclude=cache/", "--max-delete=5"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(a.Positionals, " ") != "./site :www" {
		t.Fatalf("a switch swallowed a path: %v", a.Positionals)
	}
	if !a.Bools["dry_run"] || !a.Bools["delete"] || !a.Bools["checksum"] || a.Options["max_delete"] != "5" || len(a.Multi["exclude"]) != 2 {
		t.Fatalf("parsed %+v", a)
	}
	for _, bad := range [][]string{{"--delet", "a", ":b"}, {"--dry-run=yes", "a", ":b"}, {"-x", "a", ":b"}, {"a", ":b", "--exclude"}} {
		if _, err := parseSyncArgs(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	useServer(t, "http://127.0.0.1:0")
	for _, args := range [][]string{
		{"sync", "./a", "./b"},
		{"sync", ":a", "acct-uuid:b"},
		{"sync", "./a"},
		{"sync", "--max-delete", "-1", "./a", ":b"},
		{"sync", "--bogus", "./a", ":b"},
	} {
		if _, _, err := captureOutput(t, func() error { return run(args) }); exitCode(err) != 2 {
			t.Errorf("%v: exit %v", args, err)
		}
	}
}

func TestSyncRequiresAnAccount(t *testing.T) {
	useServer(t, "http://127.0.0.1:0")
	t.Setenv("CDN_ACCOUNT", "")
	_, _, err := captureOutput(t, func() error { return run([]string{"sync", ":site", t.TempDir()}) })
	if exitCode(err) != 2 || !strings.Contains(err.Error(), "No account selected") {
		t.Fatalf("got %v", err)
	}
}

func TestSyncToolMissingIsExplained(t *testing.T) {
	s := newTarServer(t)
	s.toolMissing = true
	_, stderr, err := syncRun(t, "acct-uuid:site", t.TempDir())
	if exitCode(err) != 1 || !strings.Contains(stderr, "cdnctl cp -r") {
		t.Fatalf("%v\n%s", err, stderr)
	}
}

func TestSyncWithACutListingChangesNothing(t *testing.T) {
	s, dst := downloadFixture(t)
	old := s.srv.Config.Handler
	s.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/files/tree") {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(w, "E f 4 1727262000.0 same.txt\x00") // no trailer: cut short
			return
		}
		old.ServeHTTP(w, r)
	})
	sum, _, err := syncRun(t, "--delete", "acct-uuid:site", dst)
	if exitCode(err) != 1 || !exists(dst, "stale.txt") || s.called("tar") != 0 {
		t.Fatalf("a cut listing was acted on: %v %v", err, sum)
	}
	if !strings.Contains(strings.Join(failedPaths(sum), ","), "(remote listing)") {
		t.Errorf("summary %v", sum)
	}
}

func TestSyncUploadReportsAServerChecksumMismatchAndDeletesNothing(t *testing.T) {
	s := newTarServer(t)
	s.write("www/stale.txt", "stale", 0o644, fixedTime)
	s.corruptStaged = "b.txt"
	src := t.TempDir()
	writeLocal(t, src, "a.txt", "a", fixedTime)
	writeLocal(t, src, "b.txt", "b", fixedTime)
	sum, _, err := syncRun(t, "--delete", src, "acct-uuid:www")
	if exitCode(err) != 1 {
		t.Fatalf("expected exit 1, got %v", err)
	}
	if s.applyReq["delete"] != true {
		t.Fatalf("the delete list should have been sent: %v", s.applyReq)
	}
	if !exists(s.root, "www/stale.txt") {
		t.Fatal("the server deleted although a file failed its checksum")
	}
	if _, ok := s.read("www/b.txt"); ok {
		t.Fatal("a file with a bad checksum was placed")
	}
	if got, _ := s.read("www/a.txt"); got != "a" {
		t.Fatal("the good file was not placed")
	}
	if !strings.Contains(strings.Join(failedPaths(sum), ","), "b.txt") || sum["transferred"] != float64(1) {
		t.Errorf("summary %v", sum)
	}
}

func TestSyncDownloadAsksInBatches(t *testing.T) {
	old := syncTarBatch
	syncTarBatch = 2
	t.Cleanup(func() { syncTarBatch = old })
	s := newTarServer(t)
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		s.write("site/"+n+".txt", n, 0o644, fixedTime)
	}
	dst := t.TempDir()

	sum, stderr, err := syncRun(t, "acct-uuid:site", dst)
	if err != nil || sum["status"] != true || sum["transferred"] != float64(5) {
		t.Fatalf("batched sync: %v %v\n%s", err, sum, stderr)
	}
	tars := 0
	for _, c := range s.callList() {
		if strings.HasPrefix(c, "tar ") {
			tars++
		}
	}
	if tars != 3 {
		t.Errorf("5 files in batches of 2 should take 3 archives, took %d: %v", tars, s.callList())
	}
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		if b, _ := os.ReadFile(filepath.Join(dst, n+".txt")); string(b) != n {
			t.Errorf("%s.txt = %q", n, b)
		}
	}
}
