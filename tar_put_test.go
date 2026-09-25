package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

func withPartSize(t *testing.T, n int64) {
	t.Helper()
	old := uploadPartSize
	uploadPartSize = n
	t.Cleanup(func() { uploadPartSize = old })
}

func TestTransferLimitsMatchTheContract(t *testing.T) {
	if uploadPartSize != 32<<20 || streamIdleTimeout != 120*time.Second || streamHeaderTimeout != 120*time.Second {
		t.Fatalf("part %d, idle %v, header %v", uploadPartSize, streamIdleTimeout, streamHeaderTimeout)
	}
}

func TestPartWriterCutsAtThePartSize(t *testing.T) {
	withPartSize(t, 1000)
	for _, total := range []int{1, 999, 1000, 1001, 2500, 3000} {
		var sizes []int64
		var joined bytes.Buffer
		w, err := newPartWriter(func(part int, path string, size int64, sha string) error {
			if part != len(sizes)+1 {
				t.Errorf("part %d out of order", part)
			}
			b, _ := os.ReadFile(path)
			if int64(len(b)) != size {
				t.Errorf("spool holds %d bytes, part says %d", len(b), size)
			}
			s := sha256.Sum256(b)
			if hex.EncodeToString(s[:]) != sha {
				t.Error("part checksum does not match its bytes")
			}
			sizes = append(sizes, size)
			joined.Write(b)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		data := bytes.Repeat([]byte("0123456789abcdefg"), total/17+1)[:total]
		// odd write sizes, so parts are cut inside writes
		for i := 0; i < len(data); i += 333 {
			end := i + 333
			if end > len(data) {
				end = len(data)
			}
			if _, err := w.Write(data[i:end]); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		wantParts := (total + 999) / 1000
		if len(sizes) != wantParts {
			t.Errorf("%d bytes → %d parts %v, want %d (no empty last part)", total, len(sizes), sizes, wantParts)
		}
		for i, s := range sizes {
			if s > 1000 || (i < len(sizes)-1 && s != 1000) {
				t.Errorf("%d bytes: part sizes %v", total, sizes)
			}
		}
		if !bytes.Equal(joined.Bytes(), data) {
			t.Errorf("%d bytes: the parts do not concatenate to the stream", total)
		}
		if _, err := os.Stat(w.spool.Name()); !os.IsNotExist(err) {
			t.Error("the spool file was left behind")
		}
	}
}

func TestUploadSessionAndPartNames(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		s, err := newUploadSession()
		if err != nil || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(s) || seen[s] {
			t.Fatalf("session %q (%v)", s, err)
		}
		seen[s] = true
	}
	if got := partTarget("0123456789abcdef0123456789abcdef", 7); got != ".cdn-upload.0123456789abcdef0123456789abcdef/part-00007" {
		t.Fatalf("part target %q", got)
	}
}

func TestUploadTarLayout(t *testing.T) {
	src := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(src, "dir"), 0o700))
	must(os.WriteFile(filepath.Join(src, "dir", "a.txt"), []byte("hello"), 0o600))
	must(os.WriteFile(filepath.Join(src, "run.sh"), []byte("#!/bin/sh"), 0o700))
	mt := time.Unix(1727262000, 987654321)
	must(os.Chtimes(filepath.Join(src, "dir", "a.txt"), mt, mt))
	items := []uploadItem{
		{Rel: "dir", Local: filepath.Join(src, "dir"), Dir: true},
		{Rel: "dir/a.txt", Local: filepath.Join(src, "dir", "a.txt")},
		{Rel: "run.sh", Local: filepath.Join(src, "run.sh")},
		{Rel: "vanished.txt", Local: filepath.Join(src, "vanished.txt")},
	}
	var buf bytes.Buffer
	res, err := writeUploadTar(&buf, items, []string{"old.txt", "old dir"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Failed) != 1 || res.Failed[0].Path != "vanished.txt" {
		t.Fatalf("failed = %v", res.Failed)
	}
	if res.DeleteListed {
		t.Fatal(".cdnctl-delete was written although a file failed (deletion must be skipped)")
	}

	// again without the failing file: now the delete list goes in
	buf.Reset()
	res, err = writeUploadTar(&buf, items[:3], []string{"old.txt", "old dir"})
	if err != nil || !res.DeleteListed {
		t.Fatalf("%v %v", err, res)
	}
	tr := tar.NewReader(&buf)
	var names []string
	contents := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
		b, _ := io.ReadAll(tr)
		contents[hdr.Name] = string(b)
		if hdr.ModTime.Nanosecond() != 0 {
			t.Errorf("%s: sub-second mtime", hdr.Name)
		}
		switch hdr.Name {
		case "dir/":
			if hdr.Typeflag != tar.TypeDir || hdr.Mode != 0o755 {
				t.Errorf("dir header %v %o", hdr.Typeflag, hdr.Mode)
			}
		case "dir/a.txt":
			if hdr.Mode != 0o644 || hdr.ModTime.Unix() != 1727262000 {
				t.Errorf("a.txt mode %o mtime %v", hdr.Mode, hdr.ModTime)
			}
		case "run.sh":
			if runtime.GOOS != "windows" && hdr.Mode != 0o755 {
				t.Errorf("run.sh mode %o", hdr.Mode)
			}
		}
	}
	if strings.Join(names, ",") != "dir/,dir/a.txt,run.sh,.cdnctl-delete,.cdnctl-sums" {
		t.Fatalf("members %v: .cdnctl-sums must be last, after .cdnctl-delete", names)
	}
	if contents[".cdnctl-delete"] != "old.txt\x00old dir\x00" {
		t.Errorf("delete list %q", contents[".cdnctl-delete"])
	}
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	wantSums := sum("hello") + "  ./dir/a.txt\n" + sum("#!/bin/sh") + "  ./run.sh\n" + sum("old.txt\x00old dir\x00") + "  ./.cdnctl-delete\n"
	if contents[".cdnctl-sums"] != wantSums {
		t.Errorf("sums:\n%s\nwant:\n%s", contents[".cdnctl-sums"], wantSums)
	}
}

func TestCpRecursiveUploadGoesAsPartsPlusOneApply(t *testing.T) {
	withPartSize(t, 4096)
	s := newTarServer(t)
	s.applyHeartbeats = 3
	src := t.TempDir()
	big := bytes.Repeat([]byte("x"), 10000) // several parts
	_ = os.MkdirAll(filepath.Join(src, "css", "empty"), 0o755)
	_ = os.WriteFile(filepath.Join(src, "css", "site.css"), []byte("body{}"), 0o644)
	_ = os.WriteFile(filepath.Join(src, "big.bin"), big, 0o644)
	if runtime.GOOS != "windows" {
		_ = os.Symlink("big.bin", filepath.Join(src, "alias"))
	}

	stdout, stderr, err := captureOutput(t, func() error {
		return run([]string{"cp", "-r", src, "acct-uuid:assets", "--force"})
	})
	if err != nil {
		t.Fatalf("upload failed: %v\n%s\n%s", err, stdout, stderr)
	}
	if got, _ := s.read("assets/big.bin"); got != string(big) {
		t.Fatal("big.bin did not arrive")
	}
	if got, _ := s.read("assets/css/site.css"); got != "body{}" {
		t.Fatal("site.css did not arrive")
	}
	if info, err := os.Stat(filepath.Join(s.root, "assets", "css", "empty")); err != nil || !info.IsDir() {
		t.Error("an empty folder was not created")
	}
	if _, err := os.Lstat(filepath.Join(s.root, "assets", "alias")); !os.IsNotExist(err) {
		t.Error("a symlink was uploaded")
	}
	if len(s.parts) < 3 {
		t.Fatalf("expected the tar in several parts, got %v", s.parts)
	}
	session := strings.TrimPrefix(strings.Split(s.parts[0], "/")[0], ".cdn-upload.")
	for i, p := range s.parts {
		if p != partTarget(session, i+1) {
			t.Errorf("part %d went to %s", i+1, p)
		}
		if int64(s.partSizes[i]) > uploadPartSize {
			t.Errorf("part %d is %d bytes", i+1, s.partSizes[i])
		}
	}
	if s.applyReq["session"] != session || intValue(s.applyReq["parts"]) != len(s.parts) ||
		s.applyReq["overwrite"] != true || s.applyReq["delete"] != false || s.applyReq["path"] != "assets" {
		t.Errorf("apply request %v", s.applyReq)
	}
	if last := s.applyMembers[len(s.applyMembers)-1]; last != ".cdnctl-sums" {
		t.Errorf("last member %q", last)
	}
	if _, err := os.Stat(filepath.Join(s.root, ".cdn-upload."+session)); !os.IsNotExist(err) {
		t.Error("the session folder was not removed")
	}
	sum := lastJSON(t, stdout)
	if sum["status"] != true || sum["uploaded"] != float64(2) {
		t.Errorf("summary %v", sum)
	}
	if runtime.GOOS != "windows" && !strings.Contains(stderr, "alias — symlink") {
		t.Errorf("the skipped symlink was not reported: %s", stderr)
	}
}

func TestCpRecursiveUploadWithoutForceKeepsExistingFiles(t *testing.T) {
	s := newTarServer(t)
	s.write("assets/a.txt", "server", 0o644, fixedTime)
	src := t.TempDir()
	_ = os.WriteFile(filepath.Join(src, "a.txt"), []byte("local"), 0o644)
	_ = os.WriteFile(filepath.Join(src, "b.txt"), []byte("new"), 0o644)
	stdout, _, err := captureOutput(t, func() error { return run([]string{"cp", "-r", src, "acct-uuid:assets"}) })
	if exitCode(err) != 1 {
		t.Fatalf("expected exit 1, got %v", err)
	}
	if got, _ := s.read("assets/a.txt"); got != "server" {
		t.Fatal("an existing file was overwritten without --force")
	}
	if got, _ := s.read("assets/b.txt"); got != "new" {
		t.Fatal("the new file was not placed")
	}
	if s.applyReq["overwrite"] != false {
		t.Errorf("overwrite = %v", s.applyReq["overwrite"])
	}
	if !strings.Contains(stdout, "a.txt") || !strings.Contains(stdout, "--force") {
		t.Errorf("the kept file was not reported: %s", stdout)
	}
}

func TestCpRecursiveUploadFallsBackWhenTarApplyIsMissing(t *testing.T) {
	s := newTarServer(t)
	old := s.srv.Config.Handler
	s.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/files/tar-apply") {
			writeJSON(w, 404, map[string]any{"message": "Not Found"})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/files/delete") {
			s.mu.Lock()
			s.calls = append(s.calls, "delete session")
			s.mu.Unlock()
			writeJSON(w, 200, map[string]any{"status": true})
			return
		}
		old.ServeHTTP(w, r)
	})
	src := t.TempDir()
	_ = os.WriteFile(filepath.Join(src, "a.txt"), []byte("a"), 0o644)
	_, stderr, err := captureOutput(t, func() error { return run([]string{"cp", "-r", src, "acct-uuid:up"}) })
	if err != nil {
		t.Fatalf("fallback failed: %v\n%s", err, stderr)
	}
	if got, _ := s.read("up/a.txt"); got != "a" {
		t.Fatal("the per-file fallback did not upload")
	}
	if s.called("delete") != 1 {
		t.Error("the orphaned session was not cleaned up")
	}
	if !strings.Contains(stderr, "file by file") {
		t.Errorf("the fallback was silent: %s", stderr)
	}
}

func TestCpRecursiveUploadRefusesUnsafeLocalNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("such names cannot exist on Windows")
	}
	s := newTarServer(t)
	src := t.TempDir()
	_ = os.WriteFile(filepath.Join(src, "new\nline.txt"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(src, `back\slash`), []byte("x"), 0o644)
	stdout, _, err := captureOutput(t, func() error { return run([]string{"cp", "-r", src, "acct-uuid:up", "--force"}) })
	if exitCode(err) != 1 {
		t.Fatalf("expected exit 1, got %v", err)
	}
	if len(s.callList()) != 0 {
		t.Fatalf("something was sent: %v", s.callList())
	}
	if !strings.Contains(stdout, "control character") || !strings.Contains(stdout, "backslash") {
		t.Errorf("reasons missing: %s", stdout)
	}
}

func TestABusyApplyIsRetriedWithTheSameSession(t *testing.T) {
	oldRetries, oldWait := applyBusyRetries, applyBusyWait
	applyBusyRetries, applyBusyWait = 3, time.Millisecond
	t.Cleanup(func() { applyBusyRetries, applyBusyWait = oldRetries, oldWait })
	s := newTarServer(t)
	s.busyApplies = 2
	src := t.TempDir()
	_ = os.WriteFile(filepath.Join(src, "a.txt"), []byte("a"), 0o644)

	_, stderr, err := captureOutput(t, func() error {
		return run([]string{"cp", "-r", src, "acct-uuid:assets", "--force"})
	})
	if err != nil {
		t.Fatalf("upload failed after busy answers: %v\n%s", err, stderr)
	}
	if got, _ := s.read("assets/a.txt"); got != "a" {
		t.Fatal("a.txt did not arrive")
	}
	puts := 0
	for _, c := range s.callList() {
		if strings.HasPrefix(c, "put ") {
			puts++
		}
	}
	if puts != 1 || s.called("tar-apply") != 3 {
		t.Errorf("parts must be uploaded once and the apply retried: %v", s.callList())
	}
	if !strings.Contains(stderr, "busy") {
		t.Errorf("no busy note on stderr:\n%s", stderr)
	}
}

func TestAStillBusyApplyDiscardsTheSession(t *testing.T) {
	oldRetries, oldWait := applyBusyRetries, applyBusyWait
	applyBusyRetries, applyBusyWait = 1, time.Millisecond
	t.Cleanup(func() { applyBusyRetries, applyBusyWait = oldRetries, oldWait })
	s := newTarServer(t)
	s.busyApplies = 10
	src := t.TempDir()
	_ = os.WriteFile(filepath.Join(src, "a.txt"), []byte("a"), 0o644)

	_, _, err := captureOutput(t, func() error {
		return run([]string{"cp", "-r", src, "acct-uuid:assets", "--force"})
	})
	if err == nil {
		t.Fatal("a server that stays busy must fail the upload")
	}
	// 2 busy answers, then one discard call
	if n := s.called("tar-apply"); n != 3 {
		t.Errorf("tar-apply calls = %d: %v", n, s.callList())
	}
}
