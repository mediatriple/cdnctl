package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// captureOutput runs fn with stdout and stderr redirected, returning both.
func captureOutput(t *testing.T, fn func() error) (stdout, stderr string, err error) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	os.Stdout, os.Stderr = outW, errW
	outC, errC := make(chan string), make(chan string)
	go func() { b, _ := io.ReadAll(outR); outC <- string(b) }()
	go func() { b, _ := io.ReadAll(errR); errC <- string(b) }()
	defer func() {
		os.Stdout, os.Stderr = oldOut, oldErr
	}()
	err = fn()
	outW.Close()
	errW.Close()
	return <-outC, <-errC, err
}

func lastJSON(t *testing.T, stdout string) map[string]any {
	t.Helper()
	i := strings.LastIndex(stdout, "\n{")
	if i < 0 {
		i = strings.Index(stdout, "{")
	}
	var m map[string]any
	if i < 0 || json.Unmarshal([]byte(strings.TrimSpace(stdout[i:])), &m) != nil {
		t.Fatalf("no JSON summary on stdout: %q", stdout)
	}
	return m
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if e, ok := isExitError(err); ok {
		return e.code
	}
	return 1
}

// leftovers lists cdnctl temp files anywhere under dir.
func leftovers(t *testing.T, dir string) []string {
	var out []string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && strings.HasPrefix(info.Name(), ".cdnctl-") {
			out = append(out, p)
		}
		return nil
	})
	return out
}

var fixedTime = time.Date(2026, 9, 1, 10, 20, 30, 0, time.UTC)

func TestCpRecursiveDownloadIsOneVerifiedTar(t *testing.T) {
	s := newTarServer(t)
	s.write("site/a.php", "<?php echo 1;", 0o644, fixedTime)
	s.write("site/bin/run.sh", "#!/bin/sh\n", 0o755, fixedTime.Add(time.Hour))
	s.write("site/deep/er/x y.txt", "spaces", 0o600, fixedTime)
	s.write("other.txt", "outside", 0o644, fixedTime)
	if runtime.GOOS != "windows" {
		_ = os.Symlink("../other.txt", filepath.Join(s.root, "site", "link"))
	}
	dst := filepath.Join(t.TempDir(), "backup")

	stdout, stderr, err := captureOutput(t, func() error { return run([]string{"cp", "-r", "acct-uuid:site", dst}) })
	if err != nil {
		t.Fatalf("cp -r failed: %v\n%s\n%s", err, stdout, stderr)
	}
	if calls := s.callList(); len(calls) != 1 || calls[0] != "tar site" {
		t.Fatalf("expected exactly one tar call, got %v", calls)
	}
	if !s.tarWhole {
		t.Fatal("cp -r should ask for the whole folder (files: null)")
	}
	for rel, want := range map[string]string{"a.php": "<?php echo 1;", "bin/run.sh": "#!/bin/sh\n", "deep/er/x y.txt": "spaces"} {
		got, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(rel)))
		if err != nil || string(got) != want {
			t.Errorf("%s: %q (%v)", rel, got, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dst, "link")); !os.IsNotExist(err) {
		t.Error("a symlink from the server was written")
	}
	if runtime.GOOS != "windows" {
		for rel, mode := range map[string]os.FileMode{"a.php": 0o644, "bin/run.sh": 0o755, "deep/er/x y.txt": 0o644} {
			info, _ := os.Stat(filepath.Join(dst, filepath.FromSlash(rel)))
			if info.Mode().Perm() != mode {
				t.Errorf("%s mode %o, want %o", rel, info.Mode().Perm(), mode)
			}
		}
		if !strings.Contains(stderr, "link — symlink") {
			t.Errorf("the skipped symlink was not reported: %s", stderr)
		}
	}
	info, _ := os.Stat(filepath.Join(dst, "bin", "run.sh"))
	if !info.ModTime().Equal(fixedTime.Add(time.Hour)) {
		t.Errorf("mtime not kept: %v", info.ModTime())
	}
	sum := lastJSON(t, stdout)
	if sum["status"] != true || sum["downloaded"] != float64(3) {
		t.Errorf("summary: %v", sum)
	}
	if l := leftovers(t, dst); len(l) != 0 {
		t.Errorf("temp files left: %v", l)
	}
}

// Every way a stream can arrive broken must place nothing and leave no temp file.
func TestABrokenTarStreamPlacesNothing(t *testing.T) {
	cases := map[string]func(body []byte) []byte{
		"one byte of the tar differs": func(b []byte) []byte {
			b = append([]byte(nil), b...)
			i := bytes.Index(b, []byte("NEWCONTENT"))
			b[i] = 'X'
			return b
		},
		"byte count differs": func(b []byte) []byte {
			return bytes.Replace(b, []byte(" bytes=10240 "), []byte(" bytes=10752 "), 1)
		},
		"trailer missing": func(b []byte) []byte {
			return b[:bytes.LastIndex(b, []byte("\nCDNTAR-END"))]
		},
		"trailer garbled": func(b []byte) []byte {
			return bytes.Replace(b, []byte("CDNTAR-END v=1"), []byte("CDNTAR-END v=9"), 1)
		},
		"cut at a member boundary": func(b []byte) []byte {
			// "./" header, then new.txt's header + one data block: a valid-looking tar prefix
			return b[:512*3]
		},
		"cut mid-member": func(b []byte) []byte { return b[:700] },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := newTarServer(t)
			s.write("site/new.txt", "NEWCONTENT", 0o644, fixedTime)
			s.mutate = mutate
			dst := t.TempDir()
			if err := os.WriteFile(filepath.Join(dst, "keep.txt"), []byte("old"), 0o644); err != nil {
				t.Fatal(err)
			}
			_, _, err := captureOutput(t, func() error { return run([]string{"cp", "-r", "acct-uuid:site", dst, "--force"}) })
			if err == nil {
				t.Fatal("a broken stream was accepted")
			}
			if !strings.Contains(err.Error(), "run the same command again") {
				t.Errorf("the message does not say to run again: %v", err)
			}
			if _, statErr := os.Stat(filepath.Join(dst, "new.txt")); !os.IsNotExist(statErr) {
				t.Error("a file from a broken stream was placed")
			}
			if b, _ := os.ReadFile(filepath.Join(dst, "keep.txt")); string(b) != "old" {
				t.Error("an existing file was touched")
			}
			if l := leftovers(t, dst); len(l) != 0 {
				t.Errorf("temp files left: %v", l)
			}
		})
	}
}

func TestTarExitCode2IsAFailureWithTarsMessages(t *testing.T) {
	s := newTarServer(t)
	s.write("site/ok.txt", "fine", 0o644, fixedTime)
	s.tarRC = 2
	s.tarStderr = "tar: \"./secret\": Cannot open: Permission denied\ntar: Exiting with failure status due to previous errors\n"
	dst := t.TempDir()
	stdout, stderr, err := captureOutput(t, func() error { return run([]string{"cp", "-r", "acct-uuid:site", dst}) })
	if exitCode(err) != 1 {
		t.Fatalf("expected exit 1, got %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "ok.txt")); string(b) != "fine" {
		t.Error("the files that did arrive (verified stream) were not placed")
	}
	if !strings.Contains(stderr, "Cannot open: Permission denied") || !strings.Contains(stdout, "tar exit code 2") {
		t.Errorf("tar's own messages were not shown:\n%s\n%s", stdout, stderr)
	}
}

func TestOddNamesInATarAreRefusedAndNothingEscapes(t *testing.T) {
	s := newTarServer(t)
	_ = os.MkdirAll(filepath.Join(s.root, "site"), 0o755)
	s.rawTar = func() []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, name := range []string{"../evil.txt", "/abs.txt", `a\b.txt`, "ctl\x01.txt", ".cdnctl-x", "sub/.cdn-upload.1/p", "./good.txt", "sub/../../up.txt", "bad\xff.txt"} {
			_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: 1, ModTime: fixedTime, Format: tar.FormatPAX})
			_, _ = tw.Write([]byte("x"))
		}
		_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeLink, Name: "hard", Linkname: "good.txt", ModTime: fixedTime})
		_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeChar, Name: "dev", ModTime: fixedTime})
		_ = tw.Close()
		return padRecord(buf.Bytes())
	}
	parent := t.TempDir()
	dst := filepath.Join(parent, "in")
	stdout, stderr, _ := captureOutput(t, func() error { return run([]string{"cp", "-r", "acct-uuid:site", dst}) })
	if b, _ := os.ReadFile(filepath.Join(dst, "good.txt")); string(b) != "x" {
		t.Fatalf("the good file was not placed:\n%s\n%s", stdout, stderr)
	}
	entries := entriesOf(parent)
	if strings.Join(entries, ",") != "in,in/good.txt" {
		t.Errorf("unexpected files written: %v", entries)
	}
	for _, want := range []string{"../evil.txt", "/abs.txt", "hard — special", "dev — special"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("%q not reported as skipped:\n%s", want, stderr)
		}
	}
}

func TestADownloadNeverWritesThroughASymlinkedLocalFolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	s := newTarServer(t)
	s.write("site/sub/x.txt", "x", 0o644, fixedTime)
	outside := t.TempDir()
	dst := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dst, "sub")); err != nil {
		t.Fatal(err)
	}
	_, _, err := captureOutput(t, func() error { return run([]string{"cp", "-r", "acct-uuid:site", dst, "--force"}) })
	if exitCode(err) != 1 {
		t.Fatalf("expected a failure, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "x.txt")); !os.IsNotExist(err) {
		t.Fatal("the download was written through a symlinked folder")
	}
}

func TestWithoutForceADifferingFileIsKeptAndReported(t *testing.T) {
	s := newTarServer(t)
	s.write("site/same.txt", "same", 0o644, fixedTime)
	s.write("site/diff.txt", "server", 0o644, fixedTime)
	dst := t.TempDir()
	_ = os.WriteFile(filepath.Join(dst, "same.txt"), []byte("same"), 0o644)
	_ = os.WriteFile(filepath.Join(dst, "diff.txt"), []byte("local"), 0o644)

	stdout, _, err := captureOutput(t, func() error { return run([]string{"cp", "-r", "acct-uuid:site", dst}) })
	if exitCode(err) != 1 {
		t.Fatalf("expected exit 1, got %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "diff.txt")); string(b) != "local" {
		t.Fatal("a differing file was replaced without --force")
	}
	sum := lastJSON(t, stdout)
	if nr, _ := sum["not_replaced"].([]any); len(nr) != 1 || nr[0] != "diff.txt" {
		t.Errorf("not_replaced = %v", sum["not_replaced"])
	}
	if sum["unchanged"] != float64(1) {
		t.Errorf("the identical file should count as unchanged: %v", sum)
	}

	_, _, err = captureOutput(t, func() error { return run([]string{"cp", "-r", "acct-uuid:site", dst, "--force"}) })
	if err != nil {
		t.Fatalf("--force run failed: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "diff.txt")); string(b) != "server" {
		t.Fatal("--force did not replace the differing file")
	}
}

func TestToolMissingFallsBackToFileByFile(t *testing.T) {
	s := newTarServer(t)
	s.toolMissing = true
	s.write("site/a.txt", "a", 0o644, fixedTime)
	s.write("site/sub/b.txt", "b", 0o644, fixedTime)
	dst := t.TempDir()
	_, stderr, err := captureOutput(t, func() error { return run([]string{"cp", "-r", "acct-uuid:site", dst}) })
	if err != nil {
		t.Fatalf("fallback failed: %v\n%s", err, stderr)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "sub", "b.txt")); string(b) != "b" {
		t.Fatal("the per-file fallback did not copy the folder")
	}
	if s.called("get") != 3 { // the folder probe + two files
		t.Errorf("expected the per-file path, calls: %v", s.callList())
	}
}

func TestCpRecursiveOfASingleFileStillWorks(t *testing.T) {
	s := newTarServer(t)
	s.write("one.txt", "1", 0o644, fixedTime)
	dst := t.TempDir()
	if _, _, err := captureOutput(t, func() error { return run([]string{"cp", "-r", "acct-uuid:one.txt", dst + "/"}) }); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "one.txt")); string(b) != "1" {
		t.Fatal("a single file with -r was not downloaded")
	}
}

func TestBusyIsReportedNotRetriedForever(t *testing.T) {
	s := newTarServer(t)
	s.busy = true
	_ = os.MkdirAll(filepath.Join(s.root, "site"), 0o755)
	stdout, _, err := captureOutput(t, func() error { return run([]string{"cp", "-r", "acct-uuid:site", t.TempDir()}) })
	if exitCode(err) != 1 {
		t.Fatalf("expected exit 1, got %v", err)
	}
	sum := lastJSON(t, stdout)
	if sum["error_code"] != "busy" || sum["_http_status"] != float64(429) {
		t.Errorf("the busy answer was not printed as-is: %v", sum)
	}
	if s.called("tar") != 1 {
		t.Errorf("calls: %v", s.callList())
	}
}

func TestStreamIdleWatchdogAbortsAStalledTransfer(t *testing.T) {
	old := streamIdleTimeout
	streamIdleTimeout = 150 * time.Millisecond
	defer func() { streamIdleTimeout = old }()
	release := make(chan struct{})
	defer close(release)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-tar")
		_, _ = w.Write(make([]byte, 512))
		w.(http.Flusher).Flush()
		select { // then silence
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	useServer(t, srv.URL)

	body, answer, err := requestStream("accounts/a/files/tar", map[string]any{"path": "x"})
	if err != nil || answer != nil {
		t.Fatalf("unexpected: %v %v", err, answer)
	}
	defer body.Close()
	start := time.Now()
	_, err = io.ReadAll(body)
	if err == nil || !strings.Contains(err.Error(), "stalled") {
		t.Fatalf("expected a stall error, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the watchdog did not fire in time")
	}
}

func TestStreamErrorsAreDecodedLikeOtherCommands(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing bearer token")
		}
		writeJSON(w, 403, map[string]any{"status": false, "error_code": "permission_denied", "message": "The site cannot open that folder."})
	}))
	defer srv.Close()
	useServer(t, srv.URL)
	body, answer, err := requestStream("accounts/a/files/tree", map[string]any{"path": "x"})
	if err != nil || body != nil {
		t.Fatalf("unexpected: %v %v", err, body)
	}
	if answer["error_code"] != "permission_denied" || httpStatusOf(answer) != 403 {
		t.Fatalf("answer = %v", answer)
	}
	if streamUnsupported(answer) {
		t.Fatal("a permission error is not 'unsupported'")
	}
	if !streamUnsupported(map[string]any{"message": "Not Found", "_http_status": 404}) ||
		streamUnsupported(map[string]any{"error_code": "file_not_found", "_http_status": 404}) ||
		!streamUnsupported(map[string]any{"error_code": "tool_missing", "_http_status": 501}) {
		t.Fatal("streamUnsupported misreads a route-less 404, a missing folder or tool_missing")
	}
}

func TestVerifyTarTailAcceptsExactlyTheContract(t *testing.T) {
	archive := buildTar(t.TempDir(), nil, nil)
	full := withTrailer(archive, 0, "")
	res, err := extractTar(bytes.NewReader(full), extractOptions{root: t.TempDir()})
	if err != nil || res.Trailer.Bytes != int64(len(archive)) {
		t.Fatalf("a correct empty archive was refused: %v", err)
	}
	// data after the trailer line makes it not the LAST line
	if _, err := extractTar(bytes.NewReader(append(full, "junk\n"...)), extractOptions{root: t.TempDir()}); err == nil {
		t.Fatal("a trailer that is not the last line was accepted")
	}
}

func TestAStreamedAnswerAfterMegabytesOfHeartbeatDecodes(t *testing.T) {
	body := strings.Repeat(" ", 5<<20) + `{"status":true,"result":{"placed":1}}`
	got, err := decodeStreamAnswer(strings.NewReader(body))
	if err != nil || got["status"] != true {
		t.Fatalf("%v %v", err, got)
	}
}
