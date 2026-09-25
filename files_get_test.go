package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseRemoteSpecFollowsScp(t *testing.T) {
	cases := []struct {
		in, account, path string
		remote            bool
	}{
		{":site-root/a.php", "", "site-root/a.php", true},
		{"oarupvcqiwtpatrckvvvw:site-root/a.php", "oarupvcqiwtpatrckvvvw", "site-root/a.php", true},
		{"acct-uuid:/uploads/x", "acct-uuid", "/uploads/x", true},
		{"./a:b.txt", "", "", false},       // colon after a slash: a local name
		{"dir/a:b", "", "", false},         // same
		{`C:\files\a.txt`, "", "", false},  // Windows drive, not an account
		{"C:/files/a.txt", "", "", false},  // Windows drive with forward slashes
		{"uploads/pic.jpg", "", "", false}, // no colon at all
		{"bad name:x", "", "", false},      // a space is not an account id
	}
	for _, c := range cases {
		account, path, remote := parseRemoteSpec(c.in)
		if remote != c.remote || account != c.account || path != c.path {
			t.Errorf("parseRemoteSpec(%q) = (%q, %q, %v), want (%q, %q, %v)", c.in, account, path, remote, c.account, c.path, c.remote)
		}
	}
}

type fakeFile struct {
	body []byte
	code string // non-empty: answer with this error_code instead
}

// fakeFileServer answers files/get and files/list for an in-memory tree. keys are
// remote paths; a folder is listed from the keys under it.
func fakeFileServer(t *testing.T, files map[string]fakeFile, calls *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		p := strval(req["path"])
		*calls = append(*calls, r.URL.Path+" "+p)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/files/get"):
			f, ok := files[p]
			if !ok {
				// a prefix of some key is a folder
				for k := range files {
					if strings.HasPrefix(k, strings.TrimRight(p, "/")+"/") {
						w.WriteHeader(422)
						_, _ = io.WriteString(w, `{"status":false,"error_code":"is_directory","message":"That path is a directory."}`)
						return
					}
				}
				w.WriteHeader(404)
				_, _ = io.WriteString(w, `{"status":false,"error_code":"file_not_found","message":"File not found."}`)
				return
			}
			if f.code != "" {
				w.WriteHeader(413)
				_ = json.NewEncoder(w).Encode(map[string]any{"status": false, "error_code": f.code, "message": "declined: " + f.code})
				return
			}
			sum := sha256.Sum256(f.body)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": true,
				"result": map[string]any{
					"path": p, "size": len(f.body), "sha256": hex.EncodeToString(sum[:]),
					"encoding": "base64", "content": base64.StdEncoding.EncodeToString(f.body),
				},
			})
		case strings.HasSuffix(r.URL.Path, "/files/list"):
			base := strings.TrimRight(p, "/") + "/"
			seen := map[string]bool{}
			var items []map[string]any
			for k := range files {
				if !strings.HasPrefix(k, base) {
					continue
				}
				rest := strings.TrimPrefix(k, base)
				name, _, isDeeper := strings.Cut(rest, "/")
				if seen[name] {
					continue
				}
				seen[name] = true
				kind := "file"
				if isDeeper {
					kind = "folder"
				}
				items = append(items, map[string]any{"name": name, "type": kind, "size": 0, "mtime": 0})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": true, "result": items})
		default:
			t.Errorf("unexpected call %s", r.URL.Path)
		}
	}))
}

func useServer(t *testing.T, url string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CDN_ENDPOINT", url)
	t.Setenv("CDN_ACCESS_TOKEN", "test-token")
	t.Setenv("CDNCTL_ENDPOINT", "")
	t.Setenv("CDNCTL_TOKEN", "")
}

func TestCpDownloadsAFileVerbatimWith0644(t *testing.T) {
	body := []byte("\n<?php echo 1;\x00\xff\n")
	var calls []string
	srv := fakeFileServer(t, map[string]fakeFile{"site-root/apple/app/fetch_radios.php": {body: body}}, &calls)
	defer srv.Close()
	useServer(t, srv.URL)
	dir := t.TempDir()

	if err := run([]string{"cp", "acct-uuid:site-root/apple/app/fetch_radios.php", dir + "/"}); err != nil {
		t.Fatalf("download failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "fetch_radios.php"))
	if err != nil || string(got) != string(body) {
		t.Fatalf("bytes differ: %q (err %v)", got, err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(filepath.Join(dir, "fetch_radios.php"))
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("downloaded file mode = %o, want 644", info.Mode().Perm())
		}
	}
	if len(calls) != 1 || calls[0] != "/api/accounts/acct-uuid/files/get site-root/apple/app/fetch_radios.php" {
		t.Fatalf("unexpected calls: %v", calls)
	}
}

func TestColonPrefixUsesTheAccountFlag(t *testing.T) {
	var calls []string
	srv := fakeFileServer(t, map[string]fakeFile{"a.txt": {body: []byte("x")}}, &calls)
	defer srv.Close()
	useServer(t, srv.URL)
	out := filepath.Join(t.TempDir(), "renamed.txt")

	if err := run([]string{"cp", ":a.txt", out, "--account", "oarupvcqiwtpatrckvvvw"}); err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if calls[0] != "/api/accounts/oarupvcqiwtpatrckvvvw/files/get a.txt" {
		t.Fatalf("unexpected call: %v", calls)
	}
	if b, _ := os.ReadFile(out); string(b) != "x" {
		t.Fatalf("file not written at the named destination")
	}
}

func TestDownloadRefusesToOverwriteWithoutForce(t *testing.T) {
	var calls []string
	srv := fakeFileServer(t, map[string]fakeFile{"a.txt": {body: []byte("new")}}, &calls)
	defer srv.Close()
	useServer(t, srv.URL)
	target := filepath.Join(t.TempDir(), "a.txt")
	_ = os.WriteFile(target, []byte("mine"), 0o644)

	if err := run([]string{"cp", "acct-uuid:a.txt", target}); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("expected an overwrite refusal mentioning --force, got %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "mine" {
		t.Fatal("local file was changed without --force")
	}
	if err := run([]string{"cp", "acct-uuid:a.txt", target, "--force"}); err != nil {
		t.Fatalf("--force download failed: %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "new" {
		t.Fatal("--force did not replace the file")
	}
}

func TestATamperedDownloadWritesNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": true,
			"result": map[string]any{
				"path": "a.txt", "size": 3, "sha256": strings.Repeat("0", 64),
				"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte("abc")),
			},
		})
	}))
	defer srv.Close()
	useServer(t, srv.URL)
	target := filepath.Join(t.TempDir(), "a.txt")

	err := run([]string{"cp", "acct-uuid:a.txt", target})
	if err == nil || !strings.Contains(err.Error(), "verification") {
		t.Fatalf("expected a verification failure, got %v", err)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatal("a file that failed verification was written")
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(target), ".cdnctl-download-*"))
	if len(left) != 0 {
		t.Fatalf("temporary files left behind: %v", left)
	}
}

func TestServerRefusalIsReportedAndNothingIsWritten(t *testing.T) {
	var calls []string
	srv := fakeFileServer(t, map[string]fakeFile{}, &calls)
	defer srv.Close()
	useServer(t, srv.URL)
	dir := t.TempDir()

	if err := run([]string{"cp", "acct-uuid:missing.php", dir}); err == nil {
		t.Fatal("expected a non-zero exit for a missing remote file")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("something was written for a missing file: %v", entries)
	}
}

func TestRecursiveDownloadMirrorsTheFolderContents(t *testing.T) {
	var calls []string
	srv := fakeFileServer(t, map[string]fakeFile{
		"site-root/apple/nr1.xml":           {body: []byte("<nr1/>")},
		"site-root/apple/app/fetch.php":     {body: []byte("<?php")},
		"site-root/apple/app/deep/logo.png": {body: []byte{0x89, 'P', 'N', 'G'}},
		"site-root/other.txt":               {body: []byte("not under apple")},
	}, &calls)
	defer srv.Close()
	useServer(t, srv.URL)
	dir := t.TempDir()

	if err := run([]string{"cp", "-r", "acct-uuid:site-root/apple", dir}); err != nil {
		t.Fatalf("recursive download failed: %v", err)
	}
	for rel, want := range map[string]string{
		"nr1.xml":           "<nr1/>",
		"app/fetch.php":     "<?php",
		"app/deep/logo.png": "\x89PNG",
	} {
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil || string(got) != want {
			t.Errorf("%s: got %q (err %v)", rel, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "other.txt")); !os.IsNotExist(err) {
		t.Error("a file outside the requested folder was downloaded")
	}
}

func TestADirectoryWithoutDashRIsRefused(t *testing.T) {
	var calls []string
	srv := fakeFileServer(t, map[string]fakeFile{"site-root/apple/a.xml": {body: []byte("a")}}, &calls)
	defer srv.Close()
	useServer(t, srv.URL)

	if err := run([]string{"cp", "acct-uuid:site-root/apple", t.TempDir()}); err == nil {
		t.Fatal("expected a directory without -r to fail")
	}
	for _, c := range calls {
		if strings.Contains(c, "/files/list") {
			t.Fatal("a directory was walked without -r")
		}
	}
}

func TestUnsafeNameInAListingIsNotWritten(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/files/get") {
			w.WriteHeader(422)
			_, _ = io.WriteString(w, `{"status":false,"error_code":"is_directory","message":"dir"}`)
			return
		}
		_, _ = io.WriteString(w, `{"status":true,"result":[{"name":"..\\..\\evil.txt","type":"file"}]}`)
	}))
	defer srv.Close()
	useServer(t, srv.URL)
	parent := t.TempDir()
	dir := filepath.Join(parent, "into")

	if err := run([]string{"cp", "-r", "acct-uuid:x", dir}); err == nil {
		t.Fatal("expected the unsafe name to be reported as a failure")
	}
	if _, err := os.Stat(filepath.Join(parent, "evil.txt")); !os.IsNotExist(err) {
		t.Fatal("a server-supplied name escaped the destination folder")
	}
}

func TestFilesGetWritesToOut(t *testing.T) {
	var calls []string
	srv := fakeFileServer(t, map[string]fakeFile{"uploads/a.txt": {body: []byte("hello")}}, &calls)
	defer srv.Close()
	useServer(t, srv.URL)
	out := filepath.Join(t.TempDir(), "b.txt")

	if err := run([]string{"files", "get", "--account", "acct-uuid", "--path", "uploads/a.txt", "--out", out}); err != nil {
		t.Fatalf("files get failed: %v", err)
	}
	if b, _ := os.ReadFile(out); string(b) != "hello" {
		t.Fatalf("files get wrote %q", b)
	}
}

func TestUploadOfAMissingLocalFileSuggestsTheDownloadForm(t *testing.T) {
	useServer(t, "http://127.0.0.1:0")
	err := run([]string{"cp", "site-root/apple/app/fetch_radios.php", "./", "--account", "acct-uuid"})
	if err == nil || !strings.Contains(err.Error(), "cdnctl cp :site-root/apple/app/fetch_radios.php ./") {
		t.Fatalf("expected a hint towards the download form, got %v", err)
	}
}

func TestANonListAnswerIsAFailureNotAnEmptyFolder(t *testing.T) {
	// cdnapi used to hand back raw text as a "successful" listing when a file
	// name broke its JSON; cp -r then copied nothing and reported success.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/files/get") {
			w.WriteHeader(422)
			_, _ = io.WriteString(w, `{"status":false,"error_code":"is_directory","message":"dir"}`)
			return
		}
		_, _ = io.WriteString(w, `{"status":true,"result":"[{\"name\":\"bad\u0001\"}]"}`)
	}))
	defer srv.Close()
	useServer(t, srv.URL)

	if err := run([]string{"cp", "-r", "acct-uuid:x", t.TempDir()}); err == nil {
		t.Fatal("a listing that is not a list was taken for an empty folder")
	}
}

func TestLinkedFoldersAreNotFollowed(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		p := strval(req["path"])
		calls = append(calls, r.URL.Path+" "+p)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/files/get") && p == "x":
			w.WriteHeader(422)
			_, _ = io.WriteString(w, `{"status":false,"error_code":"is_directory","message":"dir"}`)
		case strings.HasSuffix(r.URL.Path, "/files/get"):
			sum := sha256.Sum256([]byte("a"))
			_ = json.NewEncoder(w).Encode(map[string]any{"status": true, "result": map[string]any{
				"size": 1, "sha256": hex.EncodeToString(sum[:]), "encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte("a")),
			}})
		default:
			_, _ = io.WriteString(w, `{"status":true,"result":[{"name":"loop","type":"folder","link":true},{"name":"a.txt","type":"file","link":false}]}`)
		}
	}))
	defer srv.Close()
	useServer(t, srv.URL)
	dir := t.TempDir()

	if err := run([]string{"cp", "-r", "acct-uuid:x", dir}); err != nil {
		t.Fatalf("a skipped link made the copy fail: %v", err)
	}
	for _, c := range calls {
		if strings.Contains(c, "loop") {
			t.Fatalf("the linked folder was followed: %s", c)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "a.txt")); string(b) != "a" {
		t.Fatalf("the ordinary file next to the link was not downloaded: %q", b)
	}
}

func TestALocalFileWithAColonInItsNameIsStillUploaded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("colons are not allowed in Windows file names")
	}
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":true,"message":"ok","result":{}}`)
	}))
	defer srv.Close()
	useServer(t, srv.URL)
	dir := t.TempDir()
	wd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)
	name := "backup-2026-09-25T10:30:00.tar.gz"
	if err := os.WriteFile(name, []byte("tar"), 0o644); err != nil {
		t.Fatal(err)
	}

	_ = run([]string{"cp", name, "backups/" + name, "--account", "acct-uuid"})
	if len(calls) == 0 || !strings.HasSuffix(calls[0], "/files/put") {
		t.Fatalf("an existing local file with a colon was not uploaded; calls: %v", calls)
	}
}

func TestTheDownloadHintKeepsTheDotOfAHiddenFile(t *testing.T) {
	useServer(t, "http://127.0.0.1:0")
	err := run([]string{"cp", "./.htaccess-missing", "./", "--account", "acct-uuid"})
	if err == nil || !strings.Contains(err.Error(), "cdnctl cp :.htaccess-missing ./") {
		t.Fatalf("the hint lost the leading dot: %v", err)
	}
}
