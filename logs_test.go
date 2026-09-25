package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// TestLogsPullFetchesTheDayOnceAndSkipsWhatIsThere runs `cdnctl logs pull` against a
// fake API + fake object storage: every listed file lands under its own base name,
// the signed URL comes from the download endpoint, and a second pull downloads
// nothing because every file is already present with the listed size.
func TestLogsPullFetchesTheDayOnceAndSkipsWhatIsThere(t *testing.T) {
	const account = "abc123"
	bodies := map[string]string{
		account + "/2026/09/25/20260925T100000Z-185-70-97-9.jsonl.gz":   "first-file",
		account + "/2026/09/25/20260925T100500Z-95-216-98-163.jsonl.gz": "second-file-longer",
	}
	var storageHits int32

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/accounts/"+account+"/logpush/files":
			if r.URL.Query().Get("day") != "2026-09-25" || r.Header.Get("Authorization") != "Bearer tok" {
				http.Error(w, "bad request", 400)
				return
			}
			var items []string
			for key, body := range bodies {
				items = append(items, fmt.Sprintf(`{"key":%q,"size":%d}`, key, len(body)))
			}
			fmt.Fprintf(w, `{"status":"success","files":[%s]}`, strings.Join(items, ","))
		case r.URL.Path == "/api/accounts/"+account+"/logpush/download":
			key := r.URL.Query().Get("key")
			if _, ok := bodies[key]; !ok {
				http.Error(w, `{"status":"error","message":"File not found."}`, 404)
				return
			}
			fmt.Fprintf(w, `{"status":"success","url":%q,"expires_in":900}`, srv.URL+"/storage/"+key+"?X-Amz-Signature=x")
		case strings.HasPrefix(r.URL.Path, "/storage/"):
			atomic.AddInt32(&storageHits, 1)
			fmt.Fprint(w, bodies[strings.TrimPrefix(r.URL.Path, "/storage/")])
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Setenv("HOME", t.TempDir())
	t.Setenv("CDNCTL_ENDPOINT", srv.URL)
	t.Setenv("CDNCTL_TOKEN", "tok")
	out := filepath.Join(t.TempDir(), "logs")
	args := parsedArgs{Positionals: []string{"pull"}, Options: map[string]string{"account": account, "day": "2026-09-25", "out": out}}

	if err := cmdLogs(args); err != nil {
		t.Fatalf("first pull: %v", err)
	}
	for key, body := range bodies {
		got, err := os.ReadFile(filepath.Join(out, filepath.Base(key)))
		if err != nil || string(got) != body {
			t.Fatalf("%s: got %q, %v", key, got, err)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(out, "*.part")); len(left) != 0 {
		t.Fatalf("partial files left behind: %v", left)
	}
	if storageHits != 2 {
		t.Fatalf("expected 2 downloads, got %d", storageHits)
	}

	if err := cmdLogs(args); err != nil {
		t.Fatalf("second pull: %v", err)
	}
	if storageHits != 2 {
		t.Fatalf("second pull downloaded again: %d storage hits", storageHits)
	}
}

func TestLogsRejectsANonUTCDayShape(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CDNCTL_TOKEN", "tok")
	err := cmdLogs(parsedArgs{Positionals: []string{"list"}, Options: map[string]string{"account": "abc123", "day": "25.09.2026"}})
	if exit, ok := isExitError(err); !ok || exit.code != 2 {
		t.Fatalf("expected usage exit 2, got %v", err)
	}
}
