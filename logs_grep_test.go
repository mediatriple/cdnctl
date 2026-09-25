package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func gzLines(lines ...string) string {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	io.WriteString(w, strings.Join(lines, "\n")+"\n")
	w.Close()
	return b.String()
}

func logLine(ts, ip, method, uri string, status int) string {
	return fmt.Sprintf(`{"ts":"%s","edge":"185.70.97.9","client_ip":"%s","method":"%s","scheme":"https","host":"www.example.com","uri":"%s","protocol":"HTTP/2.0","status":%d,"bytes":10,"cache":"HIT","country":"TR","asn":1}`, ts, ip, method, uri, status)
}

// TestLogsGrepDownloadsOnlyTheWindowAndFiltersLines: three 5-minute files around a
// 14:00–14:05 UTC window; only the two overlapping ones are fetched, lines outside the
// window are skipped, filters AND together, and a second run downloads nothing.
func TestLogsGrepDownloadsOnlyTheWindowAndFiltersLines(t *testing.T) {
	const account = "abc123"
	objects := map[string]string{
		// shipped 14:00:02 → holds 13:55–14:00 (plus one line at the edge)
		account + "/2026/09/25/20260925T140002Z-185-70-97-9.jsonl.gz": gzLines(
			logLine("2026-09-25T16:58:00+03:00", "203.0.113.7", "GET", "/old", 200),
			logLine("2026-09-25T17:00:00+03:00", "203.0.113.7", "GET", "/api/x", 502),
		),
		// shipped 14:05:01 → 14:00–14:05
		account + "/2026/09/25/20260925T140501Z-185-70-97-9.jsonl.gz": gzLines(
			logLine("2026-09-25T17:01:00+03:00", "203.0.113.9", "GET", "/api/y", 503),
			logLine("2026-09-25T17:02:00+03:00", "198.51.100.1", "GET", "/api/z", 500),
			logLine("2026-09-25T17:03:00+03:00", "203.0.113.7", "POST", "/login", 404),
		),
		// shipped 14:20:01 → far outside the window, must not be downloaded
		account + "/2026/09/25/20260925T142001Z-185-70-97-9.jsonl.gz": gzLines(
			logLine("2026-09-25T17:16:00+03:00", "203.0.113.7", "GET", "/late", 500),
		),
	}
	var downloads int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/accounts/"+account+"/logpush/files":
			var items []string
			day := strings.ReplaceAll(r.URL.Query().Get("day"), "-", "/")
			for k, v := range objects {
				if strings.Contains(k, "/"+day+"/") {
					items = append(items, fmt.Sprintf(`{"key":%q,"size":%d}`, k, len(v)))
				}
			}
			fmt.Fprintf(w, `{"status":"success","files":[%s]}`, strings.Join(items, ","))
		case r.URL.Path == "/api/accounts/"+account+"/logpush/download":
			fmt.Fprintf(w, `{"status":"success","url":%q}`, srv.URL+"/s/"+r.URL.Query().Get("key"))
		case strings.HasPrefix(r.URL.Path, "/s/"):
			atomic.AddInt32(&downloads, 1)
			io.WriteString(w, objects[strings.TrimPrefix(r.URL.Path, "/s/")])
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CDNCTL_ENDPOINT", srv.URL)
	t.Setenv("CDNCTL_TOKEN", "tok")
	cache := t.TempDir()

	run := func(extra map[string]string, bools map[string]bool) string {
		opts := map[string]string{"account": account, "from": "2026-09-25T14:00:00Z", "to": "2026-09-25T14:05:00Z", "cache_dir": cache}
		for k, v := range extra {
			opts[k] = v
		}
		if bools == nil {
			bools = map[string]bool{}
		}
		out, err := captureStdout(func() error {
			return cmdLogs(parsedArgs{Positionals: []string{"grep"}, Options: opts, Bools: bools})
		})
		if err != nil {
			t.Fatalf("grep failed: %v", err)
		}
		return out
	}

	all := run(nil, nil)
	if n := strings.Count(all, "\n"); n != 4 {
		t.Fatalf("expected the 4 lines inside [14:00,14:05) UTC, got %d:\n%s", n, all)
	}
	if strings.Contains(all, "/old") || strings.Contains(all, "/late") {
		t.Fatalf("lines outside the window leaked:\n%s", all)
	}
	if downloads != 2 {
		t.Fatalf("only the two overlapping files should be fetched, got %d", downloads)
	}

	five := run(map[string]string{"status": "5xx", "ip": "203.0.113.0/24", "path": "/api/"}, nil)
	if strings.Count(five, "\n") != 2 || !strings.Contains(five, "/api/x") || !strings.Contains(five, "/api/y") {
		t.Fatalf("5xx from 203.0.113.0/24 under /api/: want /api/x and /api/y, got:\n%s", five)
	}
	if got := strings.TrimSpace(run(map[string]string{"status": "404", "method": "post"}, map[string]bool{"count": true})); got != "1" {
		t.Fatalf("--count for POST 404: want 1, got %q", got)
	}
	if downloads != 2 {
		t.Fatalf("re-runs must use the local cache, downloads=%d", downloads)
	}
}

func TestLogsGrepTimeParsingAndDays(t *testing.T) {
	loc := time.FixedZone("TRT", 3*3600)
	now := time.Date(2026, 9, 25, 16, 0, 0, 0, loc)
	for raw, want := range map[string]string{
		"2026-09-25T14:00":     "2026-09-25T14:00:00+03:00",
		"2026-09-25 14:00":     "2026-09-25T14:00:00+03:00",
		"14:30":                "2026-09-25T14:30:00+03:00",
		"2026-09-25T11:00:00Z": "2026-09-25T11:00:00Z",
		"2026-09-25":           "2026-09-25T00:00:00+03:00",
	} {
		got, err := parseLogTime(raw, now)
		if err != nil || got.Format(time.RFC3339) != want {
			t.Fatalf("%q → %v (%v), want %s", raw, got.Format(time.RFC3339), err, want)
		}
	}
	if _, err := parseLogTime("yesterday", now); err == nil {
		t.Fatal("garbage time must be refused")
	}
	// Local 00:30–01:30 on the 25th is 21:30–22:30 UTC on the 24th.
	from, _ := parseLogTime("2026-09-25 00:30", now)
	to, _ := parseLogTime("2026-09-25 01:30", now)
	if d := strings.Join(utcDays(from, to), ","); d != "2026-09-24" {
		t.Fatalf("utcDays: %s", d)
	}
	// A window ending at 23:58 UTC also needs the next folder (shipped just after midnight).
	if d := strings.Join(utcDays(time.Date(2026, 9, 24, 23, 0, 0, 0, time.UTC), time.Date(2026, 9, 24, 23, 58, 0, 0, time.UTC)), ","); d != "2026-09-24,2026-09-25" {
		t.Fatalf("utcDays across midnight: %s", d)
	}
}
