package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"
)

const wafTestAccount = "abc123"
const wafTestRef = "5c0f3e9a7b21d4e68f90a1b2c3d4e5f6"

// wafTestEnv points cdnctl at a fake API, with nothing from the developer's own
// configuration or environment leaking into the run.
func wafTestEnv(t *testing.T, srv *httptest.Server, lang string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CDN_ENDPOINT", "")
	t.Setenv("CDN_ACCESS_TOKEN", "")
	t.Setenv("CDN_ACCOUNT", "")
	t.Setenv("CDNCTL_ENDPOINT", srv.URL)
	t.Setenv("CDNCTL_TOKEN", "tok")
	t.Setenv("CDNCTL_LANG", lang)
	previous := langOverride
	langOverride = ""
	t.Cleanup(func() { langOverride = previous })
}

// wafEventServer answers GET accounts/{uuid}/waf/events/{ref} with body, and records
// how often it was asked and in which language.
func wafEventServer(t *testing.T, status int, body string) (*httptest.Server, *int32, *atomic.Value) {
	t.Helper()
	var hits int32
	var lang atomic.Value
	lang.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/api/accounts/"+wafTestAccount+"/waf/events/") {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, `{"message":"Unauthenticated."}`, http.StatusUnauthorized)
			return
		}
		lang.Store(r.Header.Get("Accept-Language"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits, &lang
}

func wafShowArgs(ref string, options map[string]string) parsedArgs {
	opts := map[string]string{"account": wafTestAccount}
	for key, value := range options {
		opts[key] = value
	}
	return parsedArgs{Positionals: []string{"show", ref}, Options: opts, Bools: map[string]bool{}, Multi: map[string][]string{}}
}

func TestNormalizeWafRef(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{wafTestRef, wafTestRef, true},
		{wafTestRef[:12], wafTestRef[:12], true}, // what the panel table shows
		{strings.ToUpper(wafTestRef), wafTestRef, true},
		{"  " + wafTestRef + "\n", wafTestRef, true},
		{wafTestRef[:11], "", false},      // too short: would match unrelated requests
		{wafTestRef + "0", "", false},     // 33 characters
		{"5c0f3e9a7b2g", "", false},       // not hex
		{"5c0f3e9a-7b21-d4e6", "", false}, // a UUID-shaped paste is not the reference
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := normalizeWafRef(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("normalizeWafRef(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// A malformed reference is refused on this computer: exit 2 with the expected shape,
// and the API is never asked.
func TestWafShowRejectsABadRefWithoutCallingTheAPI(t *testing.T) {
	srv, hits, _ := wafEventServer(t, http.StatusOK, `{"found":false,"event":null}`)
	wafTestEnv(t, srv, "en")

	for _, ref := range []string{"abc", "zzzzzzzzzzzzzzzz", wafTestRef + "ff"} {
		err := cmdWaf(wafShowArgs(ref, nil))
		exit, ok := isExitError(err)
		if !ok || exit.code != 2 {
			t.Fatalf("%q: expected exit 2, got %v", ref, err)
		}
		if !strings.Contains(exit.message, "12 to 32 hexadecimal") {
			t.Errorf("%q: message does not say what is expected: %q", ref, exit.message)
		}
	}

	err := cmdWaf(parsedArgs{Positionals: []string{"show"}, Options: map[string]string{"account": wafTestAccount}})
	if exit, ok := isExitError(err); !ok || exit.code != 2 || !strings.Contains(exit.message, "cdnctl waf show <ref>") {
		t.Fatalf("missing ref: expected the usage line with exit 2, got %v", err)
	}
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Fatalf("the API was called %d time(s) for references that were never valid", n)
	}
}

// The table shows the request, each rule with its matched data and the verdict; the
// size is exact (not 2.097152e+07); attacker bytes cannot reach the terminal raw.
func TestWafShowRendersTheEvent(t *testing.T) {
	longData := strings.Repeat("A", 500)
	event := map[string]any{
		"ref":            wafTestRef,
		"time":           "2026-10-07T09:14:03Z",
		"client_ip":      "203.0.113.7",
		"method":         "POST",
		"uri":            "/wp-admin/async-upload.php\x1b[2J",
		"host":           "www.example.com",
		"status":         400,
		"content_type":   "multipart/form-data; boundary=----WebKitFormBoundary",
		"content_length": 20971520,
		"rules": []map[string]any{
			{
				"id":          "200004",
				"message":     "Multipart parser detected a possible unmatched boundary.",
				"data":        "",
				"severity":    "CRITICAL",
				"family":      "protocol",
				"explanation": "The body was cut at the inspection limit.\nThe final boundary was never seen.",
			},
			{
				"id":          930100,
				"message":     "Path Traversal Attack (/../ or /..;/)",
				"data":        "Matched Data: \x1b]0;owned\x07\u202e" + longData,
				"severity":    "CRITICAL",
				"family":      "attack-lfi",
				"explanation": "Bytes inside an uploaded file matched a text pattern.",
			},
		},
		"verdict": map[string]any{
			"kind": "truncated_upload",
			"text": "The upload is larger than the part of the body the WAF inspects.",
		},
	}
	body, _ := json.Marshal(map[string]any{"found": true, "event": event})
	srv, hits, lang := wafEventServer(t, http.StatusOK, string(body))
	wafTestEnv(t, srv, "en")

	out, err := captureStdout(func() error { return cmdWaf(wafShowArgs(strings.ToUpper(wafTestRef), nil)) })
	if err != nil {
		t.Fatalf("waf show: %v", err)
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Fatalf("expected one API call, got %d", atomic.LoadInt32(hits))
	}
	if got := lang.Load().(string); got != "en" {
		t.Errorf("Accept-Language = %q, want en", got)
	}

	for _, want := range []string{
		"Reference ID  " + wafTestRef,
		"Status        400",
		"Method        POST",
		"Host          www.example.com",
		"Client IP     203.0.113.7",
		"Size          20.0 MiB (20971520 bytes)",
		"Matched rules",
		"200004  [CRITICAL]  Multipart parser detected a possible unmatched boundary.",
		"930100  [CRITICAL]  Path Traversal Attack",
		"The body was cut at the inspection limit.\n          The final boundary was never seen.",
		"Verdict (truncated_upload)\n  The upload is larger than the part of the body the WAF inspects.",
		`/wp-admin/async-upload.php\u001b[2J`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.ContainsAny(out, "\x1b\x07\u202e") {
		t.Errorf("a control or bidi character reached the terminal raw:\n%q", out)
	}
	if strings.Contains(out, "2.097152e+07") {
		t.Errorf("size printed as a float:\n%s", out)
	}

	var matched string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "matched:") {
			matched = line
		}
	}
	if matched == "" {
		t.Fatalf("no matched-data line:\n%s", out)
	}
	if strings.Count(matched, "A") >= 500 || !strings.HasSuffix(matched, "…") {
		t.Errorf("matched data was not truncated: %d characters", utf8.RuneCountInString(matched))
	}
	if strings.Contains(out, "matched: \n") || strings.Count(out, "matched:") != 1 {
		t.Errorf("a rule with no matched data still printed a matched line:\n%s", out)
	}
}

// The language the reader chose is the language the API is asked to explain in.
func TestWafShowAsksForTheReadersLanguage(t *testing.T) {
	srv, _, lang := wafEventServer(t, http.StatusOK, `{"found":true,"event":{"ref":"`+wafTestRef+`","rules":[],"verdict":{"kind":"other","text":"x"}}}`)
	wafTestEnv(t, srv, "tr")

	out, err := captureStdout(func() error { return cmdWaf(wafShowArgs(wafTestRef, nil)) })
	if err != nil {
		t.Fatalf("waf show: %v", err)
	}
	if got := lang.Load().(string); got != "tr" {
		t.Errorf("Accept-Language = %q, want tr", got)
	}
	if !strings.Contains(out, "Eşleşen kurallar") {
		t.Errorf("labels are not in the chosen language:\n%s", out)
	}
}

// Nothing found is a failure a script can see (exit 1) with a message a person can
// act on; in JSON mode the body is still printed for the script to read.
func TestWafShowNotFoundExitsOne(t *testing.T) {
	srv, _, _ := wafEventServer(t, http.StatusOK, `{"found":false,"event":null}`)
	wafTestEnv(t, srv, "en")

	err := cmdWaf(wafShowArgs(wafTestRef[:12], nil))
	exit, ok := isExitError(err)
	if !ok || exit.code != 1 {
		t.Fatalf("expected exit 1, got %v", err)
	}
	if !strings.Contains(exit.message, wafTestRef[:12]) || !strings.Contains(exit.message, "--account") {
		t.Errorf("not-found message should name the reference and the account hint: %q", exit.message)
	}

	out, err := captureStdout(func() error { return cmdWaf(wafShowArgs(wafTestRef, map[string]string{"format": "json"})) })
	if exit, ok := isExitError(err); !ok || exit.code != 1 {
		t.Fatalf("json: expected exit 1, got %v", err)
	}
	var payload map[string]any
	if json.Unmarshal([]byte(out), &payload) != nil || payload["found"] != false {
		t.Errorf("json: expected the API body on stdout, got %q", out)
	}
}

func TestWafShowJSONFoundExitsZero(t *testing.T) {
	srv, _, _ := wafEventServer(t, http.StatusOK, `{"found":true,"event":{"ref":"`+wafTestRef+`","content_length":20971520}}`)
	wafTestEnv(t, srv, "en")

	out, err := captureStdout(func() error { return cmdWaf(wafShowArgs(wafTestRef, map[string]string{"format": "json"})) })
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	var payload map[string]any
	if json.Unmarshal([]byte(out), &payload) != nil || payload["found"] != true {
		t.Fatalf("json: unexpected output %q", out)
	}
}

// An API refusal (unknown account, not the owner) surfaces the API's own message.
func TestWafShowReportsTheAPIError(t *testing.T) {
	srv, _, _ := wafEventServer(t, http.StatusNotFound, `{"message":"Account not found."}`)
	wafTestEnv(t, srv, "en")

	err := cmdWaf(wafShowArgs(wafTestRef, nil))
	if exit, ok := isExitError(err); !ok || exit.code != 1 || exit.message != "Account not found." {
		t.Fatalf("expected exit 1 with the API message, got %v", err)
	}
}

// The API's real 404 and 503 bodies carry "found": false as well. Read as "no such
// block", a wrong --account or an Elasticsearch outage would send the reader after a
// block that may well exist; the status decides, and the API's message is shown.
func TestWafShowErrorStatusIsNotANotFound(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"unknown account", http.StatusNotFound, `{"found":false,"event":null,"message":"Account not found."}`, "Account not found."},
		{"search failed", http.StatusServiceUnavailable, `{"found":false,"event":null,"message":"The lookup failed. Please try again in a moment."}`, "The lookup failed. Please try again in a moment."},
		{"no message", http.StatusBadGateway, `{"found":false,"event":null}`, "HTTP 502"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _ := wafEventServer(t, tc.status, tc.body)
			wafTestEnv(t, srv, "en")

			err := cmdWaf(wafShowArgs(wafTestRef, nil))
			exit, ok := isExitError(err)
			if !ok || exit.code != 1 || exit.message != tc.want {
				t.Fatalf("expected exit 1 with %q, got %v", tc.want, err)
			}
			if strings.Contains(exit.message, "No WAF event") {
				t.Errorf("an HTTP %d was reported as a missing event: %q", tc.status, exit.message)
			}

			out, err := captureStdout(func() error { return cmdWaf(wafShowArgs(wafTestRef, map[string]string{"format": "json"})) })
			if exit, ok := isExitError(err); !ok || exit.code != 1 {
				t.Fatalf("json: expected exit 1, got %v", err)
			}
			if !strings.Contains(out, `"found": false`) {
				t.Errorf("json: expected the API body on stdout, got %q", out)
			}
		})
	}
}

func TestTerminalSafeEscapesControlAndBidi(t *testing.T) {
	got := terminalSafe("a\x1b[31mb\nc\u202ed\te")
	want := `a\u001b[31mb\nc\u202ed\te`
	if got != want {
		t.Errorf("terminalSafe = %q, want %q", got, want)
	}
	// Server-written text keeps its line breaks (indented) and Persian joiners.
	if got := terminalText("بارگذاری\u200cشده\nخط دوم", "  "); got != "بارگذاری\u200cشده\n  خط دوم" {
		t.Errorf("terminalText = %q", got)
	}
}
