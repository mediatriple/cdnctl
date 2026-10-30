package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// wafExclusionsAPI is a fake of the endpoints `waf exempt`, `waf exclusions` and `waf insights`
// use: GET events/{ref}, GET and POST waf/exclusions, POST waf/exclusions/preview, DELETE
// waf/exclusions/{id} and GET waf/insights. Each answer is set per test; every request is
// recorded with its decoded body.
type wafExclusionsAPI struct {
	mu       sync.Mutex
	requests []wafRecordedRequest

	event      string // body of GET events/{ref}
	eventCode  int
	add        string // body of POST exclusions
	addCode    int
	list       string // body of GET exclusions
	listCode   int
	remove     string // body of DELETE exclusions/{id}
	removeCode int

	preview      string // body of POST exclusions/preview
	previewCode  int
	insights     string // body of GET insights
	insightsCode int
}

type wafRecordedRequest struct {
	Method, Path, Lang string
	Body               map[string]any
}

func newWafExclusionsAPI(t *testing.T, lang string) *wafExclusionsAPI {
	t.Helper()
	api := &wafExclusionsAPI{eventCode: http.StatusOK, addCode: http.StatusCreated, listCode: http.StatusOK, removeCode: http.StatusOK, previewCode: http.StatusOK, insightsCode: http.StatusOK}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		api.mu.Lock()
		api.requests = append(api.requests, wafRecordedRequest{Method: r.Method, Path: r.URL.Path, Lang: r.Header.Get("Accept-Language"), Body: body})
		api.mu.Unlock()

		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, `{"message":"Unauthenticated."}`, http.StatusUnauthorized)
			return
		}
		base := "/api/accounts/" + wafTestAccount + "/waf/"
		code, answer := http.StatusNotFound, `{"message":"no such route"}`
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, base+"events/"):
			code, answer = api.eventCode, api.event
		case r.Method == http.MethodGet && r.URL.Path == base+"exclusions":
			code, answer = api.listCode, api.list
		case r.Method == http.MethodPost && r.URL.Path == base+"exclusions":
			code, answer = api.addCode, api.add
		case r.Method == http.MethodPost && r.URL.Path == base+"exclusions/preview":
			code, answer = api.previewCode, api.preview
		case r.Method == http.MethodGet && r.URL.Path == base+"insights":
			code, answer = api.insightsCode, api.insights
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, base+"exclusions/"):
			code, answer = api.removeCode, api.remove
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		fmt.Fprint(w, answer)
	}))
	t.Cleanup(srv.Close)
	wafTestEnv(t, srv, lang)
	return api
}

func (api *wafExclusionsAPI) calls(method string) []wafRecordedRequest {
	api.mu.Lock()
	defer api.mu.Unlock()
	var out []wafRecordedRequest
	for _, r := range api.requests {
		if r.Method == method {
			out = append(out, r)
		}
	}
	return out
}

// wafEventWithRules is a found event: the 403 of a theme save on admin-ajax.php.
func wafEventWithRules(rules ...map[string]any) string {
	body, _ := json.Marshal(map[string]any{"found": true, "event": map[string]any{
		"ref":    wafTestRef,
		"method": "POST",
		"uri":    "/wp-admin/admin-ajax.php?action=td_ajax_save&x=1#top",
		"host":   "www.example.com",
		"rules":  rules,
	}})
	return string(body)
}

func wafRule(id string, exemptable bool, target string) map[string]any {
	return map[string]any{"id": id, "exemptable": exemptable, "target": target, "message": "m", "family": "x"}
}

const wafAddedBody = `{"status":"success","deployed":true,"exclusion":{"id":7,"rule_id":"932120","path":"/wp-admin/admin-ajax.php","match":"exact","target":"ARGS:content","note":"Reference ID 5c0f3e9a7b21","family":"rce"}}`

func wafExemptArgs(ref string, options map[string]string, bools ...string) parsedArgs {
	opts := map[string]string{"account": wafTestAccount}
	for key, value := range options {
		opts[key] = value
	}
	flags := map[string]bool{}
	for _, key := range bools {
		flags[key] = true
		opts[key] = "true"
	}
	return parsedArgs{Positionals: []string{"exempt", ref}, Options: opts, Bools: flags, Multi: map[string][]string{}}
}

// The switches never take the next word: `--prefix <ref>` keeps the ref, `--yes 12` the id.
// Every other command keeps parseArgs exactly as it was.
func TestWafSwitchesNeverSwallowThePositional(t *testing.T) {
	got := parseArgsWithSwitches([]string{"exempt", "--prefix", wafTestRef, "--rule", "932120", "--field", ""}, wafSwitches)
	if strings.Join(got.Positionals, " ") != "exempt "+wafTestRef || !got.Bools["prefix"] || got.Options["rule"] != "932120" {
		t.Fatalf("--prefix swallowed the ref: %+v", got)
	}
	if value, set := got.Options["field"]; !set || value != "" {
		t.Fatalf(`--field "" must be set and empty: %+v`, got.Options)
	}
	rm := parseArgsWithSwitches([]string{"exclusions", "rm", "--yes", "12"}, wafSwitches)
	if strings.Join(rm.Positionals, " ") != "exclusions rm 12" || !rm.Bools["yes"] {
		t.Fatalf("--yes swallowed the id: %+v", rm)
	}
	if plain := parseArgs([]string{"--prefix", "x"}); plain.Options["prefix"] != "x" || len(plain.Positionals) != 0 {
		t.Fatalf("parseArgs changed: %+v", plain)
	}
}

// What the panel's "Exempt" pre-fills is what is sent: the one exemptable rule, the field
// it matched, the path without its query, only that exact path, the Reference ID and a
// note naming it. The score total (not exemptable) is never offered.
func TestWafExemptAddsWhatThePanelPrefills(t *testing.T) {
	api := newWafExclusionsAPI(t, "en")
	api.event = wafEventWithRules(wafRule("932120", true, "ARGS:content"), wafRule("949110", false, ""))
	api.add = wafAddedBody

	out, err := captureStdout(func() error { return cmdWaf(wafExemptArgs(strings.ToUpper(wafTestRef[:12]), nil)) })
	if err != nil {
		t.Fatalf("waf exempt: %v", err)
	}
	posts := api.calls(http.MethodPost)
	if len(posts) != 1 {
		t.Fatalf("expected one POST, got %d", len(posts))
	}
	want := map[string]any{
		"rule": "932120", "path": "/wp-admin/admin-ajax.php", "match": "exact", "target": "ARGS:content",
		"ref": wafTestRef, "note": "Reference ID " + wafTestRef[:12],
	}
	for key, value := range want {
		if posts[0].Body[key] != value {
			t.Errorf("POST %s = %v, want %v (body %v)", key, posts[0].Body[key], value, posts[0].Body)
		}
	}
	if posts[0].Lang != "en" {
		t.Errorf("Accept-Language = %q, want en", posts[0].Lang)
	}
	for _, line := range []string{
		"Added WAF exception 7. The edges apply it within 1-2 minutes.",
		"Rule   932120",
		"Path   /wp-admin/admin-ajax.php  (only this exact path)",
		"Field  ARGS:content",
		"To remove it: `cdnctl waf exclusions rm 7 --yes`",
	} {
		if !strings.Contains(out, line) {
			t.Errorf("output lacks %q:\n%s", line, out)
		}
	}
}

// The flags change the pre-fill the way editing the panel's form does.
func TestWafExemptFlagsEditThePrefill(t *testing.T) {
	api := newWafExclusionsAPI(t, "en")
	api.event = wafEventWithRules(wafRule("941100", true, "ARGS:content"), wafRule("942100", true, "ARGS:q"))
	api.add = wafAddedBody

	_, err := captureStdout(func() error {
		return cmdWaf(wafExemptArgs(wafTestRef, map[string]string{"rule": "942100", "path": "/wp-json/wp/v2/pages", "field": ""}, "prefix"))
	})
	if err != nil {
		t.Fatalf("waf exempt: %v", err)
	}
	body := api.calls(http.MethodPost)[0].Body
	if body["rule"] != "942100" || body["path"] != "/wp-json/wp/v2/pages" || body["match"] != "prefix" || body["target"] != "" {
		t.Fatalf("flags not applied: %v", body)
	}
}

// When the request leaves a choice open, nothing is added: the reader is told which flag
// settles it (exit 2), or that nothing here can be exempted (exit 1).
func TestWafExemptNeverGuesses(t *testing.T) {
	cases := []struct {
		name    string
		rules   []map[string]any
		options map[string]string
		code    int
		want    []string
	}{
		{"two rules, no --rule", []map[string]any{wafRule("941100", true, ""), wafRule("942100", true, "ARGS:q")}, nil, 2, []string{"941100, 942100", "--rule <id>"}},
		{"--rule it did not match", []map[string]any{wafRule("941100", true, "")}, map[string]string{"rule": "930120"}, 2, []string{"Rule 930120 cannot be exempted", "941100"}},
		{"--rule a score total", []map[string]any{wafRule("941100", true, ""), wafRule("949110", false, "")}, map[string]string{"rule": "949110"}, 2, []string{"Rule 949110 cannot be exempted"}},
		{"one rule in two fields", []map[string]any{wafRule("942100", true, "ARGS:q"), wafRule("942100", true, "ARGS:s")}, nil, 2, []string{`"ARGS:q", "ARGS:s"`, `--field ""`}},
		{"nothing exemptable", []map[string]any{wafRule("200004", false, ""), wafRule("949110", false, "")}, nil, 1, []string{"None of the rules", "`cdnctl waf show " + wafTestRef + "`"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newWafExclusionsAPI(t, "en")
			api.event = wafEventWithRules(tc.rules...)
			api.add = wafAddedBody

			err := cmdWaf(wafExemptArgs(wafTestRef, tc.options))
			exit, ok := isExitError(err)
			if !ok || exit.code != tc.code {
				t.Fatalf("expected exit %d, got %v", tc.code, err)
			}
			for _, want := range tc.want {
				if !strings.Contains(exit.message, want) {
					t.Errorf("message lacks %q: %q", want, exit.message)
				}
			}
			if n := len(api.calls(http.MethodPost)); n != 0 {
				t.Errorf("an exception was added (%d POST) although the choice was open", n)
			}
		})
	}

	// With --rule the same request goes through, and a choice of field with --field.
	api := newWafExclusionsAPI(t, "en")
	api.event = wafEventWithRules(wafRule("942100", true, "ARGS:q"), wafRule("942100", true, "ARGS:s"))
	api.add = wafAddedBody
	if _, err := captureStdout(func() error { return cmdWaf(wafExemptArgs(wafTestRef, map[string]string{"field": "ARGS:s"})) }); err != nil {
		t.Fatalf("with --field: %v", err)
	}
	if got := api.calls(http.MethodPost)[0].Body["target"]; got != "ARGS:s" {
		t.Errorf("target = %v, want ARGS:s", got)
	}
}

// A malformed call costs no request: a bad ref, a bare --rule/--path/--field, a format
// that does not exist.
func TestWafExemptRejectsMalformedCallsOffline(t *testing.T) {
	api := newWafExclusionsAPI(t, "en")
	for name, args := range map[string]parsedArgs{
		"no ref":      {Positionals: []string{"exempt"}, Options: map[string]string{"account": wafTestAccount}, Bools: map[string]bool{}},
		"bad ref":     wafExemptArgs("abc", nil),
		"bare rule":   wafExemptArgs(wafTestRef, map[string]string{"rule": "true"}),
		"bare path":   wafExemptArgs(wafTestRef, map[string]string{"path": "true"}),
		"bare field":  wafExemptArgs(wafTestRef, map[string]string{"field": "true"}),
		"format yaml": wafExemptArgs(wafTestRef, map[string]string{"format": "yaml"}),
	} {
		if exit, ok := isExitError(cmdWaf(args)); !ok || exit.code != 2 || exit.message == "" {
			t.Errorf("%s: expected exit 2 with a message, got %+v", name, exit)
		}
	}
	if len(api.requests) != 0 {
		t.Fatalf("%d request(s) for calls that were never valid", len(api.requests))
	}
}

// No event, no exception; the API's refusal of the exception is shown as the API wrote it.
func TestWafExemptReportsTheLookupAndTheRefusal(t *testing.T) {
	api := newWafExclusionsAPI(t, "en")
	api.event = `{"found":false,"event":null}`
	err := cmdWaf(wafExemptArgs(wafTestRef, nil))
	if exit, ok := isExitError(err); !ok || exit.code != 1 || !strings.Contains(exit.message, "No WAF event with Reference ID") {
		t.Fatalf("not found: expected exit 1 with the lookup message, got %v", err)
	}
	if len(api.calls(http.MethodPost)) != 0 {
		t.Fatal("an exception was added for a block that was not found")
	}

	api.event = wafEventWithRules(wafRule("932120", true, "ARGS:content"))
	api.add, api.addCode = `{"status":"error","error_code":"exclusion_limit","message":"An account can have at most 50 exceptions."}`, http.StatusUnprocessableEntity
	err = cmdWaf(wafExemptArgs(wafTestRef, nil))
	if exit, ok := isExitError(err); !ok || exit.code != 1 || exit.message != "An account can have at most 50 exceptions." {
		t.Fatalf("refused: expected exit 1 with the API message, got %v", err)
	}

	out, err := captureStdout(func() error { return cmdWaf(wafExemptArgs(wafTestRef, map[string]string{"format": "json"})) })
	if exit, ok := isExitError(err); !ok || exit.code != 1 || !strings.Contains(out, `"error_code": "exclusion_limit"`) {
		t.Fatalf("json: expected the API body and exit 1, got %v / %q", err, out)
	}

	api.add, api.addCode = `{"status":"success","deployed":false,"exclusion":{"id":7,"rule_id":"932120","path":"/wp-admin/admin-ajax.php","match":"exact","target":"ARGS:content"}}`, http.StatusOK
	out, err = captureStdout(func() error { return cmdWaf(wafExemptArgs(wafTestRef, nil)) })
	if err != nil || !strings.Contains(out, "This exception already exists (id 7); nothing changed.") {
		t.Fatalf("existing: %v\n%s", err, out)
	}
}

// The command line as typed, through run(): the switch parser is the one waf gets.
func TestWafExemptFromTheCommandLine(t *testing.T) {
	api := newWafExclusionsAPI(t, "en")
	api.event = wafEventWithRules(wafRule("932120", true, "ARGS:content"))
	api.add = wafAddedBody

	if _, err := captureStdout(func() error {
		return run([]string{"waf", "exempt", "--prefix", wafTestRef, "--account", wafTestAccount, "--path", "/wp-admin"})
	}); err != nil {
		t.Fatalf("run: %v", err)
	}
	body := api.calls(http.MethodPost)[0].Body
	if body["match"] != "prefix" || body["path"] != "/wp-admin" {
		t.Fatalf("parsed wrongly: %v", body)
	}
}

func wafListArgs(action string, extra ...string) parsedArgs {
	return parsedArgs{Positionals: append([]string{"exclusions", action}, extra...), Options: map[string]string{"account": wafTestAccount}, Bools: map[string]bool{}, Multi: map[string][]string{}}
}

func TestWafExclusionsListPrintsTheTable(t *testing.T) {
	api := newWafExclusionsAPI(t, "en")
	api.list = `{"status":"success","account_uuid":"abc123","limit":50,"exclusions":[` +
		`{"id":7,"rule_id":"932120","path":"/wp-admin/admin-ajax.php","match":"exact","target":"ARGS:content","note":"Reference ID 5c0f3e9a7b21"},` +
		`{"id":12,"rule_id":"942100","path":"/search\u001b[2J","match":"prefix","target":"","note":null}]}`

	out, err := captureStdout(func() error { return cmdWaf(wafListArgs("list")) })
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two rows on stdout (the header goes to stderr), got:\n%s", out)
	}
	if lines[0] != "7   932120  exact   /wp-admin/admin-ajax.php  ARGS:content  Reference ID 5c0f3e9a7b21" {
		t.Errorf("row 1 = %q", lines[0])
	}
	if lines[1] != `12  942100  prefix  /search\u001b[2J          all fields` {
		t.Errorf("row 2 = %q", lines[1])
	}
	if got := api.calls(http.MethodGet)[0]; got.Path != "/api/accounts/abc123/waf/exclusions" || got.Lang != "en" {
		t.Errorf("asked %s in %q", got.Path, got.Lang)
	}

	api.list = `{"status":"success","account_uuid":"abc123","limit":50,"exclusions":[]}`
	if out, err := captureStdout(func() error { return cmdWaf(wafListArgs("list")) }); err != nil || strings.TrimSpace(out) != "" {
		t.Fatalf("empty list: %v %q", err, out)
	}

	api.list, api.listCode = `{"status":"error","error_code":"account_not_found","message":"Account not found."}`, http.StatusNotFound
	if exit, ok := isExitError(cmdWaf(wafListArgs("list"))); !ok || exit.code != 1 || exit.message != "Account not found." {
		t.Fatalf("not found: %+v", exit)
	}
}

func TestWafExclusionsRmNeedsYesAndAnID(t *testing.T) {
	api := newWafExclusionsAPI(t, "en")
	api.remove = `{"status":"success","deployed":true,"exclusion":{"id":12,"rule_id":"942100","path":"/search","match":"prefix","target":""}}`

	for name, args := range map[string]parsedArgs{
		"no id":     wafListArgs("rm"),
		"not an id": wafListArgs("rm", "12; DROP"),
		"no --yes":  wafListArgs("rm", "12"),
		"unknown":   wafListArgs("purge", "12"),
	} {
		if exit, ok := isExitError(cmdWaf(args)); !ok || exit.code != 2 {
			t.Errorf("%s: expected exit 2, got %+v", name, exit)
		}
	}
	if len(api.requests) != 0 {
		t.Fatalf("%d request(s) before the call was valid", len(api.requests))
	}

	args := wafListArgs("rm", "12")
	args.Bools["yes"] = true
	out, err := captureStdout(func() error { return cmdWaf(args) })
	if err != nil {
		t.Fatalf("rm: %v", err)
	}
	if got := api.calls(http.MethodDelete); len(got) != 1 || got[0].Path != "/api/accounts/abc123/waf/exclusions/12" {
		t.Fatalf("DELETE = %+v", got)
	}
	if !strings.Contains(out, "Removed WAF exception 12. Its rule applies on that path again within 1-2 minutes.") ||
		!strings.Contains(out, "(this path and everything under it)") || !strings.Contains(out, "all fields") {
		t.Errorf("output:\n%s", out)
	}

	api.remove, api.removeCode = `{"status":"error","error_code":"exclusion_not_found","message":"This account has no WAF exception with that ID."}`, http.StatusNotFound
	if exit, ok := isExitError(cmdWaf(args)); !ok || exit.code != 1 || exit.message != "This account has no WAF exception with that ID." {
		t.Fatalf("not found: %+v", exit)
	}
}

// Labels and fixed texts follow --lang; the API is asked in that language too.
func TestWafExclusionsSpeakTheReadersLanguage(t *testing.T) {
	api := newWafExclusionsAPI(t, "tr")
	api.remove = `{"status":"success","deployed":true,"exclusion":{"id":12,"rule_id":"942100","path":"/search","match":"exact","target":""}}`

	args := wafListArgs("rm", "12")
	args.Bools["yes"] = true
	out, err := captureStdout(func() error { return cmdWaf(args) })
	if err != nil {
		t.Fatalf("rm: %v", err)
	}
	if !strings.Contains(out, "12 numaralı WAF istisnası kaldırıldı") || !strings.Contains(out, "yalnızca bu yol") {
		t.Errorf("not in Turkish:\n%s", out)
	}
	if got := api.calls(http.MethodDelete)[0].Lang; got != "tr" {
		t.Errorf("Accept-Language = %q, want tr", got)
	}
}

// What `waf exempt` sends as the path is what an exception is compared with on the edge,
// REQUEST_FILENAME: the URI's part before the first "?", every %XX decoded once. The cases are
// the panel's tests/fixtures/waf-request-filename.json, read back from libmodsecurity 3.0.15
// (slayer2 1.31.6-xrg1) where they reach it; the panel's "Exempt" decodes the same way. A
// result that is not UTF-8 text, or holds a control character, "?" or "#", is no path an
// exception can hold: the URI's path as sent, and decoded false.
func TestWafRequestFilenameIsWhatTheEdgeCompares(t *testing.T) {
	cases := []struct {
		uri, filenameHex, path string
		decoded                bool
	}{
		{"/caf%C3%A9", "2f636166c3a9", "/café", true},
		{"/caf%c3%a9", "2f636166c3a9", "/café", true},
		{"/café", "2f636166c3a9", "/café", true},
		{"/2016/08/29/2016-mtv-video-muzik-odulleri-sahipleri/nicki-minaj-2016-mtv-video-mu%CC%88zik-o%CC%88du%CC%88ller?amp=1", "2f323031362f30382f32392f323031362d6d74762d766964656f2d6d757a696b2d6f64756c6c6572692d73616869706c6572692f6e69636b692d6d696e616a2d323031362d6d74762d766964656f2d6d75cc887a696b2d6fcc886475cc886c6c6572", "/2016/08/29/2016-mtv-video-muzik-odulleri-sahipleri/nicki-minaj-2016-mtv-video-mu\u0308zik-o\u0308du\u0308ller", true},
		{"/%D9%85%D9%82%D8%A7%D9%84%D8%A7%D8%AA/%d8%a7%d8%ae%d8%aa%d8%a8%d8%a7%d8%b1", "2fd985d982d8a7d984d8a7d8aa2fd8a7d8aed8aad8a8d8a7d8b1", "/مقالات/اختبار", true},
		{"/%D1%81%D1%82%D0%B0%D1%82%D1%8C%D0%B8/%D1%82%D0%B5%D1%81%D1%82", "2fd181d182d0b0d182d18cd0b82fd182d0b5d181d182", "/статьи/тест", true},
		{"/a%E2%80%8Cb", "2f61e2808c62", "/a\u200cb", true},
		{"/a%2Fb", "2f612f62", "/a/b", true},
		{"/a+b", "2f612b62", "/a+b", true},
		{"/a%20b", "2f612062", "/a%20b", false},
		{"/a%25b", "2f612562", "/a%b", true},
		{"/a%2541", "2f61253431", "/a%41", true},
		// A "%" at the end would take the edge rule's closing quote: no exception holds it.
		{"/100%25", "2f31303025", "/100%25", false},
		{"/sale-50%25?x=1", "2f73616c652d353025", "/sale-50%25", false},
		{"/100%25%25", "2f3130302525", "/100%25%25", false},
		{"/s/100%25/x", "2f732f313030252f78", "/s/100%/x", true},
		{"/a/../b", "2f612f2e2e2f62", "/a/../b", true},
		{"//a", "2f2f61", "//a", true},
		{"/a%2e%2e/b", "2f612e2e2f62", "/a../b", true},
		{"/%F0%A0%AE%B7", "2ff0a0aeb7", "/%F0%A0%AE%B7", false},
		{"/x%3Fa", "2f783f61", "/x%3Fa", false},
		{"/x%3Fa?q=1", "2f783f61", "/x%3Fa", false},
		{"/a%23b", "2f612362", "/a%23b", false},
		{"/caf%E9", "2f636166e9", "/caf%E9", false},
		{"/%C0%AF", "2fc0af", "/%C0%AF", false},
		{"/%ED%A0%80", "2feda080", "/%ED%A0%80", false},
		{"/a%0Ab", "2f610a62", "/a%0Ab", false},
		{"/a%09b", "2f610962", "/a%09b", false},
		{"/a%7Fb", "2f617f62", "/a%7Fb", false},
		{"/a%C2%85b", "2f61c28562", "/a%C2%85b", false},
		{"/a%zz", "2f61257a7a", "/a%zz", true},
		{"/a%2", "2f612532", "/a%2", true},
		{"/a%", "2f6125", "/a%", false},
		{"/q?x=%C3%A9", "2f71", "/q", true},
		{"?q=1", "2f", "/", true},
		{"/a#frag", "2f61", "/a", true},
		// Any decoded path the panel refuses is kept as sent: a space, a quote, ";", a backslash,
		// braces, "$", NBSP, a bidi control, U+2028, an emoji, more than 255 characters.
		{"/docs/my%20file.pdf", "2f646f63732f6d792066696c652e706466", "/docs/my%20file.pdf", false},
		{"/a%22b", "2f612262", "/a%22b", false},
		{"/a%27b", "2f612762", "/a%27b", false},
		{"/a;b", "2f613b62", "/a;b", false},
		{"/a%3Bb", "2f613b62", "/a%3Bb", false},
		{"/a%5Cb", "2f615c62", "/a%5Cb", false},
		{"/a%7Bb%7D", "2f617b627d", "/a%7Bb%7D", false},
		{"/a%24b", "2f612462", "/a%24b", false},
		{"/a%C2%A0b", "2f61c2a062", "/a%C2%A0b", false},
		{"/a%E2%80%AEb", "2f61e280ae62", "/a%E2%80%AEb", false},
		{"/a%E2%80%A8b", "2f61e280a862", "/a%E2%80%A8b", false},
		{"/%F0%9F%98%80", "2ff09f9880", "/%F0%9F%98%80", false},
		{"/a%E2%80%8Db", "2f61e2808d62", "/a\u200db", true},
		{"/a%CC%88", "2f61cc88", "/a\u0308", true},
		{"/" + strings.Repeat("b", 255), "2f" + strings.Repeat("62", 255), "/" + strings.Repeat("b", 255), true},
		{"/" + strings.Repeat("b", 256), "2f" + strings.Repeat("62", 256), "/" + strings.Repeat("b", 256), false},
		{"/" + strings.Repeat("%D8%A8", 255), "2f" + strings.Repeat("d8a8", 255), "/" + strings.Repeat("ب", 255), true},
	}
	for _, c := range cases {
		path, decoded := wafRequestFilename(c.uri)
		if path != c.path || decoded != c.decoded {
			t.Errorf("wafRequestFilename(%q) = %q, %v; want %q, %v", c.uri, path, decoded, c.path, c.decoded)
		}
		if decoded && fmt.Sprintf("%x", path) != c.filenameHex {
			t.Errorf("wafRequestFilename(%q) = %x, the edge has %s", c.uri, path, c.filenameHex)
		}
	}
	// The panel's shared fixture, where this runs inside the panel repository (the public
	// mirror ships the Go files alone): the same answer for every case.
	if raw, err := os.ReadFile("../../tests/fixtures/waf-request-filename.json"); err == nil {
		var fixture struct {
			Cases []struct {
				URI     string `json:"uri"`
				Prefill struct {
					Path    string `json:"path"`
					Decoded bool   `json:"decoded"`
				} `json:"prefill"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(raw, &fixture); err != nil || len(fixture.Cases) < 50 {
			t.Fatalf("tests/fixtures/waf-request-filename.json: %v, %d cases", err, len(fixture.Cases))
		}
		for _, c := range fixture.Cases {
			if path, decoded := wafRequestFilename(c.URI); path != c.Prefill.Path || decoded != c.Prefill.Decoded {
				t.Errorf("fixture: wafRequestFilename(%q) = %q, %v; want %q, %v", c.URI, path, decoded, c.Prefill.Path, c.Prefill.Decoded)
			}
		}
	}
	// Whatever the log holds, an answer and no panic; nothing at all is the home page.
	for _, uri := range []string{"", "%", "%%", "/%", "/%E", "/%G0", "?", "#", "/\xff\xfe"} {
		wafRequestFilename(uri)
	}
	if path, decoded := wafRequestFilename(""); path != "/" || !decoded {
		t.Errorf(`wafRequestFilename("") = %q, %v`, path, decoded)
	}
}

// A request on a non-ASCII path is exempted on its decoded path; one whose path no exception
// can hold is not exempted at all: the reader is told why and which flags settle it (exit 2).
func TestWafExemptSendsTheDecodedPath(t *testing.T) {
	event := func(uri string) string {
		body, _ := json.Marshal(map[string]any{"found": true, "event": map[string]any{
			"ref": wafTestRef, "method": "GET", "uri": uri, "host": "www.example.com",
			"rules": []map[string]any{wafRule("951120", true, ""), wafRule("959100", false, "")},
		}})
		return string(body)
	}

	api := newWafExclusionsAPI(t, "en")
	api.event = event("/2016/nicki-minaj-2016-mtv-video-mu%CC%88zik-o%CC%88du%CC%88ller?amp=1")
	api.add = wafAddedBody
	if _, err := captureStdout(func() error { return cmdWaf(wafExemptArgs(wafTestRef, nil)) }); err != nil {
		t.Fatalf("waf exempt: %v", err)
	}
	if got := api.calls(http.MethodPost)[0].Body["path"]; got != "/2016/nicki-minaj-2016-mtv-video-mu\u0308zik-o\u0308du\u0308ller" {
		t.Errorf("path = %q, want the decoded NFD path", got)
	}

	api = newWafExclusionsAPI(t, "en")
	api.event = event("/caf%E9?x=1")
	api.add = wafAddedBody
	exit, ok := isExitError(cmdWaf(wafExemptArgs(wafTestRef, nil)))
	if !ok || exit.code != 2 || !strings.Contains(exit.message, "/caf%E9") || !strings.Contains(exit.message, "--path <folder> --prefix") {
		t.Fatalf("an undecodable path: %+v", exit)
	}
	if n := len(api.calls(http.MethodPost)); n != 0 {
		t.Fatalf("an exception that could never apply was added (%d POST)", n)
	}

	// --path settles it: the reader's own path goes as given.
	if _, err := captureStdout(func() error {
		return cmdWaf(wafExemptArgs(wafTestRef, map[string]string{"path": "/caf"}, "prefix"))
	}); err != nil {
		t.Fatalf("with --path: %v", err)
	}
	if body := api.calls(http.MethodPost)[0].Body; body["path"] != "/caf" || body["match"] != "prefix" {
		t.Errorf("with --path: %v", body)
	}

	// A path that decodes but holds what no exception can (a space, an emoji): the same exit 2,
	// nothing sent; the folder before it, as a prefix, is what covers the request.
	for _, uri := range []string{"/docs/my%20file.pdf", "/docs/%F0%9F%98%80.pdf", "/docs/a%22b"} {
		refused := newWafExclusionsAPI(t, "en")
		refused.event = event(uri)
		refused.add = wafAddedBody
		exit, ok := isExitError(cmdWaf(wafExemptArgs(wafTestRef, nil)))
		if !ok || exit.code != 2 || !strings.Contains(exit.message, uri) || !strings.Contains(exit.message, "--path <folder> --prefix") {
			t.Fatalf("%s: %+v", uri, exit)
		}
		if n := len(refused.calls(http.MethodPost)); n != 0 {
			t.Fatalf("%s: an exception that could never apply was added (%d POST)", uri, n)
		}
	}

	// REQUEST_FILENAME "/sale-50%": a "%" at the end would take the edge rule's closing quote,
	// so no exception holds it either. The message names the "%" itself (a %% in the format).
	for lang, says := range map[string]string{"en": "or a % at the end", "tr": "ya da sonda %)"} {
		trailing := newWafExclusionsAPI(t, lang)
		trailing.event = event("/sale-50%25?x=1")
		trailing.add = wafAddedBody
		exit, ok := isExitError(cmdWaf(wafExemptArgs(wafTestRef, nil)))
		if !ok || exit.code != 2 || !strings.Contains(exit.message, "/sale-50%25") || !strings.Contains(exit.message, says) || strings.Contains(exit.message, "%!") {
			t.Fatalf("%s: a path ending in %%: %+v", lang, exit)
		}
		if n := len(trailing.calls(http.MethodPost)); n != 0 {
			t.Fatalf("%s: an exception the edge cannot hold was added (%d POST)", lang, n)
		}
	}
}
