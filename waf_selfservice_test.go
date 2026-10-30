package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// `waf insights` (the panel's Repeated blocks card) and `waf exempt --dry-run` (the exception
// form's scope preview), against the fake API in waf_exclusions_test.go.

// wafPreviewBody is an answer of POST .../waf/exclusions/preview; overrides replace top-level keys.
func wafPreviewBody(overrides map[string]any) string {
	body := map[string]any{
		"status":       "success",
		"exclusion":    map[string]any{"rule_id": "932120", "path": "/wp-admin/admin-ajax.php", "match": "exact", "target": "ARGS:content"},
		"family":       "rce",
		"attack":       true,
		"all_fields":   false,
		"whole_site":   false,
		"counts":       wafPreviewCounts(12, 9, 40, 25, false, false),
		"family_label": "Command injection",
	}
	for key, value := range overrides {
		body[key] = value
	}
	raw, _ := json.Marshal(body)
	return string(raw)
}

func wafPreviewCounts(b7, ip7, b30, ip30 int, atLeast7, atLeast30 bool) map[string]any {
	return map[string]any{
		"d7":      map[string]any{"blocks": b7, "ips": ip7, "at_least": atLeast7},
		"d30":     map[string]any{"blocks": b30, "ips": ip30, "at_least": atLeast30},
		"sampled": b30,
		"capped":  atLeast30,
	}
}

// What `waf exempt` would add is previewed instead: the same rule, path, match and field are
// sent to the preview, nothing to the add, and the answer is printed as the form shows it.
func TestWafExemptDryRunPreviewsAndAddsNothing(t *testing.T) {
	api := newWafExclusionsAPI(t, "en")
	api.event = wafEventWithRules(wafRule("932120", true, "ARGS:content"), wafRule("949110", false, ""))
	api.preview = wafPreviewBody(nil)
	api.add = wafAddedBody

	out, err := captureStdout(func() error { return cmdWaf(wafExemptArgs(wafTestRef, nil, "dry_run")) })
	if err != nil {
		t.Fatalf("waf exempt --dry-run: %v", err)
	}
	posts := api.calls(http.MethodPost)
	if len(posts) != 1 || posts[0].Path != "/api/accounts/"+wafTestAccount+"/waf/exclusions/preview" {
		t.Fatalf("expected one POST, to the preview: %+v", posts)
	}
	want := map[string]any{"rule": "932120", "path": "/wp-admin/admin-ajax.php", "match": "exact", "target": "ARGS:content"}
	if len(posts[0].Body) != len(want) {
		t.Errorf("preview body = %v, want only %v", posts[0].Body, want)
	}
	for key, value := range want {
		if posts[0].Body[key] != value {
			t.Errorf("preview %s = %v, want %v", key, posts[0].Body[key], value)
		}
	}
	if posts[0].Lang != "en" {
		t.Errorf("Accept-Language = %q, want en", posts[0].Lang)
	}
	for _, line := range []string{
		"Dry run: nothing was added.",
		"Rule   932120 (Command injection)",
		"Path   /wp-admin/admin-ajax.php  (only this exact path)",
		"Field  ARGS:content",
		"Past blocks it would apply to: 12 in the last 7 days (from 9 IP addresses), 40 in the last 30 days (from 25).",
		"Other rules that matched in the same requests still apply.",
		"To add it, run the same command without --dry-run.",
	} {
		if !strings.Contains(out, line) {
			t.Errorf("output lacks %q:\n%s", line, out)
		}
	}
	for _, absent := range []string{"Added WAF exception", "No field set", "whole site", "Response rule"} {
		if strings.Contains(out, absent) {
			t.Errorf("output has %q:\n%s", absent, out)
		}
	}
}

// The warnings are the form's, chosen by the same flags; the counts say "at least" where the
// API says so, and a failed count is not a failure.
func TestWafExemptDryRunWarnsAsTheFormDoes(t *testing.T) {
	cases := []struct {
		name    string
		answer  map[string]any
		want    []string
		without []string
	}{
		{
			"the whole site",
			map[string]any{"exclusion": map[string]any{"rule_id": "942100", "path": "/", "match": "prefix", "target": ""}, "family": "sqli", "family_label": "SQL injection", "all_fields": true, "whole_site": true},
			[]string{"This exception would apply to the whole site: rule 942100 would be off on every path.", "Path   /  (this path and everything under it)", "Field  all fields"},
			[]string{"No field set"},
		},
		{
			"an attack rule on every field of one path",
			map[string]any{"exclusion": map[string]any{"rule_id": "942100", "path": "/search", "match": "exact", "target": ""}, "family": "sqli", "family_label": "SQL injection", "all_fields": true},
			[]string{"No field set: rule 942100 (SQL injection) would not check any field on /search — query and form parameters, cookies, headers and the request body included. If the block names a field, pass it with --field to exempt only that field."},
			[]string{"whole site", "or any path under it"},
		},
		{
			"an attack rule on every field under a path",
			map[string]any{"exclusion": map[string]any{"rule_id": "942100", "path": "/search", "match": "prefix", "target": ""}, "family": "sqli", "family_label": "SQL injection", "all_fields": true},
			[]string{"No field set: rule 942100 (SQL injection) would not check any field on /search or any path under it"},
			[]string{"whole site"},
		},
		{
			"a response rule",
			map[string]any{"exclusion": map[string]any{"rule_id": "951110", "path": "/news/oracle", "match": "exact", "target": ""}, "family": "leakage", "family_label": "Response", "attack": false, "all_fields": true},
			[]string{"Rule   951110 (Response)", "Response rule: it checks the page your origin returns, not the request. The exception switches it off for the whole path; no field can be set."},
			[]string{"No field set", "whole site"},
		},
		{
			"a count that failed",
			map[string]any{"counts": nil},
			[]string{"The blocks could not be counted right now; you can still add the exception.", "To add it, run the same command without --dry-run."},
			[]string{"Past blocks", "Other rules"},
		},
		{
			"no past block",
			map[string]any{"counts": wafPreviewCounts(0, 0, 0, 0, false, false)},
			[]string{"No block of the last 30 days matches this exception."},
			[]string{"Past blocks"},
		},
		{
			"more blocks than were read",
			map[string]any{"counts": wafPreviewCounts(1500, 300, 2000, 900, false, true)},
			[]string{"Past blocks it would apply to: 1500 in the last 7 days (from 300 IP addresses), at least 2000 in the last 30 days (from at least 900)."},
			nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newWafExclusionsAPI(t, "en")
			api.event = wafEventWithRules(wafRule("932120", true, "ARGS:content"))
			api.preview = wafPreviewBody(tc.answer)

			out, err := captureStdout(func() error { return cmdWaf(wafExemptArgs(wafTestRef, nil, "dry_run")) })
			if err != nil {
				t.Fatalf("dry run: %v", err)
			}
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
			for _, absent := range tc.without {
				if strings.Contains(out, absent) {
					t.Errorf("output has %q:\n%s", absent, out)
				}
			}
		})
	}
}

// A value the API refuses ends the dry run as it would end the add: exit 1 with the API's
// own text; in JSON, its body.
func TestWafExemptDryRunReportsTheRefusal(t *testing.T) {
	api := newWafExclusionsAPI(t, "en")
	api.event = wafEventWithRules(wafRule("932120", true, "ARGS:content"))
	api.preview, api.previewCode = `{"status":"error","error_code":"exclusion_bad_path","message":"The path must start with / and contain only URL characters (no spaces or quotes)."}`, http.StatusUnprocessableEntity

	err := cmdWaf(wafExemptArgs(wafTestRef, map[string]string{"path": "/a b"}, "dry_run"))
	if exit, ok := isExitError(err); !ok || exit.code != 1 || exit.message != "The path must start with / and contain only URL characters (no spaces or quotes)." {
		t.Fatalf("expected exit 1 with the API message, got %v", err)
	}
	out, err := captureStdout(func() error {
		return cmdWaf(wafExemptArgs(wafTestRef, map[string]string{"path": "/a b", "format": "json"}, "dry_run"))
	})
	if exit, ok := isExitError(err); !ok || exit.code != 1 || !strings.Contains(out, `"error_code": "exclusion_bad_path"`) {
		t.Fatalf("json: expected the API body and exit 1, got %v / %q", err, out)
	}

	api.preview, api.previewCode = wafPreviewBody(nil), http.StatusOK
	out, err = captureStdout(func() error {
		return cmdWaf(wafExemptArgs(wafTestRef, map[string]string{"format": "json"}, "dry_run"))
	})
	if err != nil || !strings.Contains(out, `"family_label": "Command injection"`) {
		t.Fatalf("json: expected the preview and exit 0, got %v / %q", err, out)
	}
	for _, post := range api.calls(http.MethodPost) {
		if !strings.HasSuffix(post.Path, "/waf/exclusions/preview") {
			t.Fatalf("a dry run reached %s", post.Path)
		}
	}
}

// As typed: --dry-run never takes the Reference ID after it as its value, and a value given
// to it is refused before any request rather than read as "not a dry run".
func TestWafExemptDryRunFromTheCommandLine(t *testing.T) {
	api := newWafExclusionsAPI(t, "en")
	api.event = wafEventWithRules(wafRule("932120", true, "ARGS:content"))
	api.preview = wafPreviewBody(nil)
	api.add = wafAddedBody

	if _, err := captureStdout(func() error {
		return run([]string{"waf", "exempt", "--dry-run", wafTestRef, "--account", wafTestAccount})
	}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if posts := api.calls(http.MethodPost); len(posts) != 1 || !strings.HasSuffix(posts[0].Path, "/waf/exclusions/preview") {
		t.Fatalf("expected only the preview: %+v", posts)
	}

	before := len(api.requests)
	for _, value := range []string{"--dry-run=yes", "--dry-run=no", "--dry-run="} {
		err := run([]string{"waf", "exempt", wafTestRef, "--account", wafTestAccount, value})
		if exit, ok := isExitError(err); !ok || exit.code != 2 {
			t.Errorf("%s: expected exit 2, got %v", value, err)
		}
	}
	if len(api.requests) != before {
		t.Fatalf("%d request(s) for a --dry-run with a value", len(api.requests)-before)
	}
}

// --field= is the empty field where a shell drops "" (Windows PowerShell 5.1); a bare --field,
// what that shell leaves of --field "", says so before any request.
func TestWafFieldEqualsIsEveryField(t *testing.T) {
	api := newWafExclusionsAPI(t, "en")
	api.event = wafEventWithRules(wafRule("932120", true, "ARGS:content"))
	api.add = wafAddedBody

	if _, err := captureStdout(func() error {
		return run([]string{"waf", "exempt", wafTestRef, "--account", wafTestAccount, "--field="})
	}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if body := api.calls(http.MethodPost)[0].Body; body["target"] != "" {
		t.Fatalf("--field= sent target %v, want every field", body["target"])
	}

	before := len(api.requests)
	err := run([]string{"waf", "exempt", wafTestRef, "--account", wafTestAccount, "--field"})
	exit, ok := isExitError(err)
	if !ok || exit.code != 2 || !strings.Contains(exit.message, "--field=") || !strings.Contains(exit.message, "Windows PowerShell 5.1") {
		t.Fatalf("bare --field: expected exit 2 naming --field=, got %v", err)
	}
	if len(api.requests) != before {
		t.Fatal("a bare --field reached the API")
	}

	// The choice of field a request leaves open names --field= too.
	api.event = wafEventWithRules(wafRule("942100", true, "ARGS:q"), wafRule("942100", true, "ARGS:s"))
	exit, ok = isExitError(cmdWaf(wafExemptArgs(wafTestRef, nil)))
	if !ok || exit.code != 2 || !strings.Contains(exit.message, `--field ""`) || !strings.Contains(exit.message, "--field=") {
		t.Fatalf("two fields: %+v", exit)
	}
}

const wafInsightsBody = `{"status":"success","account_uuid":"abc123","days":7,"sampled":7,"total":7,"capped":false,"groups":[` +
	`{"rule_id":"942100","family":"sqli","exemptable":true,"path":"/","field":"ARGS:s","blocks":3,"ips":2,"first_seen":"2026-10-28T10:00:00.000Z","last_seen":"2026-10-29T11:00:00.000Z","last_ref":"c1b2c3d4e5f60718293a4b5c6d7e8f90","covered":false,"family_label":"SQL injection"},` +
	`{"rule_id":"932120","family":"rce","exemptable":true,"path":"/wp-admin/admin-ajax.php","field":"ARGS:td_atts","blocks":2,"ips":2,"first_seen":"2026-10-29T08:00:00.000Z","last_seen":"2026-10-29T09:00:00.000Z","last_ref":"a1b2c3d4e5f60718293a4b5c6d7e8f90","covered":true,"family_label":"Command injection"},` +
	`{"rule_id":"200004","family":"body","exemptable":false,"path":"/upload\u001b[2J","field":"","blocks":2,"ips":1,"first_seen":"2026-10-29T07:00:00.000Z","last_seen":"not a time","last_ref":"","covered":false,"family_label":"Request body"}]}`

func wafInsightsArgs(extra map[string]string, positionals ...string) parsedArgs {
	opts := map[string]string{"account": wafTestAccount}
	for key, value := range extra {
		opts[key] = value
	}
	return parsedArgs{Positionals: append([]string{"insights"}, positionals...), Options: opts, Bools: map[string]bool{}, Multi: map[string][]string{}}
}

func TestWafInsightsPrintsTheCard(t *testing.T) {
	api := newWafExclusionsAPI(t, "en")
	api.insights = wafInsightsBody

	stdout, stderr, err := captureOutput(t, func() error { return cmdWaf(wafInsightsArgs(nil)) })
	if err != nil {
		t.Fatalf("waf insights: %v", err)
	}
	if got := api.calls(http.MethodGet); len(got) != 1 || got[0].Path != "/api/accounts/abc123/waf/insights" || got[0].Lang != "en" {
		t.Fatalf("asked %+v", got)
	}

	rows := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(rows) != 3 {
		t.Fatalf("expected three rows on stdout (the header goes to stderr), got:\n%s", stdout)
	}
	last, _ := time.Parse(time.RFC3339, "2026-10-29T11:00:00.000Z")
	for i, cells := range [][]string{
		{"942100", "SQL injection", "3", "2", last.Local().Format("2006-01-02 15:04"), "c1b2c3d4e5f6", "-", "ARGS:s", "/"},
		{"932120", "Command injection", "2", "2", "a1b2c3d4e5f6", "exception exists", "ARGS:td_atts", "/wp-admin/admin-ajax.php"},
		{"200004", "Request body", "2", "1", "not a time", "cannot be exempted", "not one field", `/upload\u001b[2J`},
	} {
		at := 0
		for _, cell := range cells {
			next := strings.Index(rows[i][at:], cell)
			if next < 0 {
				t.Errorf("row %d lacks %q after column %d: %q", i+1, cell, at, rows[i])
				break
			}
			at += next + len(cell)
		}
	}
	if strings.Contains(stdout, "\x1b") {
		t.Errorf("a raw escape from a blocked path reached the terminal: %q", stdout)
	}
	if !strings.HasSuffix(rows[2], `/upload\u001b[2J`) || !strings.Contains(rows[2], " - ") {
		t.Errorf("row 3: no Reference ID is shown as -: %q", rows[2])
	}
	for _, line := range []string{
		"Repeated blocks of the last 7 days, grouped by rule, path and the field the rule matched; most blocks first.",
		"Based on the 7 blocks of the last 7 days.",
		"RULE    TYPE",
		"Many different IP addresses in one field on one path of your own site",
		"`cdnctl waf show <ref>`",
		"`cdnctl waf exempt <ref> --dry-run`",
	} {
		if !strings.Contains(stderr, line) {
			t.Errorf("stderr lacks %q:\n%s", line, stderr)
		}
	}
}

func TestWafInsightsSaysWhenTheFiguresAreCappedOrEmpty(t *testing.T) {
	api := newWafExclusionsAPI(t, "en")
	api.insights = strings.Replace(strings.Replace(wafInsightsBody, `"total":7,"capped":false`, `"total":5321,"capped":true`, 1), `"sampled":7`, `"sampled":2000`, 1)
	_, stderr, err := captureOutput(t, func() error { return cmdWaf(wafInsightsArgs(nil)) })
	if err != nil || !strings.Contains(stderr, "Based on the newest 2000 blocks (5321 in the last 7 days).") {
		t.Fatalf("capped: %v\n%s", err, stderr)
	}

	// Blocks, but none of them repeated: a block on its own is not a pattern.
	api.insights = `{"status":"success","days":7,"sampled":3,"total":3,"capped":false,"groups":[]}`
	stdout, stderr, err := captureOutput(t, func() error { return cmdWaf(wafInsightsArgs(nil)) })
	if err != nil || strings.TrimSpace(stdout) != "" {
		t.Fatalf("empty: %v %q", err, stdout)
	}
	if !strings.Contains(stderr, "No repeated blocks in the last 7 days.") || !strings.Contains(stderr, "Based on the 3 blocks of the last 7 days.") {
		t.Errorf("empty card:\n%s", stderr)
	}
}

func TestWafInsightsReportsTheAPIsRefusal(t *testing.T) {
	api := newWafExclusionsAPI(t, "en")
	api.insights, api.insightsCode = `{"status":"error","error_code":"search_failed","message":"Repeated blocks could not be loaded. Please try again in a moment."}`, http.StatusServiceUnavailable
	if exit, ok := isExitError(cmdWaf(wafInsightsArgs(nil))); !ok || exit.code != 1 || exit.message != "Repeated blocks could not be loaded. Please try again in a moment." {
		t.Fatalf("503: %+v", exit)
	}
	out, err := captureStdout(func() error { return cmdWaf(wafInsightsArgs(map[string]string{"format": "json"})) })
	if exit, ok := isExitError(err); !ok || exit.code != 1 || !strings.Contains(out, `"error_code": "search_failed"`) {
		t.Fatalf("json 503: %v / %q", err, out)
	}

	api.insights, api.insightsCode = `{"status":"error","error_code":"account_not_found","message":"Account not found."}`, http.StatusNotFound
	if exit, ok := isExitError(cmdWaf(wafInsightsArgs(nil))); !ok || exit.code != 1 || exit.message != "Account not found." {
		t.Fatalf("404: %+v", exit)
	}

	api.insights, api.insightsCode = wafInsightsBody, http.StatusOK
	out, err = captureStdout(func() error { return cmdWaf(wafInsightsArgs(map[string]string{"format": "json"})) })
	if err != nil || !strings.Contains(out, `"last_ref": "c1b2c3d4e5f60718293a4b5c6d7e8f90"`) {
		t.Fatalf("json: %v / %q", err, out)
	}
}

func TestWafInsightsRejectsMalformedCallsOffline(t *testing.T) {
	api := newWafExclusionsAPI(t, "en")
	for name, args := range map[string]parsedArgs{
		"format yaml":     wafInsightsArgs(map[string]string{"format": "yaml"}),
		"a stray operand": wafInsightsArgs(nil, "list"),
	} {
		if exit, ok := isExitError(cmdWaf(args)); !ok || exit.code != 2 || exit.message == "" {
			t.Errorf("%s: expected exit 2 with a message, got %+v", name, exit)
		}
	}
	if len(api.requests) != 0 {
		t.Fatalf("%d request(s) for calls that were never valid", len(api.requests))
	}
}

func TestWafInsightsSpeaksTheReadersLanguage(t *testing.T) {
	api := newWafExclusionsAPI(t, "tr")
	api.insights = wafInsightsBody

	stdout, stderr, err := captureOutput(t, func() error { return cmdWaf(wafInsightsArgs(nil)) })
	if err != nil {
		t.Fatalf("insights: %v", err)
	}
	if !strings.Contains(stdout, "istisna var") || !strings.Contains(stdout, "muaf tutulamaz") || !strings.Contains(stdout, "tek bir alan değil") {
		t.Errorf("rows not in Turkish:\n%s", stdout)
	}
	if !strings.Contains(stderr, "Son 7 günün tekrarlayan engelleri") {
		t.Errorf("notes not in Turkish:\n%s", stderr)
	}
	if got := api.calls(http.MethodGet)[0].Lang; got != "tr" {
		t.Errorf("Accept-Language = %q, want tr", got)
	}
}

// The banner is the contract the help center's commands are checked against.
func TestUsageDocumentsInsightsDryRunAndTheEmptyField(t *testing.T) {
	text := usageText(t)
	for _, want := range []string{
		"cdnctl waf insights [--account <uuid>] [--format table|json]",
		"[--field <field>] [--dry-run] [--format table|json]",
		`--field "" every field (--field= in Windows`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("usage lacks %q", want)
		}
	}
}

// `waf exclusions rm` has no dry run: --dry-run there is refused before any request, never
// ignored into a real removal.
func TestWafExclusionsRmRefusesDryRun(t *testing.T) {
	api := newWafExclusionsAPI(t, "en")
	api.remove = `{"status":"success","deployed":true,"exclusion":{"id":12,"rule_id":"942100","path":"/search","match":"exact","target":""}}`

	for _, argv := range [][]string{
		{"waf", "exclusions", "rm", "12", "--yes", "--dry-run", "--account", wafTestAccount},
		{"waf", "exclusions", "rm", "--dry-run", "12", "--yes", "--account", wafTestAccount},
		{"waf", "exclusions", "rm", "12", "--yes", "--dry-run=yes", "--account", wafTestAccount},
	} {
		if exit, ok := isExitError(run(argv)); !ok || exit.code != 2 {
			t.Errorf("%v: expected exit 2, got %+v", argv, exit)
		}
	}
	if len(api.requests) != 0 {
		t.Fatalf("%d request(s): a dry run removed for real", len(api.requests))
	}
}

// An exception that switches the rule off for the whole site (path "/", prefix, no field) is
// added only with --yes, as the panel adds it only after its confirmation tick: without it,
// exit 2 naming --yes and no exception sent, in the reader's language. Spellings the API keeps
// as "/" count too. --dry-run needs no --yes; a narrower exception needs none either.
func TestWafExemptForTheWholeSiteNeedsYes(t *testing.T) {
	site := map[string]string{"path": "/", "field": ""}
	for _, tc := range []struct {
		lang    string
		options map[string]string
		says    string
	}{
		{"en", site, "Add --yes to confirm"},
		{"tr", site, "Onaylamak için --yes ekleyin"},
		{"en", map[string]string{"path": "", "field": ""}, "--yes"},
		{"en", map[string]string{"path": "https://www.example.com/?x=1", "field": " "}, "--yes"},
		{"en", map[string]string{"path": "/#top", "field": ""}, "--yes"},
	} {
		api := newWafExclusionsAPI(t, tc.lang)
		api.event = wafEventWithRules(wafRule("942100", true, "ARGS:q"))
		api.add = wafAddedBody
		exit, ok := isExitError(cmdWaf(wafExemptArgs(wafTestRef, tc.options, "prefix")))
		if !ok || exit.code != 2 || !strings.Contains(exit.message, tc.says) || !strings.Contains(exit.message, "942100") {
			t.Errorf("%s %v: expected exit 2 naming --yes, got %+v", tc.lang, tc.options, exit)
		}
		if n := len(api.calls(http.MethodPost)); n != 0 {
			t.Errorf("%s %v: %d POST without --yes", tc.lang, tc.options, n)
		}
	}

	api := newWafExclusionsAPI(t, "en")
	api.event = wafEventWithRules(wafRule("942100", true, "ARGS:q"))
	api.add = wafAddedBody
	api.preview = wafPreviewBody(nil)
	if _, err := captureStdout(func() error { return cmdWaf(wafExemptArgs(wafTestRef, site, "prefix", "dry_run")) }); err != nil {
		t.Fatalf("--dry-run without --yes: %v", err)
	}
	if posts := api.calls(http.MethodPost); len(posts) != 1 || !strings.HasSuffix(posts[0].Path, "/waf/exclusions/preview") {
		t.Fatalf("--dry-run: expected the preview only, got %+v", posts)
	}
	if _, err := captureStdout(func() error { return cmdWaf(wafExemptArgs(wafTestRef, site, "prefix", "yes")) }); err != nil {
		t.Fatalf("with --yes: %v", err)
	}
	body := api.calls(http.MethodPost)[1].Body
	if body["path"] != "/" || body["match"] != "prefix" || body["target"] != "" {
		t.Fatalf("with --yes: %v", body)
	}
	// Narrower: "/" exact, "/" with a field, a path under the site: no --yes.
	for _, narrower := range []struct {
		options map[string]string
		bools   []string
	}{
		{map[string]string{"path": "/", "field": ""}, nil},
		{map[string]string{"path": "/"}, []string{"prefix"}},
		{map[string]string{"path": "/blog", "field": ""}, []string{"prefix"}},
	} {
		before := len(api.calls(http.MethodPost))
		if _, err := captureStdout(func() error { return cmdWaf(wafExemptArgs(wafTestRef, narrower.options, narrower.bools...)) }); err != nil {
			t.Errorf("%v %v: %v", narrower.options, narrower.bools, err)
		}
		if len(api.calls(http.MethodPost)) != before+1 {
			t.Errorf("%v %v: not added", narrower.options, narrower.bools)
		}
	}
	// --yes=<anything> is the usage, as --dry-run=<anything> is.
	args := wafExemptArgs(wafTestRef, site, "prefix")
	args.Options["yes"] = "maybe"
	if exit, ok := isExitError(cmdWaf(args)); !ok || exit.code != 2 || !strings.Contains(exit.message, "[--yes]") {
		t.Errorf("--yes=maybe: %+v", exit)
	}
}

// The two waf commands that write refuse a word they would otherwise pass over, before any
// request: a dry run typed another way (one dash, a word processor's dash, a missing hyphen)
// must never add or remove an exception for real.
func TestWafWritesRefuseAWordTheyWouldPassOver(t *testing.T) {
	api := newWafExclusionsAPI(t, "en")
	api.event = wafEventWithRules(wafRule("932120", true, "ARGS:content"))
	api.preview = wafPreviewBody(nil)
	api.add = wafAddedBody
	api.remove = `{"status":"success","deployed":true,"exclusion":{"id":12,"rule_id":"942100","path":"/search","match":"exact","target":""}}`

	exempt := []string{"waf", "exempt", wafTestRef, "--account", wafTestAccount}
	rm := []string{"waf", "exclusions", "rm", "12", "--yes", "--account", wafTestAccount}
	for _, tc := range []struct {
		argv []string
		word string
	}{
		{append(append([]string{}, exempt...), "-dry-run"), `"-dry-run"`},
		{append(append([]string{}, exempt...), "—dry-run"), `"—dry-run"`},
		{append(append([]string{}, exempt...), "--dryrun"), `"--dryrun"`},
		{append(append([]string{}, exempt...), "--dry"), `"--dry"`},
		{append(append([]string{}, exempt...), "--confirm"), `"--confirm"`},
		{append(append([]string{}, exempt...), "932120"), `"932120"`},
		{append(append([]string{}, rm...), "-dry-run"), `"-dry-run"`},
		{append(append([]string{}, rm...), "--dryrun"), `"--dryrun"`},
		{append(append([]string{}, rm...), "--prefix"), `"--prefix"`},
	} {
		exit, ok := isExitError(run(tc.argv))
		if !ok || exit.code != 2 || !strings.Contains(exit.message, "Unexpected argument "+tc.word) || !strings.Contains(exit.message, "usage: cdnctl waf ") {
			t.Errorf("%q: expected exit 2 naming %s with the usage, got %+v", tc.argv, tc.word, exit)
		}
	}
	if len(api.requests) != 0 {
		t.Fatalf("%d request(s) for a call with a word it does not read: %+v", len(api.requests), api.requests)
	}

	// What each reads still goes through, --lang included (it applies to every command).
	if _, err := captureStdout(func() error {
		return run(append(append([]string{}, exempt...), "--dry-run", "--lang", "en", "--format", "json"))
	}); err != nil {
		t.Fatalf("exempt --dry-run --lang --format: %v", err)
	}
	if _, err := captureStdout(func() error { return run(append(append([]string{}, rm...), "--format", "table")) }); err != nil {
		t.Fatalf("rm --format: %v", err)
	}
	posts, deletes := api.calls(http.MethodPost), api.calls(http.MethodDelete)
	if len(posts) != 1 || !strings.HasSuffix(posts[0].Path, "/waf/exclusions/preview") || len(deletes) != 1 {
		t.Fatalf("expected the preview and one removal: POST %+v DELETE %+v", posts, deletes)
	}
}
