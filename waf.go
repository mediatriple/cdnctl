package main

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// cmdWaf is the WAF from a terminal: what it matched (logs), one block in detail (show),
// what keeps being blocked (insights), and the account's exceptions (exempt, exclusions).
//
// Triaging a block is the work least likely to happen in a browser: it starts from an
// alert or a customer message, often out of hours. The panel screen was the only way to
// see what the firewall had done, so the help center described the work with no terminal
// equivalent to offer. The fix for a false positive, an exception for that rule on that
// path, was panel-only too, which left the triage one browser trip short of done.
func cmdWaf(args parsedArgs) error {
	if len(args.Positionals) > 0 {
		switch args.Positionals[0] {
		case "logs":
			return cmdWafLogs(args)
		case "show":
			return cmdWafShow(args)
		case "insights":
			return cmdWafInsights(args)
		case "exempt":
			return cmdWafExempt(args)
		case "exclusions":
			return cmdWafExclusions(args)
		}
	}
	usage(os.Stderr)
	return errExit(2)
}

// wafSwitches are the waf flags that never take a value (parseArgsWithSwitches).
var wafSwitches = map[string]bool{"prefix": true, "yes": true, "dry_run": true}

// wafUnexpected is the first word of a call that a waf command which writes would otherwise
// pass over: a word after its arguments, or an option it does not read. Such a word is most
// often a switch typed another way: -dry-run with one dash (a word to the parser, not an
// option), —dry-run with the dash a word processor puts in, --dryrun. Passed over, it would
// add or remove an exception for real where a dry run was meant, so the command stops before
// any request instead. "" when the call has none. --lang is read for every command (run).
func wafUnexpected(args parsedArgs, positionals int, options ...string) string {
	if len(args.Positionals) > positionals {
		return args.Positionals[positionals]
	}
	var unknown []string
	for key := range args.Options {
		if key != "lang" && !containsString(options, key) {
			unknown = append(unknown, "--"+strings.ReplaceAll(key, "_", "-"))
		}
	}
	if len(unknown) == 0 {
		return ""
	}
	sort.Strings(unknown)
	return unknown[0]
}

// wafUnexpectedError is the refusal for what wafUnexpected found, with the command's usage.
func wafUnexpectedError(word, usage string) error {
	return errExitMessage(2, fmt.Sprintf(T("Unexpected argument %q: nothing was changed."), word)+"\n"+usage)
}

// cmdWafLogs summarises what the WAF matched in a time window.
func cmdWafLogs(args parsedArgs) error {
	account, err := resolveAccountE(args)
	if err != nil {
		return err
	}

	rangeValue := option(args, "range", "1h")
	switch rangeValue {
	case "1h", "1d", "7d", "30d":
	default:
		return errExitMessage(2, "usage: cdnctl waf logs [--range 1h|1d|7d|30d]")
	}

	resp, err := requestJSON(http.MethodGet, "accounts/"+account+"/waf/logs?range="+rangeValue, nil)
	if err != nil {
		return err
	}

	if option(args, "format", "table") == "json" {
		return printJSON(resp)
	}

	if message := strval(resp["message"]); message != "" && resp["aggregations"] == nil {
		fmt.Fprintln(os.Stderr, message)
		return errExit(1)
	}

	fmt.Fprintf(os.Stderr, "Range: %s   matched requests: %s\n\n", rangeValue, strval(resp["detail_total"]))

	aggregations, _ := resp["aggregations"].(map[string]any)
	// Reported in the order a person actually triages: what was hit, from where, by whom.
	for _, section := range []struct{ key, title string }{
		{"attack_types", "RULE"},
		{"countries", "COUNTRY"},
		{"client_ips", "CLIENT IP"},
		{"response_codes", "STATUS"},
	} {
		bucket, _ := aggregations[section.key].(map[string]any)
		items, _ := bucket["buckets"].([]any)
		if len(items) == 0 {
			continue
		}
		fmt.Fprintf(os.Stderr, "%-40s  %s\n", section.title, "COUNT")
		for _, raw := range items {
			item, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			fmt.Printf("%-40s  %s\n", strval(item["key"]), strval(item["doc_count"]))
		}
		fmt.Println()
	}

	return nil
}

// wafRefPattern is what `waf show` accepts: the Reference ID printed on the edge's
// block page is nginx's $request_id, which is also the ModSecurity transaction id —
// 32 lowercase hex characters. The panel's table shows the first 12, so a prefix of at
// least that length is accepted too; anything shorter would match unrelated requests.
var wafRefPattern = regexp.MustCompile(`^[0-9a-f]{12,32}$`)

// wafShowUsage is the usage line `waf show` prints for a malformed call.
const wafShowUsage = "usage: cdnctl waf show <ref> [--account <uuid>] [--format table|json]"

// matchedDataLimit caps how much of a rule's matched data is printed. The match can be
// a slice of an uploaded file; a terminal full of it hides the rules around it.
const matchedDataLimit = 200

// normalizeWafRef accepts the reference the way people paste it — surrounding spaces,
// upper case from a screenshot — and reports whether it is a usable id or prefix.
func normalizeWafRef(raw string) (string, bool) {
	ref := strings.ToLower(strings.TrimSpace(raw))
	return ref, wafRefPattern.MatchString(ref)
}

// cmdWafShow looks up one blocked request by the Reference ID its block page showed.
//
// It starts where support actually starts: a visitor (or the customer) sends a
// screenshot of the block page. `waf logs` answers "what has the WAF been doing";
// this answers "why was THIS request refused", including the requests too old to be
// among the newest rows a summary or the panel table loads.
func cmdWafShow(args parsedArgs) error {
	if len(args.Positionals) < 2 {
		return errExitMessage(2, wafShowUsage)
	}
	ref, ok := normalizeWafRef(args.Positionals[1])
	if !ok {
		// Checked here, before the network: a typo should cost nothing and say exactly
		// what shape is expected, not come back as an API validation error.
		return errExitMessage(2, T("The Reference ID must be 12 to 32 hexadecimal characters: the full ID from the block page, or at least the first 12 characters the panel shows."))
	}
	format := option(args, "format", "table")
	if format != "table" && format != "json" {
		return errExitMessage(2, wafShowUsage)
	}

	account, err := resolveAccountE(args)
	if err != nil {
		return err
	}

	resp, event, problem, err := wafEventLookup(account, ref)
	if err != nil {
		return err
	}
	if format == "json" {
		if err := printJSON(resp); err != nil {
			return err
		}
		if problem != "" {
			return errExit(1)
		}
		return nil
	}
	if problem != "" {
		return errExitMessage(1, problem)
	}

	renderWafEvent(os.Stdout, event)
	return nil
}

// wafEventLookup asks the API for the newest block with Reference ID ref on the account's
// sites: the answer as it came, and the event. problem is what to tell a person when there
// is no event to work with.
func wafEventLookup(account, ref string) (resp map[string]any, event map[string]any, problem string, err error) {
	// The verdict and the rule explanations are written by the API in the reader's
	// language; the rule messages themselves stay as ModSecurity logged them.
	resp, err = requestJSONWithHeaders(http.MethodGet, "accounts/"+account+"/waf/events/"+ref, nil,
		map[string]string{"Accept-Language": resolveLang()})
	if err != nil {
		return nil, nil, "", err
	}

	// An error status first: the 404 (no such account) and 503 (the search itself failed)
	// bodies carry "found": false too, and reading those as "no such block" sends the
	// reader looking for a cause that is not there.
	status := httpStatusOf(resp)
	found, answered := resp["found"].(bool)
	if status >= 400 || !answered {
		fallback := T("unexpected response from the API")
		if status >= 400 {
			fallback = fmt.Sprintf("HTTP %d", status)
		}
		return resp, nil, terminalText(firstString(resp, "message", "error", fallback), ""), nil
	}
	event, _ = resp["event"].(map[string]any)
	if !found || event == nil {
		return resp, nil, fmt.Sprintf(T("No WAF event with Reference ID %s in the last 30 days on this account's sites. If the block page came from a site on another account, pass --account <uuid>."), ref), nil
	}
	return resp, event, "", nil
}

// wafExemptUsage is the usage line `waf exempt` prints for a malformed call.
const wafExemptUsage = "usage: cdnctl waf exempt <ref> [--account <uuid>] [--rule <id>] [--path <path>] [--prefix] [--field <field>] [--dry-run] [--yes] [--format table|json]"

// wafExclusionsUsage is what `waf exclusions` prints for a malformed call.
const wafExclusionsUsage = "usage: cdnctl waf exclusions list [--account <uuid>] [--format table|json]\n" +
	"       cdnctl waf exclusions rm <id> [--account <uuid>] [--format table|json] --yes"

// wafExclusionIDPattern is an exception's id, as `waf exclusions list` prints it.
var wafExclusionIDPattern = regexp.MustCompile(`^[0-9]{1,18}$`)

// wafExemption is the exception `waf exempt` asks the API to add.
type wafExemption struct {
	Rule, Path, Match, Target string
}

// cmdWafExempt adds the WAF exception the panel's "Exempt" button prepares for a blocked
// request: the rule it matched, on that request's path only, for the one field it matched.
// The flags change it the way a person edits that form before pressing "Add exception".
// With --dry-run nothing is added: the API's preview says what the exception would cover,
// as the form does below its button. An exception that switches the rule off for the whole
// site (path "/", --prefix, no field) is added only with --yes, as the panel adds it only
// after its confirmation is ticked.
//
// It ends the triage `waf show` starts, from the same terminal. The API adds it through
// the service behind the panel's button, so the two agree on what may be exempted; which
// of the request's rules can be is the API's answer too (each rule's "exemptable").
func cmdWafExempt(args parsedArgs) error {
	if len(args.Positionals) < 2 {
		return errExitMessage(2, wafExemptUsage)
	}
	// It deploys: `waf exempt <ref> -dry-run` must not add the exception for real.
	if word := wafUnexpected(args, 2, "account", "rule", "path", "prefix", "field", "dry_run", "yes", "format"); word != "" {
		return wafUnexpectedError(word, wafExemptUsage)
	}
	ref, ok := normalizeWafRef(args.Positionals[1])
	if !ok {
		return errExitMessage(2, T("The Reference ID must be 12 to 32 hexadecimal characters: the full ID from the block page, or at least the first 12 characters the panel shows."))
	}
	format := option(args, "format", "table")
	if format != "table" && format != "json" {
		return errExitMessage(2, wafExemptUsage)
	}
	// Given bare, these read "true": no rule, path or field is called that.
	if option(args, "rule", "") == "true" || option(args, "path", "") == "true" {
		return errExitMessage(2, wafExemptUsage)
	}
	if option(args, "field", "") == "true" {
		// Also what Windows PowerShell 5.1 makes of --field "": it drops the empty argument.
		return errExitMessage(2, T("--field needs a value: one request field such as ARGS:content, or \"\" for every field. Windows PowerShell 5.1 drops an empty argument: there, write --field= instead."))
	}
	// --dry-run=<anything> is refused rather than read as "not a dry run": whoever typed
	// it asked for one, and must never get a real exception instead.
	if _, set := args.Options["dry_run"]; set && !args.Bools["dry_run"] {
		return errExitMessage(2, wafExemptUsage)
	}
	if _, set := args.Options["yes"]; set && !args.Bools["yes"] {
		return errExitMessage(2, wafExemptUsage)
	}
	dryRun := args.Bools["dry_run"]

	account, err := resolveAccountE(args)
	if err != nil {
		return err
	}
	lookup, event, problem, err := wafEventLookup(account, ref)
	if err != nil {
		return err
	}
	if problem != "" {
		if format == "json" {
			if err := printJSON(lookup); err != nil {
				return err
			}
			return errExit(1)
		}
		return errExitMessage(1, problem)
	}

	exemption, err := chooseWafExemption(event, ref, args)
	if err != nil {
		return err
	}
	if dryRun {
		return previewWafExemption(account, exemption, format)
	}
	if wafWholeSite(exemption) && !args.Bools["yes"] {
		return errExitMessage(2, fmt.Sprintf(T("This exception would switch rule %s off for the whole site: every path and every field. Add --yes to confirm, as the panel asks you to tick its confirmation; --dry-run shows what it would cover."), exemption.Rule))
	}
	// What the panel's button writes besides: the block it was made from, and a note
	// naming it (its first 12 characters, as the panel's table shows them) so the list
	// says where an exception came from.
	source, ok := normalizeWafRef(strval(event["ref"]))
	if !ok {
		source = ref
	}
	resp, err := requestJSONWithHeaders(http.MethodPost, "accounts/"+account+"/waf/exclusions", map[string]any{
		"rule":   exemption.Rule,
		"path":   exemption.Path,
		"match":  exemption.Match,
		"target": exemption.Target,
		"ref":    source,
		"note":   "Reference ID " + source[:12],
	}, map[string]string{"Accept-Language": resolveLang()})
	if err != nil {
		return err
	}

	failed := httpStatusOf(resp) >= 400 || strval(resp["status"]) != "success"
	if format == "json" {
		if err := printJSON(resp); err != nil {
			return err
		}
		if failed {
			return errExit(1)
		}
		return nil
	}
	if failed {
		return wafAPIError(resp)
	}
	exclusion, _ := resp["exclusion"].(map[string]any)
	id := wafNumber(exclusion["id"])
	if deployed, _ := resp["deployed"].(bool); deployed {
		fmt.Printf(T("Added WAF exception %s. The edges apply it within 1-2 minutes.")+"\n", id)
	} else {
		fmt.Printf(T("This exception already exists (id %s); nothing changed.")+"\n", id)
	}
	renderWafExclusion(os.Stdout, exclusion)
	fmt.Printf(T("To remove it: `cdnctl waf exclusions rm %s --yes`")+"\n", id)
	return nil
}

// chooseWafExemption works out from a WAF event what the panel's "Exempt" button would
// pre-fill, changed by the flags as a person edits that form: the rule (the one the request
// matched that can be exempted, or --rule), the field that rule matched (or --field, ""
// for every field), the request's path without its query (or --path), only that exact
// path (or --prefix: everything under it too). The error is an exit for the reader: 2 when
// a flag settles it, 1 when this request has nothing to exempt.
func chooseWafExemption(event map[string]any, ref string, args parsedArgs) (wafExemption, error) {
	var ids []string
	fields := map[string][]string{}
	rules, _ := event["rules"].([]any)
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if exemptable, _ := rule["exemptable"].(bool); !exemptable {
			continue
		}
		id := strings.TrimSpace(wafNumber(rule["id"]))
		if id == "" {
			continue
		}
		if _, seen := fields[id]; !seen {
			ids = append(ids, id)
			fields[id] = []string{}
		}
		// A rule that matched in several places is listed once per match, each with its field.
		if target := strings.TrimSpace(strval(rule["target"])); !containsString(fields[id], target) {
			fields[id] = append(fields[id], target)
		}
	}

	rule := strings.TrimSpace(option(args, "rule", ""))
	switch {
	case len(ids) == 0:
		return wafExemption{}, errExitMessage(1, fmt.Sprintf(T("None of the rules this request matched can be exempted. `cdnctl waf show %s` lists them, each with what it checks."), ref))
	case rule != "":
		if _, ok := fields[rule]; !ok {
			return wafExemption{}, errExitMessage(2, fmt.Sprintf(T("Rule %s cannot be exempted for this request. The rules it matched that can be: %s."), terminalSafe(rule), strings.Join(ids, ", ")))
		}
	case len(ids) > 1:
		return wafExemption{}, errExitMessage(2, fmt.Sprintf(T("This request matched more than one rule that can be exempted: %s. Choose one with --rule <id>."), strings.Join(ids, ", ")))
	default:
		rule = ids[0]
	}

	target := ""
	if value, set := args.Options["field"]; set {
		target = strings.TrimSpace(value)
	} else if matched := fields[rule]; len(matched) == 1 {
		target = matched[0]
	} else {
		quoted := make([]string, len(matched))
		for i, field := range matched {
			quoted[i] = strconv.Quote(field)
		}
		return wafExemption{}, errExitMessage(2, fmt.Sprintf(T("Rule %s matched more than one field of this request: %s. Choose one with --field <field>, or --field \"\" for every field (--field= in Windows PowerShell 5.1)."), rule, strings.Join(quoted, ", ")))
	}

	path, decoded := wafRequestFilename(strval(event["uri"]))
	if value, set := args.Options["path"]; set {
		path = strings.TrimSpace(value)
	} else if !decoded {
		return wafExemption{}, errExitMessage(2, fmt.Sprintf(T("This request's path (%s) cannot be turned into a path an exception can hold (for example a space, a quote, ;, an emoji, a control character, an encoded ? or #, invalid UTF-8 or a %% at the end). An exception only matches the decoded path, so one for this path would never apply. Give the folder before the segment that holds it with --path <folder> --prefix."), terminalSafe(path)))
	}
	match := "exact"
	if args.Bools["prefix"] {
		match = "prefix"
	}
	return wafExemption{Rule: rule, Path: path, Match: match, Target: target}, nil
}

// wafWholeSite reports whether the API would store e as the whole site: the path it keeps
// (WafExclusionRules::clean(): a pasted URL's path, nothing after "?" or "#", "" as "/") is "/",
// the match is not exact and there is no field. The generator writes that without a path test.
func wafWholeSite(e wafExemption) bool {
	path := strings.TrimSpace(e.Path)
	if m := wafPastedURL.FindStringSubmatch(path); m != nil {
		path = m[1]
	}
	path = strings.SplitN(strings.SplitN(path, "?", 2)[0], "#", 2)[0]
	return (path == "" || path == "/") && e.Match != "exact" && strings.TrimSpace(e.Target) == ""
}

// wafPastedURL is a full URL given as a path; the API keeps its path alone.
var wafPastedURL = regexp.MustCompile(`(?i)^https?://[^/]+(/.*)?$`)

// wafRequestFilename is what an exception's path is compared with on the edge, REQUEST_FILENAME,
// from a request URI as the WAF log holds it: the part before the first "?", every %XX decoded
// once ("%3F" stays a "?" in it; a "%" without two hex digits stays as it is). It is the path the
// panel's "Exempt" pre-fills, and the API stores it as sent. decoded is false when the result is
// not a path the panel stores (wafPathHeld): no exception can hold it, and path is then the URI's
// path as sent. "/" when nothing is left. Measured on libmodsecurity 3.0.15 (slayer2
// 1.31.6-xrg1); TestWafRequestFilenameIsWhatTheEdgeCompares has the cases of the panel's
// tests/fixtures/waf-request-filename.json.
func wafRequestFilename(uri string) (path string, decoded bool) {
	raw := strings.SplitN(strings.SplitN(uri, "?", 2)[0], "#", 2)[0]
	if raw == "" {
		raw = "/"
	}
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] == '%' && i+2 < len(raw) && wafHexDigit(raw[i+1]) >= 0 && wafHexDigit(raw[i+2]) >= 0 {
			out = append(out, byte(wafHexDigit(raw[i+1])<<4|wafHexDigit(raw[i+2])))
			i += 2
			continue
		}
		out = append(out, raw[i])
	}
	text := string(out)
	if !wafPathHeld(text) {
		return raw, false
	}
	return text, true
}

// wafPathHeld reports whether the panel stores path as an exception's path (its
// WafExclusionRules::PATH_RE): "/" and at most 255 characters of the Basic Multilingual Plane,
// each a letter, combining mark or digit of any script, ZWNJ/ZWJ, or one of / . _ ~ % ! & ( ) * + , = : @ -,
// valid UTF-8, not ending in "%" (/100%25: on the edge it would take the rule's closing quote).
// So no space, quote, ";", emoji, control or bidi character, "?" or "#".
func wafPathHeld(path string) bool {
	if !utf8.ValidString(path) || !strings.HasPrefix(path, "/") || strings.HasSuffix(path, "%") || utf8.RuneCountInString(path) > 256 {
		return false
	}
	for _, r := range path[1:] {
		switch {
		case r > 0xFFFF:
			return false
		case unicode.IsLetter(r) || unicode.Is(unicode.M, r) || unicode.IsNumber(r) || r == 0x200C || r == 0x200D:
		case strings.ContainsRune("/._~%!&()*+,=:@-", r):
		default:
			return false
		}
	}
	return true
}

// wafHexDigit is the value of a hexadecimal digit, -1 for any other byte.
func wafHexDigit(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// previewWafExemption is `waf exempt --dry-run`: what the exception would cover, from the
// API's preview (POST .../waf/exclusions/preview, the answer the panel's form shows below
// "Add exception"), with the form's warnings. Nothing is added. Exit 0, or 1 when the API
// refuses a value (the rule, path or field) as the add would refuse it. The preview does not
// look at the account's limit of 50 or at an identical exception already there: the add
// reports those.
func previewWafExemption(account string, exemption wafExemption, format string) error {
	resp, err := requestJSONWithHeaders(http.MethodPost, "accounts/"+account+"/waf/exclusions/preview", map[string]any{
		"rule":   exemption.Rule,
		"path":   exemption.Path,
		"match":  exemption.Match,
		"target": exemption.Target,
	}, map[string]string{"Accept-Language": resolveLang()})
	if err != nil {
		return err
	}

	failed := httpStatusOf(resp) >= 400 || strval(resp["status"]) != "success"
	if format == "json" {
		if err := printJSON(resp); err != nil {
			return err
		}
		if failed {
			return errExit(1)
		}
		return nil
	}
	if failed {
		return wafAPIError(resp)
	}
	renderWafPreview(os.Stdout, resp)
	return nil
}

// renderWafPreview prints a scope preview: the exception as it would be added, the warnings
// the panel's form shows for the same answer, and how many past blocks it applies to.
func renderWafPreview(w io.Writer, preview map[string]any) {
	exclusion, _ := preview["exclusion"].(map[string]any)
	rule := terminalSafe(wafNumber(exclusion["rule_id"]))
	path := terminalSafe(strval(exclusion["path"]))
	family := strval(preview["family"])
	label := terminalSafe(strval(preview["family_label"]))
	if label == "" {
		label = terminalSafe(family)
	}

	fmt.Fprintln(w, T("Dry run: nothing was added."))
	// The rule line names the rule's type too, as the panel's form does in its warnings.
	shown := map[string]any{"rule_id": rule, "path": exclusion["path"], "match": exclusion["match"], "target": exclusion["target"]}
	if label != "" {
		shown["rule_id"] = rule + " (" + label + ")"
	}
	renderWafExclusion(w, shown)
	fmt.Fprintln(w)

	attack, _ := preview["attack"].(bool)
	allFields, _ := preview["all_fields"].(bool)
	wholeSite, _ := preview["whole_site"].(bool)
	if family == "leakage" {
		fmt.Fprintln(w, T("Response rule: it checks the page your origin returns, not the request. The exception switches it off for the whole path; no field can be set."))
	}
	switch {
	case wholeSite && allFields:
		fmt.Fprintf(w, T("This exception would apply to the whole site: rule %s would be off on every path.")+"\n", rule)
	case attack && allFields && strval(exclusion["match"]) == "prefix":
		fmt.Fprintf(w, T("No field set: rule %s (%s) would not check any field on %s or any path under it — query and form parameters, cookies, headers and the request body included. If the block names a field, pass it with --field to exempt only that field.")+"\n", rule, label, path)
	case attack && allFields:
		fmt.Fprintf(w, T("No field set: rule %s (%s) would not check any field on %s — query and form parameters, cookies, headers and the request body included. If the block names a field, pass it with --field to exempt only that field.")+"\n", rule, label, path)
	}

	counts, _ := preview["counts"].(map[string]any)
	d7, _ := counts["d7"].(map[string]any)
	d30, _ := counts["d30"].(map[string]any)
	blocks30, _ := wafInt(d30["blocks"])
	atLeast30, _ := d30["at_least"].(bool)
	switch {
	case counts == nil:
		fmt.Fprintln(w, T("The blocks could not be counted right now; you can still add the exception."))
	case blocks30 == 0 && !atLeast30:
		fmt.Fprintln(w, T("No block of the last 30 days matches this exception."))
	default:
		fmt.Fprintf(w, T("Past blocks it would apply to: %s in the last 7 days (from %s IP addresses), %s in the last 30 days (from %s).")+"\n",
			wafCount(d7["blocks"], d7["at_least"]), wafCount(d7["ips"], d7["at_least"]),
			wafCount(d30["blocks"], d30["at_least"]), wafCount(d30["ips"], d30["at_least"]))
		fmt.Fprintln(w, T("Other rules that matched in the same requests still apply."))
	}
	fmt.Fprintln(w, T("To add it, run the same command without --dry-run."))
}

// wafCount is one figure of a preview: the number, or "at least" it when the newest
// documents read did not reach back over the whole window.
func wafCount(n any, atLeast any) string {
	value, _ := wafInt(n)
	if lower, _ := atLeast.(bool); lower {
		return fmt.Sprintf(T("at least %d"), value)
	}
	return strconv.FormatInt(value, 10)
}

// wafInsightsUsage is the usage line `waf insights` prints for a malformed call.
const wafInsightsUsage = "usage: cdnctl waf insights [--account <uuid>] [--format table|json]"

// wafInsightsPathWidth is how much of a path the insights table prints; the JSON has it whole.
const wafInsightsPathWidth = 80

// cmdWafInsights prints the "Repeated blocks" card of the panel's WAF page: the last 7 days'
// blocks grouped by rule, path and the field the rule matched, most blocks first, each with
// how many blocks from how many IP addresses and whether an exception already covers it.
//
// It is where a false positive shows itself without a Reference ID to start from: many
// addresses blocked in one field on one path of the site, or a response rule stopping the
// page the origin returned. The REF column is the way into `waf show` and `waf exempt` for it.
func cmdWafInsights(args parsedArgs) error {
	format := option(args, "format", "table")
	if len(args.Positionals) > 1 || (format != "table" && format != "json") {
		return errExitMessage(2, wafInsightsUsage)
	}
	account, err := resolveAccountE(args)
	if err != nil {
		return err
	}
	// Rule types and refusals come back in the reader's language.
	resp, err := requestJSONWithHeaders(http.MethodGet, "accounts/"+account+"/waf/insights", nil,
		map[string]string{"Accept-Language": resolveLang()})
	if err != nil {
		return err
	}

	failed := httpStatusOf(resp) >= 400 || strval(resp["status"]) != "success"
	if format == "json" {
		if err := printJSON(resp); err != nil {
			return err
		}
		if failed {
			return errExit(1)
		}
		return nil
	}
	if failed {
		return wafAPIError(resp)
	}
	renderWafInsights(os.Stdout, os.Stderr, resp)
	return nil
}

// renderWafInsights prints the card: the rows to out, everything around them to notes (as in
// `waf logs`, piping the table hands on rows only). Paths and fields come from blocked
// requests, so each goes through terminalSafe.
func renderWafInsights(out, notes io.Writer, card map[string]any) {
	days, ok := wafInt(card["days"])
	if !ok || days <= 0 {
		days = 7
	}
	total, _ := wafInt(card["total"])
	sampled, _ := wafInt(card["sampled"])
	basis := ""
	if total > 0 {
		basis = fmt.Sprintf(T("Based on the %d blocks of the last %d days."), total, days)
		if capped, _ := card["capped"].(bool); capped {
			basis = fmt.Sprintf(T("Based on the newest %d blocks (%d in the last %d days)."), sampled, total, days)
		}
	}

	groups := arrayMap(card["groups"])
	if len(groups) == 0 {
		fmt.Fprintf(notes, T("No repeated blocks in the last %d days.")+"\n", days)
		if basis != "" {
			fmt.Fprintln(notes, basis)
		}
		return
	}

	rows := [][]string{{"RULE", "TYPE", "BLOCKS", "IPS", "LAST", "REF", "STATUS", "FIELD", "PATH"}}
	for _, group := range groups {
		kind := terminalSafe(strval(group["family_label"]))
		if kind == "" {
			kind = terminalSafe(strval(group["family"]))
		}
		ref, ok := normalizeWafRef(strval(group["last_ref"]))
		if !ok {
			ref = "-"
		} else if len(ref) > 12 {
			// The first 12 characters, as the panel's table shows them; waf show and
			// waf exempt take them as they are.
			ref = ref[:12]
		}
		status := "-"
		if covered, _ := group["covered"].(bool); covered {
			status = T("exception exists")
		} else if exemptable, _ := group["exemptable"].(bool); !exemptable {
			status = T("cannot be exempted")
		}
		field := terminalSafe(strval(group["field"]))
		if field == "" {
			field = T("not one field")
		}
		rows = append(rows, []string{
			terminalSafe(wafNumber(group["rule_id"])),
			kind,
			wafNumber(group["blocks"]),
			wafNumber(group["ips"]),
			wafLocalTime(strval(group["last_seen"])),
			ref,
			status,
			field,
			truncateRunes(terminalSafe(strval(group["path"])), wafInsightsPathWidth),
		})
	}

	lines := wafColumns(rows)
	fmt.Fprintf(notes, T("Repeated blocks of the last %d days, grouped by rule, path and the field the rule matched; most blocks first.")+"\n", days)
	if basis != "" {
		fmt.Fprintln(notes, basis)
	}
	fmt.Fprintln(notes)
	fmt.Fprintln(notes, lines[0])
	for _, line := range lines[1:] {
		fmt.Fprintln(out, line)
	}
	fmt.Fprintln(notes)
	fmt.Fprintln(notes, T("Many different IP addresses in one field on one path of your own site often means a legitimate feature of the site is being blocked; scanners usually try many different paths, or files the site does not have."))
	fmt.Fprintln(notes, T("REF is the newest block of a row: `cdnctl waf show <ref>` shows it, and `cdnctl waf exempt <ref> --dry-run` what an exception for it would cover."))
}

// wafLocalTime shows a time the API sends (RFC 3339, UTC) in this computer's time zone, as
// the panel shows it in the browser's.
func wafLocalTime(value string) string {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		if shown := terminalSafe(value); shown != "" {
			return shown
		}
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04")
}

// cmdWafExclusions lists the account's WAF exceptions or removes one: the table under
// "WAF exceptions" on the panel's WAF page.
func cmdWafExclusions(args parsedArgs) error {
	action := ""
	if len(args.Positionals) > 1 {
		action = args.Positionals[1]
	}
	format := option(args, "format", "table")
	if (action != "list" && action != "rm") || (format != "table" && format != "json") {
		return errExitMessage(2, wafExclusionsUsage)
	}
	id := ""
	if action == "rm" {
		// rm has no dry run: someone who typed --dry-run (as `waf exempt` takes it), or any
		// other word rm does not read, must not get a real removal instead.
		if word := wafUnexpected(args, 3, "account", "format", "yes"); word != "" {
			return wafUnexpectedError(word, wafExclusionsUsage)
		}
		if len(args.Positionals) < 3 || !wafExclusionIDPattern.MatchString(args.Positionals[2]) {
			return errExitMessage(2, wafExclusionsUsage)
		}
		id = args.Positionals[2]
		if err := requireYes(args, "remove a WAF exception"); err != nil {
			return err
		}
	}

	account, err := resolveAccountE(args)
	if err != nil {
		return err
	}
	method, path := http.MethodGet, "accounts/"+account+"/waf/exclusions"
	if action == "rm" {
		method, path = http.MethodDelete, path+"/"+id
	}
	// Explanations and refusals come back in the reader's language.
	resp, err := requestJSONWithHeaders(method, path, nil, map[string]string{"Accept-Language": resolveLang()})
	if err != nil {
		return err
	}

	failed := httpStatusOf(resp) >= 400 || strval(resp["status"]) != "success"
	if format == "json" {
		if err := printJSON(resp); err != nil {
			return err
		}
		if failed {
			return errExit(1)
		}
		return nil
	}
	if failed {
		return wafAPIError(resp)
	}

	if action == "rm" {
		exclusion, _ := resp["exclusion"].(map[string]any)
		fmt.Printf(T("Removed WAF exception %s. Its rule applies on that path again within 1-2 minutes.")+"\n", id)
		renderWafExclusion(os.Stdout, exclusion)
		return nil
	}

	items := arrayMap(resp["exclusions"])
	if len(items) == 0 {
		fmt.Fprintln(os.Stderr, T("No WAF exceptions on this account: every rule applies to the whole site."))
		return nil
	}
	rows := [][]string{{"ID", "RULE", "MATCH", "PATH", "FIELD", "NOTE"}}
	for _, item := range items {
		field := terminalSafe(strval(item["target"]))
		if field == "" {
			field = T("all fields")
		}
		rows = append(rows, []string{
			wafNumber(item["id"]),
			terminalSafe(wafNumber(item["rule_id"])),
			terminalSafe(strval(item["match"])),
			terminalSafe(strval(item["path"])),
			field,
			terminalSafe(strval(item["note"])),
		})
	}
	lines := wafColumns(rows)
	// The header goes to stderr, as in `waf logs`: piping the table hands on rows only.
	fmt.Fprintln(os.Stderr, lines[0])
	for _, line := range lines[1:] {
		fmt.Println(line)
	}
	if limit, ok := wafInt(resp["limit"]); ok {
		fmt.Fprintf(os.Stderr, "\n"+T("%d of %d exceptions in use on this account.")+"\n", len(items), limit)
	}
	return nil
}

// wafColumns lays rows out in columns two spaces apart, each as wide as its widest cell.
func wafColumns(rows [][]string) []string {
	var widths []int
	for _, row := range rows {
		for i, cell := range row {
			if i >= len(widths) {
				widths = append(widths, 0)
			}
			if n := utf8.RuneCountInString(cell); n > widths[i] {
				widths[i] = n
			}
		}
	}
	lines := make([]string, len(rows))
	for r, row := range rows {
		var b strings.Builder
		for i, cell := range row {
			if i > 0 {
				b.WriteString("  ")
			}
			b.WriteString(cell)
			if i < len(row)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-utf8.RuneCountInString(cell)))
			}
		}
		lines[r] = strings.TrimRight(b.String(), " ")
	}
	return lines
}

// renderWafExclusion prints one exception as labelled lines, as the panel's table shows it.
// The path, the field and the note can carry what a blocked request sent, so each goes
// through terminalSafe.
func renderWafExclusion(w io.Writer, exclusion map[string]any) {
	scope := T("only this exact path")
	if strval(exclusion["match"]) == "prefix" {
		scope = T("this path and everything under it")
	}
	field := terminalSafe(strval(exclusion["target"]))
	if field == "" {
		field = T("all fields")
	}
	rows := []struct{ label, value string }{
		{T("Rule"), terminalSafe(wafNumber(exclusion["rule_id"]))},
		{T("Path"), terminalSafe(strval(exclusion["path"])) + "  (" + scope + ")"},
		{T("Field"), field},
	}
	if note := terminalSafe(strval(exclusion["note"])); note != "" {
		rows = append(rows, struct{ label, value string }{T("Note"), note})
	}
	width := 0
	for _, row := range rows {
		if n := utf8.RuneCountInString(row.label); n > width {
			width = n
		}
	}
	for _, row := range rows {
		fmt.Fprintf(w, "  %-*s  %s\n", width, row.label, row.value)
	}
}

// wafAPIError is the exit for a call the API refused or failed: its own message, in the
// reader's language where it has one, else the HTTP status.
func wafAPIError(resp map[string]any) error {
	fallback := T("unexpected response from the API")
	if status := httpStatusOf(resp); status >= 400 {
		fallback = fmt.Sprintf("HTTP %d", status)
	}
	return errExitMessage(1, terminalText(firstString(resp, "message", "error", fallback), ""))
}

// renderWafEvent prints one WAF event as a labelled record, its matched rules and the
// verdict. Everything that came from the blocked request — the URI, the Host header,
// the matched bytes — is attacker-chosen, so it goes through terminalSafe first.
func renderWafEvent(w io.Writer, event map[string]any) {
	rows := []struct{ label, value string }{
		{"Reference ID", strval(event["ref"])},
		{T("Time"), strval(event["time"])},
		{T("Status"), wafNumber(event["status"])},
		{T("Method"), strval(event["method"])},
		{"URI", strval(event["uri"])},
		{T("Host"), strval(event["host"])},
		{T("Client IP"), strval(event["client_ip"])},
		{T("Content type"), strval(event["content_type"])},
		{T("Size"), wafSize(event["content_length"])},
	}
	width := 0
	for _, row := range rows {
		if n := len([]rune(row.label)); n > width {
			width = n
		}
	}
	for _, row := range rows {
		value := terminalSafe(row.value)
		if value == "" {
			value = "-"
		}
		fmt.Fprintf(w, "%-*s  %s\n", width, row.label, value)
	}

	fmt.Fprintf(w, "\n%s\n", T("Matched rules"))
	rules, _ := event["rules"].([]any)
	if len(rules) == 0 {
		fmt.Fprintln(w, "  -")
	}
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		id := terminalSafe(wafNumber(rule["id"]))
		line := id
		if severity := terminalSafe(strval(rule["severity"])); severity != "" {
			line += "  [" + severity + "]"
		}
		if message := terminalSafe(strval(rule["message"])); message != "" {
			line += "  " + message
		}
		fmt.Fprintf(w, "  %s\n", line)
		indent := "  " + strings.Repeat(" ", len([]rune(id))+2)
		// CRS writes its own "Matched Data: " in front; under our label it is noise.
		if data := strings.TrimPrefix(strval(rule["data"]), "Matched Data: "); data != "" {
			fmt.Fprintf(w, "%s%s %s\n", indent, T("matched:"), terminalSafe(truncateRunes(data, matchedDataLimit)))
		}
		if explanation := terminalText(strval(rule["explanation"]), indent); explanation != "" {
			fmt.Fprintf(w, "%s%s\n", indent, explanation)
		}
	}

	verdict, _ := event["verdict"].(map[string]any)
	if text := terminalText(strval(verdict["text"]), "  "); text != "" {
		heading := T("Verdict")
		if kind := terminalSafe(strval(verdict["kind"])); kind != "" {
			heading += " (" + kind + ")"
		}
		fmt.Fprintf(w, "\n%s\n  %s\n", heading, text)
	}
}

// wafNumber prints a JSON number as an integer. encoding/json decodes every number
// as float64, and %v renders a 20 MB Content-Length as 2.097152e+07.
func wafNumber(v any) string {
	if n, ok := wafInt(v); ok {
		return strconv.FormatInt(n, 10)
	}
	return strval(v)
}

func wafInt(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		if n == math.Trunc(n) && !math.IsInf(n, 0) {
			return int64(n), true
		}
	case string:
		if parsed, err := strconv.ParseInt(strings.TrimSpace(n), 10, 64); err == nil {
			return parsed, true
		}
	}
	return 0, false
}

// wafSize shows a request body size both ways: the rounded unit for reading, the exact
// byte count for comparing against a limit.
func wafSize(v any) string {
	n, ok := wafInt(v)
	if !ok || n < 0 {
		return ""
	}
	return fmt.Sprintf(T("%s (%d bytes)"), humanBytes(n), n)
}

// truncateRunes shortens s to at most max characters without splitting one.
func truncateRunes(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "…"
}

// terminalSafe makes request-derived text safe to print. A raw ESC in a blocked URI or
// in the matched bytes of an upload would let whoever sent the request recolour, move
// or clear the operator's terminal, and a bidi override would reorder what they read;
// both are shown as escapes instead. Line breaks are escaped too, so one field stays on
// its line.
func terminalSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// terminalText prepares text the API wrote (explanations, the verdict) for printing.
// It is ours, not the attacker's, so line breaks stay line breaks (continued at indent)
// and bidi marks stay, since Arabic and Persian text may rely on them; only control
// characters are escaped, in case a request-derived value was ever quoted into it.
func terminalText(s, indent string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		switch {
		case r == '\n':
			b.WriteString("\n" + indent)
		case r == '\r':
		case r == '\t':
			b.WriteRune(' ')
		case unicode.IsControl(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
