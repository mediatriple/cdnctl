package main

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// cmdWaf is the read-only WAF view.
//
// Triaging a block is the work least likely to happen in a browser: it starts from an
// alert or a customer message, often out of hours. The panel screen was the only way to
// see what the firewall had done, so the help center described the work with no terminal
// equivalent to offer.
func cmdWaf(args parsedArgs) error {
	if len(args.Positionals) > 0 {
		switch args.Positionals[0] {
		case "logs":
			return cmdWafLogs(args)
		case "show":
			return cmdWafShow(args)
		}
	}
	usage(os.Stderr)
	return errExit(2)
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

	// The verdict and the rule explanations are written by the API in the reader's
	// language; the rule messages themselves stay as ModSecurity logged them.
	resp, err := requestJSONWithHeaders(http.MethodGet, "accounts/"+account+"/waf/events/"+ref, nil,
		map[string]string{"Accept-Language": resolveLang()})
	if err != nil {
		return err
	}

	// An error status first: the 404 (no such account) and 503 (the search itself failed)
	// bodies carry "found": false too, and reading those as "no such block" sends the
	// reader looking for a cause that is not there.
	status := httpStatusOf(resp)
	failed := status >= 400
	found, answered := resp["found"].(bool)
	if format == "json" {
		if err := printJSON(resp); err != nil {
			return err
		}
		if failed || !answered || !found {
			return errExit(1)
		}
		return nil
	}

	if failed || !answered {
		fallback := T("unexpected response from the API")
		if failed {
			fallback = fmt.Sprintf("HTTP %d", status)
		}
		return errExitMessage(1, terminalText(firstString(resp, "message", "error", fallback), ""))
	}
	event, _ := resp["event"].(map[string]any)
	if !found || event == nil {
		return errExitMessage(1, fmt.Sprintf(T("No WAF event with Reference ID %s in the last 30 days on this account's sites. If the block page came from a site on another account, pass --account <uuid>."), ref))
	}

	renderWafEvent(os.Stdout, event)
	return nil
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
