package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// cmdLogsGrep searches the account's delivered access logs on the customer's own machine.
//
// The panel deliberately has no search inside log files: a day is hundreds of gzipped
// objects and the useful questions ("every request from this IP", "5xx on this path
// between 14:00 and 15:00") are exactly what a local scan answers well. grep downloads
// only the 5-minute files that overlap the requested window — into the same cache
// directory `logs pull` uses, so nothing is fetched twice — and filters line by line.
func cmdLogsGrep(args parsedArgs, account string) error {
	now := time.Now()
	from, err := parseLogTime(option(args, "from", ""), now)
	if err != nil || option(args, "from", "") == "" || option(args, "from", "") == "true" {
		return errExitMessage(2, "usage: cdnctl logs grep --from <time> [--to <time>] [filters]  (time: 2026-09-25T14:00, \"2026-09-25 14:00\", 14:00 or RFC 3339; no zone = this computer's local time)")
	}
	to := now
	if raw := option(args, "to", ""); raw != "" && raw != "true" {
		if to, err = parseLogTime(raw, now); err != nil {
			return errExitMessage(2, "--to: "+err.Error())
		}
	}
	if !to.After(from) {
		return errExitMessage(2, "--to must be after --from")
	}

	filter, err := newLogFilter(args)
	if err != nil {
		return errExitMessage(2, err.Error())
	}
	cacheDir := option(args, "cache_dir", "cdntr-logs")
	format := option(args, "format", "json")
	countOnly := args.Bools["count"]

	var paths []string
	fetchedTotal := 0
	for _, day := range utcDays(from, to) {
		files, err := listLogFiles(account, day)
		if err != nil {
			return err
		}
		var wanted []map[string]any
		for _, f := range files {
			if logFileOverlaps(strval(f["key"]), from, to) {
				wanted = append(wanted, f)
			}
		}
		dir := filepath.Join(cacheDir, day)
		fetched, _, err := syncLogFiles(account, wanted, dir)
		if err != nil {
			return err
		}
		fetchedTotal += fetched
		for _, f := range wanted {
			paths = append(paths, filepath.Join(dir, path.Base(strval(f["key"]))))
		}
	}
	sort.Strings(paths)

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	if format == "table" && !countOnly {
		fmt.Fprintf(out, "%-25s %-6s %-4s %-6s %-40s %-15s %s\n", "TIME", "METHOD", "CODE", "CACHE", "HOST+PATH", "CLIENT", "COUNTRY")
	}

	scanned, matched := 0, 0
	for _, p := range paths {
		n, m, err := grepLogFile(p, from, to, filter, func(raw []byte, rec map[string]any) {
			if countOnly {
				return
			}
			if format == "table" {
				fmt.Fprintf(out, "%-25s %-6s %-4s %-6s %-40s %-15s %s\n", strval(rec["ts"]), strval(rec["method"]),
					strval(rec["status"]), strval(rec["cache"]), clip(strval(rec["host"])+strval(rec["uri"]), 40),
					strval(rec["client_ip"]), strval(rec["country"]))
				return
			}
			out.Write(raw)
			out.WriteByte('\n')
		})
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		scanned += n
		matched += m
	}
	if countOnly {
		fmt.Fprintln(out, matched)
	}
	fmt.Fprintf(os.Stderr, "%d file(s) (%d downloaded), %d line(s) in range scanned, %d matched  [%s → %s]\n",
		len(paths), fetchedTotal, scanned, matched, from.Format(time.RFC3339), to.Format(time.RFC3339))
	return nil
}

// logFilter holds the line predicates; every set field must match (AND).
type logFilter struct {
	ip      net.IP
	ipNet   *net.IPNet
	status  []string // "404", or a class like "5xx"
	host    string
	path    string
	method  string
	cache   string
	country string
	text    string
}

func newLogFilter(args parsedArgs) (logFilter, error) {
	f := logFilter{
		host:    strings.ToLower(opt(args, "host")),
		path:    opt(args, "path"),
		method:  strings.ToUpper(opt(args, "method")),
		cache:   strings.ToUpper(opt(args, "cache")),
		country: strings.ToUpper(opt(args, "country")),
		text:    opt(args, "text"),
	}
	if raw := opt(args, "ip"); raw != "" {
		if strings.Contains(raw, "/") {
			_, n, err := net.ParseCIDR(raw)
			if err != nil {
				return f, fmt.Errorf("--ip: not an address or CIDR: %s", raw)
			}
			f.ipNet = n
		} else if f.ip = net.ParseIP(raw); f.ip == nil {
			return f, fmt.Errorf("--ip: not an address or CIDR: %s", raw)
		}
	}
	for _, s := range strings.Split(opt(args, "status"), ",") {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if !logStatusArg.MatchString(s) {
			return f, fmt.Errorf("--status: use a code (404) or a class (5xx), comma-separated")
		}
		f.status = append(f.status, s)
	}
	return f, nil
}

func (f logFilter) match(raw []byte, rec map[string]any) bool {
	if f.text != "" && !strings.Contains(string(raw), f.text) {
		return false
	}
	if f.ip != nil || f.ipNet != nil {
		ip := net.ParseIP(strval(rec["client_ip"]))
		if ip == nil || (f.ip != nil && !f.ip.Equal(ip)) || (f.ipNet != nil && !f.ipNet.Contains(ip)) {
			return false
		}
	}
	if len(f.status) > 0 {
		code := strval(rec["status"])
		ok := false
		for _, s := range f.status {
			if s == code || (strings.HasSuffix(s, "xx") && len(code) == 3 && code[0] == s[0]) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if f.host != "" && strings.ToLower(strval(rec["host"])) != f.host {
		return false
	}
	if f.path != "" && !strings.Contains(strval(rec["uri"]), f.path) {
		return false
	}
	if f.method != "" && strings.ToUpper(strval(rec["method"])) != f.method {
		return false
	}
	if f.cache != "" && strings.ToUpper(strval(rec["cache"])) != f.cache {
		return false
	}
	if f.country != "" && strings.ToUpper(strval(rec["country"])) != f.country {
		return false
	}
	return true
}

// grepLogFile streams one gzipped JSON-lines file; lines outside [from, to) are skipped
// (a file overlapping the window edge also holds lines just outside it).
func grepLogFile(p string, from, to time.Time, f logFilter, emit func([]byte, map[string]any)) (int, int, error) {
	fh, err := os.Open(p)
	if err != nil {
		return 0, 0, err
	}
	defer fh.Close()
	gz, err := gzip.NewReader(fh)
	if err != nil {
		return 0, 0, err
	}
	defer gz.Close()

	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	scanned, matched := 0, 0
	for sc.Scan() {
		raw := sc.Bytes()
		var rec map[string]any
		if json.Unmarshal(raw, &rec) != nil {
			continue
		}
		ts, err := time.Parse(time.RFC3339, strval(rec["ts"]))
		if err != nil || ts.Before(from) || !ts.Before(to) {
			continue
		}
		scanned++
		if f.match(raw, rec) {
			matched++
			emit(append([]byte(nil), raw...), rec)
		}
	}
	if err := sc.Err(); err != nil && err != io.EOF {
		return scanned, matched, err
	}
	return scanned, matched, nil
}

var logStatusArg = regexp.MustCompile(`^([1-5]xx|[1-5][0-9][0-9])$`)

var logKeyStamp = regexp.MustCompile(`/(\d{8}T\d{6}Z)-[A-Za-z0-9-]+\.jsonl\.gz$`)

// logFileOverlaps: a file shipped at T holds roughly (T-5m, T]; allow one extra minute for
// cron jitter so a line at the window edge is never missed.
func logFileOverlaps(key string, from, to time.Time) bool {
	m := logKeyStamp.FindStringSubmatch(key)
	if m == nil {
		return false
	}
	shipped, err := time.Parse("20060102T150405Z", m[1])
	if err != nil {
		return false
	}
	start := shipped.Add(-6 * time.Minute)
	return shipped.After(from) && start.Before(to)
}

// utcDays lists the UTC folders a window touches, plus the next day (a file shipped just
// after midnight UTC holds the last minutes of the previous day).
func utcDays(from, to time.Time) []string {
	var days []string
	d := time.Date(from.UTC().Year(), from.UTC().Month(), from.UTC().Day(), 0, 0, 0, 0, time.UTC)
	end := to.UTC().Add(6 * time.Minute)
	for !d.After(end) {
		days = append(days, d.Format("2006-01-02"))
		d = d.AddDate(0, 0, 1)
	}
	return days
}

// parseLogTime accepts RFC 3339, "2006-01-02T15:04", "2006-01-02 15:04", "2006-01-02"
// and a bare "15:04" (today). Without a zone the computer's local time is meant.
func parseLogTime(raw string, now time.Time) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, nil
	}
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, raw, now.Location()); err == nil {
			return t, nil
		}
	}
	if t, err := time.ParseInLocation("15:04", raw, now.Location()); err == nil {
		return time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), 0, 0, now.Location()), nil
	}
	return time.Time{}, fmt.Errorf("unrecognised time %q", raw)
}

func opt(args parsedArgs, key string) string {
	v := option(args, key, "")
	if v == "true" {
		return ""
	}
	return strings.TrimSpace(v)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
