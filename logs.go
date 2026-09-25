package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

var logDayPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// cmdLogs reads the account's delivered edge access logs (logpush).
//
// Delivery is switched on in the panel (Access logs page); from then on every edge
// uploads gzipped JSON lines to our object storage every five minutes. "pull" is the
// part a browser is bad at: a day is ~288 files per edge, and the usual consumer is a
// script feeding them into the customer's own log pipeline.
func cmdLogs(args parsedArgs) error {
	if len(args.Positionals) == 0 {
		usage(os.Stderr)
		return errExit(2)
	}
	account, err := resolveAccountE(args)
	if err != nil {
		return err
	}

	switch args.Positionals[0] {
	case "status":
		resp, err := requestJSON(http.MethodGet, "accounts/"+account+"/logpush", nil)
		if err != nil {
			return err
		}
		if option(args, "format", "table") == "json" {
			return printJSON(resp)
		}
		lp, ok := resp["logpush"].(map[string]any)
		if !ok {
			return logsError(resp)
		}
		fmt.Printf("enabled:    %v\nmask_ip:    %v\nretention:  %s days\n", lp["enabled"], lp["mask_ip"], strval(lp["retention_days"]))
		if lp["enabled"] != true {
			fmt.Fprintln(os.Stderr, "Delivery is off. Turn it on in the panel: Access logs.")
		}
		return nil
	case "list", "pull":
	default:
		usage(os.Stderr)
		return errExit(2)
	}

	day := option(args, "day", time.Now().UTC().Format("2006-01-02"))
	if !logDayPattern.MatchString(day) {
		return errExitMessage(2, "--day must be YYYY-MM-DD (UTC)")
	}
	files, err := listLogFiles(account, day)
	if err != nil {
		return err
	}

	if args.Positionals[0] == "list" {
		if option(args, "format", "table") == "json" {
			return printJSON(map[string]any{"day": day, "files": files})
		}
		fmt.Fprintf(os.Stderr, "%-70s  %10s\n", "FILE", "BYTES")
		for _, f := range files {
			fmt.Printf("%-70s  %10s\n", strval(f["key"]), strval(f["size"]))
		}
		fmt.Fprintf(os.Stderr, "\n%d file(s) for %s (UTC)\n", len(files), day)
		return nil
	}

	outDir := option(args, "out", filepath.Join("cdntr-logs", day))
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	fetched, skipped := 0, 0
	for _, f := range files {
		key := strval(f["key"])
		target := filepath.Join(outDir, path.Base(key))
		// Re-running pull only fetches what is new: a file already present with the
		// same size is the same upload (edges never rewrite an object).
		if st, err := os.Stat(target); err == nil && strconv.FormatInt(st.Size(), 10) == strval(f["size"]) {
			skipped++
			continue
		}
		if err := pullLogFile(account, key, target); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		fetched++
	}
	fmt.Fprintf(os.Stderr, "%s: %d downloaded, %d already present -> %s\n", day, fetched, skipped, outDir)
	return nil
}

func listLogFiles(account, day string) ([]map[string]any, error) {
	resp, err := requestJSON(http.MethodGet, "accounts/"+account+"/logpush/files?day="+day, nil)
	if err != nil {
		return nil, err
	}
	raw, ok := resp["files"].([]any)
	if !ok {
		return nil, logsError(resp)
	}
	files := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if f, ok := item.(map[string]any); ok {
			files = append(files, f)
		}
	}
	return files, nil
}

func pullLogFile(account, key, target string) error {
	resp, err := requestJSON(http.MethodGet, "accounts/"+account+"/logpush/download?key="+url.QueryEscape(key), nil)
	if err != nil {
		return err
	}
	signed := strval(resp["url"])
	if signed == "" {
		return logsError(resp)
	}

	client := &http.Client{Timeout: 120 * time.Second}
	res, err := client.Get(signed)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("storage answered HTTP %d", res.StatusCode)
	}

	tmp := target + ".part"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, res.Body); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, target)
}

func logsError(resp map[string]any) error {
	if message := strval(resp["message"]); message != "" {
		return errExitMessage(1, message)
	}
	return errExitMessage(1, "unexpected response from the API")
}
