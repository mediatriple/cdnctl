package main

import (
	"fmt"
	"net/http"
	"os"
)

// cmdWaf is the read-only WAF view.
//
// Triaging a block is the work least likely to happen in a browser: it starts from an
// alert or a customer message, often out of hours. The panel screen was the only way to
// see what the firewall had done, so the help center described the work with no terminal
// equivalent to offer.
func cmdWaf(args parsedArgs) error {
	if len(args.Positionals) == 0 || args.Positionals[0] != "logs" {
		usage(os.Stderr)
		return errExit(2)
	}

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
