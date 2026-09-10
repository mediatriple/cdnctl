package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

// cmdCdn groups the CDN account settings that are not files or purges. Today that
// is the cache/advanced rules.
func cmdCdn(args parsedArgs) error {
	if len(args.Positionals) == 0 {
		usage(os.Stderr)
		return errExit(2)
	}

	switch args.Positionals[0] {
	case "advanced-rules":
		return cmdAdvancedRules(parsedArgs{
			Positionals: args.Positionals[1:],
			Options:     args.Options,
			Bools:       args.Bools,
			Multi:       args.Multi,
		})
	default:
		usage(os.Stderr)
		return errExit(2)
	}
}

func cmdAdvancedRules(args parsedArgs) error {
	action := "list"
	if len(args.Positionals) >= 1 {
		action = args.Positionals[0]
	}

	switch action {
	case "list":
		account, err := resolveAccountE(args)
		if err != nil {
			return err
		}
		return printRequest(http.MethodGet, "advanced_managements/"+account, nil)
	case "validate":
		return cmdAdvancedRulesValidate(args, false)
	case "create":
		return cmdAdvancedRulesValidate(args, true)
	default:
		usage(os.Stderr)
		return errExit(2)
	}
}

// cmdAdvancedRulesValidate answers "would this rule be accepted?" without writing it.
//
// A cache rule is the setting where being wrong is both expensive and quiet: a path
// regex that matches too much, or a query mode that drops part of the cache key, does
// not error — it serves the wrong thing until someone notices. The server runs the same
// validation the save runs, so a pass here means the save will not be rejected.
// create runs the same path as validate and then saves. Sharing the code is the point:
// a rule that validates and is then rejected by the save would make the dry run
// worthless, so there is only one way for a rule to reach the server.
func cmdAdvancedRulesValidate(args parsedArgs, save bool) error {
	account, err := resolveAccountE(args)
	if err != nil {
		return err
	}

	file := option(args, "file", "")
	if file == "" {
		verb := "validate"
		if save {
			verb = "create"
		}
		return errExitMessage(2, "usage: cdnctl cdn advanced-rules "+verb+" --account <uuid> --file rule.json")
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", file, err)
	}

	var rule map[string]any
	if err := json.Unmarshal(data, &rule); err != nil {
		// A JSON error here is the most common failure and the least helpful when it
		// arrives as a server-side validation message about missing fields.
		return errExitMessage(2, fmt.Sprintf("%s is not valid JSON: %v", file, err))
	}

	// Always validate first, even when saving: the store endpoint reports the same
	// problems, but only one at a time, and a rule usually has more than one.
	resp, err := requestJSON(http.MethodPost, "advanced_managements/"+account+"/validate", rule)
	if err != nil {
		return err
	}

	if valid, ok := resp["valid"].(bool); ok && valid {
		if !save {
			fmt.Fprintln(os.Stderr, "Rule is valid — the save would be accepted.")
			return nil
		}

		saved, err := requestJSON(http.MethodPost, "advanced_managements/"+account+"/store", rule)
		if err != nil {
			return err
		}
		if status := strval(saved["status"]); status != "success" {
			fmt.Fprintf(os.Stderr, "Rule was not saved: %s\n", strval(saved["message"]))
			return errExit(1)
		}
		fmt.Fprintln(os.Stderr, "Rule saved. It reaches traffic on the next Apply Changes.")
		return nil
	}

	fmt.Fprintln(os.Stderr, "Rule was rejected:")
	if errs, ok := resp["errors"].(map[string]any); ok {
		for field, messages := range errs {
			for _, message := range toStringSlice(messages) {
				fmt.Fprintf(os.Stderr, "  %s: %s\n", field, message)
			}
		}
	} else if message := strval(resp["message"]); message != "" {
		fmt.Fprintf(os.Stderr, "  %s\n", message)
	}

	// Non-zero: a pipeline that validates before deploying has to be able to stop.
	return errExit(1)
}

func toStringSlice(v any) []string {
	switch value := v.(type) {
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			out = append(out, strval(item))
		}
		return out
	case string:
		return []string{value}
	default:
		return []string{strval(v)}
	}
}
