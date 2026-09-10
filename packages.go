package main

import (
	"fmt"
	"net/http"
	"os"
)

// cmdPackages exposes the packages a user has paid for and not yet attached to
// an account.
//
// Every guide that creates an account tells the reader to supply PAID_PACKAGE_ID
// and then had nowhere to send them for it — the number lived in a panel screen
// and in the accounts JSON, under a key ("account_packages") that reads like it
// means the opposite of what it holds. This is that answer as a command.
func cmdPackages(args parsedArgs) error {
	action := "list"
	if len(args.Positionals) >= 1 {
		action = args.Positionals[0]
	}

	switch action {
	case "list":
		return cmdPackagesList(args)
	default:
		usage(os.Stderr)
		return errExit(2)
	}
}

func cmdPackagesList(args parsedArgs) error {
	resp, err := requestJSON(http.MethodGet, "accounts", nil)
	if err != nil {
		return err
	}

	// The endpoint returns only this user's paid, unassigned orders — its query is
	// literally "no account_packages row". --owned says that out loud for anyone
	// reading a script; there is no other set to ask for, so it changes nothing.
	list, _ := resp["account_packages"].([]any)

	if option(args, "format", "table") == "json" {
		return printJSON(map[string]any{"account_packages": list})
	}

	if len(list) == 0 {
		fmt.Fprintln(os.Stderr, "No paid package is waiting to be assigned.")
		fmt.Fprintln(os.Stderr, "Every package you have bought is already attached to an account.")
		return nil
	}

	fmt.Fprintf(os.Stderr, "%-10s  %-30s  %-12s  %s\n", "ID", "PACKAGE", "BANDWIDTH", "PLATFORM")
	for _, item := range list {
		pkg, ok := item.(map[string]any)
		if !ok {
			continue
		}
		platform := "no"
		if enabled, ok := pkg["managed_platform_enabled"].(float64); ok && enabled == 1 {
			platform = "yes"
		}
		fmt.Printf("%-10s  %-30s  %-12s  %s\n",
			strval(pkg["id"]), strval(pkg["package_name"]), strval(pkg["bandwidth"]), platform)
	}

	// The ID column is a user_orders row, not a packages row — the API returns both
	// and picking the wrong one fails with a message that does not say which.
	fmt.Fprintln(os.Stderr, "\nThe ID column is the value other commands and guides call PAID_PACKAGE_ID.")
	return nil
}
