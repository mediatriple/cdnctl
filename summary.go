package main

import (
	"fmt"
	"os"
	"strings"
)

// A person asking "what happened to my app" gets an answer; a program asking
// gets the data. The full payload of a single container app runs to hundreds of
// lines — revisions, operations, resource plans, timestamps — and burying the
// three facts that matter (is it up, where is it, why not) in that wall is a way
// of not answering at all.
//
// The split is by destination, not by flag: a terminal gets the summary, a pipe
// or a redirect gets JSON exactly as before, so every existing script keeps
// working untouched. --json forces the payload even on a terminal.

// wantsJSON reports whether the caller should receive the raw payload.
func wantsJSON(args parsedArgs) bool {
	if args.Bools["json"] {
		return true
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return true
	}
	return (info.Mode() & os.ModeCharDevice) == 0
}

// printAppSummary renders one container app as the few lines a person asked for.
func printAppSummary(payload map[string]any) {
	app, _ := payload["app"].(map[string]any)
	if app == nil {
		app = payload
	}

	name, _ := app["name"].(string)
	state := appState(app)
	domain := appDomain(payload)

	fmt.Printf("%-10s %s\n", T("App"), name)
	fmt.Printf("%-10s %s\n", T("State"), state)
	if domain != "" {
		fmt.Printf("%-10s https://%s\n", T("Address"), domain)
	}
	if image, ok := app["image"].(string); ok && image != "" {
		if tag, ok := app["tag"].(string); ok && tag != "" {
			image += ":" + tag
		}
		fmt.Printf("%-10s %s\n", T("Image"), image)
	}
	fmt.Printf("%-10s %s\n", T("Resources"), resourceLine(app))

	// A failure is the reason someone is reading this at all, so it gets the
	// last word and a next step rather than a field among fields.
	if hint := failureHint(app); hint != "" {
		fmt.Println()
		fmt.Println(hint)
	}
	fmt.Println()
	fmt.Println(T("Full detail: add --json"))
}

// appState collapses the several state fields into the one a person means.
func appState(app map[string]any) string {
	if raw, ok := app["runtime_status"].(string); ok && raw != "" {
		return raw
	}
	if revisions, ok := app["revisions"].([]any); ok && len(revisions) > 0 {
		if latest, ok := revisions[0].(map[string]any); ok {
			if status, ok := latest["status"].(string); ok && status != "" {
				return status
			}
		}
	}
	if desired, ok := app["desired_state"].(string); ok && desired != "" {
		return desired
	}
	return T("unknown")
}

func resourceLine(app map[string]any) string {
	number := func(key string) int {
		if value, ok := app[key].(float64); ok {
			return int(value)
		}
		return 0
	}
	return fmt.Sprintf("%d x %dm CPU / %d MB", max(number("replicas"), 1), number("cpu_millicores"), number("memory_mb"))
}

// failureHint turns a failed revision into the sentence someone can act on.
func failureHint(app map[string]any) string {
	state := strings.ToLower(appState(app))
	if state != "failed" && state != "crashloopbackoff" && state != "error" {
		return ""
	}
	uuid, _ := app["uuid"].(string)
	lines := []string{T("The app is not serving. What usually explains it:")}
	if health, ok := app["healthcheck_path"].(string); ok && health != "" {
		lines = append(lines, fmt.Sprintf(T("  · the healthcheck %s never answered 200 — the platform stops a container that fails its probe"), health))
	}
	lines = append(lines,
		T("  · the app exited on its own, or never listened on the configured port (bind 0.0.0.0, not localhost)"),
		fmt.Sprintf(T("Read the logs: cdnctl container apps logs --app %s --tail 50"), uuid))
	return strings.Join(lines, "\n")
}

// printAppListSummary renders the app list as one line each.
func printAppListSummary(payload map[string]any) {
	apps, _ := payload["apps"].([]any)
	if len(apps) == 0 {
		fmt.Println(T("No container apps on this account yet. Create one: cdnctl deploy"))
		return
	}
	for _, raw := range apps {
		app, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := app["name"].(string)
		domain := ""
		if list, ok := app["domains"].([]any); ok && len(list) > 0 {
			domain, _ = list[0].(string)
		}
		uuid, _ := app["uuid"].(string)
		fmt.Printf("%-24s %-14s %-42s %s\n", truncate(name, 24), appState(app), domain, uuid)
	}
	fmt.Println()
	fmt.Println(T("Full detail: add --json"))
}

func truncate(text string, limit int) string {
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[:limit-1]) + "…"
}
