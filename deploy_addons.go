package main

// Managed add-ons declared in cdnctl.yaml.
//
// A first deploy used to run without its database: `cdnctl deploy` created the app
// and started it, and the add-on came later, by hand, from the panel or with
// `cdnctl container addons enable-postgres`. The app crashed on "connection url is
// empty" in between (measured on a live app, 2026-11-12: Postgres enabled six
// minutes after the first deploy). Declared here, an add-on exists and answers
// before the app's first pod starts:
//
//	addons:
//	  postgres:
//	    env_prefix: DATABASE   # the app receives DATABASE_URL
//	    plan: starter
//	  redis: true
//
// The section is a statement of what the app needs, not of everything it may have.
// cdnctl enables a declared add-on the app lacks and never touches one that exists:
// nothing is disabled or deleted because it is missing from the file, and an add-on
// that exists is not enabled a second time (the platform issues new credentials on
// every enable, and a database keeps the ones it was created with). An app that
// already gets the service another way is left alone as well: a ${web.DATABASE_URL}
// reference to the app that holds the database, its own DATABASE_URL secret, a
// preprod that shares production's data. A new add-on would take over those
// variables and move the running app onto an empty database.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// addonSpec is one declared add-on. An empty option is left to the platform's
// default (plan starter, the prefix of the add-on type).
type addonSpec struct {
	Type      string // the add-on's type as the API lists it: postgres, redis, mysql, nats
	EnvPrefix string
	Plan      string
	StorageMB int
	URLScheme string // mysql only
}

// addonKind is how one add-on type is enabled: the API path under
// apps/{uuid}/addons/ and the `cdnctl container addons` command that does the same.
// pod: the add-on runs a pod of its own, whose readiness the wait checks (MySQL is a
// database on a shared server). prefix: the platform's default env_prefix.
type addonKind struct {
	path    string
	command string
	storage bool
	pod     bool
	prefix  string
}

var addonKinds = map[string]addonKind{
	"postgres": {path: "postgres", command: "enable-postgres", storage: true, pod: true, prefix: "DATABASE"},
	"redis":    {path: "redis", command: "enable-redis", pod: true, prefix: "REDIS"},
	"mysql":    {path: "database", command: "enable-database", storage: true, prefix: "DB"},
	"nats":     {path: "nats", command: "enable-nats", storage: true, pod: true, prefix: "NATS"},
}

const supportedAddonNames = "postgres, redis, mysql, nats"

var envPrefixPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,23}$`)
var planCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (spec addonSpec) payload() map[string]any {
	payload := map[string]any{}
	if spec.EnvPrefix != "" {
		payload["env_prefix"] = spec.EnvPrefix
	}
	if spec.Plan != "" {
		payload["plan_code"] = spec.Plan
	}
	if spec.StorageMB > 0 {
		payload["storage_mb"] = spec.StorageMB
	}
	if spec.URLScheme != "" {
		payload["url_scheme"] = spec.URLScheme
	}
	return payload
}

// ownedEnvKeys are the variables the add-on sets on its app, as the panel lists
// them (ContainerPlatformService::managedAddonOwnedKeys). When the add-on becomes
// active the panel drops any value the app had for one of them, its own or a
// reference to another app, and rolls the app onto the add-on's. postgres and mysql
// also take DATABASE_URL, whatever the prefix.
func (spec addonSpec) ownedEnvKeys() []string {
	prefix := strings.Trim(strings.ToUpper(spec.EnvPrefix), "_")
	if prefix == "" {
		prefix = addonKinds[spec.Type].prefix
	}
	with := func(suffixes ...string) []string {
		keys := make([]string, 0, len(suffixes)+1)
		for _, suffix := range suffixes {
			keys = append(keys, prefix+"_"+suffix)
		}
		return keys
	}
	switch spec.Type {
	case "postgres":
		return append(with("HOST", "PORT", "NAME", "USER", "PASSWORD", "URL"), "DATABASE_URL")
	case "mysql":
		return append(with("HOST", "PORT", "DATABASE", "USERNAME", "PASSWORD", "URL"), "DATABASE_URL")
	case "redis":
		return with("HOST", "PORT", "DB", "URL", "PASSWORD", "USERNAME")
	case "nats":
		return append(with("HOST", "PORT"), "NATS_URL")
	}
	return nil
}

func addonNames(specs []addonSpec) string {
	names := make([]string, 0, len(specs))
	for _, spec := range specs {
		names = append(names, spec.Type)
	}
	return strings.Join(names, ", ")
}

// readManifestAddons reads the addons section of cdnctl.yaml. No file, or no
// section, declares nothing.
func readManifestAddons(dir string) ([]addonSpec, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "cdnctl.yaml"))
	if err != nil {
		return nil, nil
	}
	return parseManifestAddons(string(raw))
}

// stripManifestComment cuts a YAML comment: a # at the start of the line or after
// white space.
func stripManifestComment(line string) string {
	for i, r := range line {
		if r == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			return line[:i]
		}
	}
	return line
}

func unquoteManifestValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if first, last := value[0], value[len(value)-1]; (first == '"' || first == '\'') && first == last {
			return value[1 : len(value)-1]
		}
	}
	return value
}

// parseManifestAddons reads the section with a line scan, like the rest of the
// manifest: it is small enough that a YAML dependency would be the larger risk. It
// is strict where readManifestValue is lenient, because a misread line here is the
// bug the section exists to prevent: an add-on silently not provisioned. Three
// spellings are accepted:
//
//	addons:                  addons: [postgres, redis]      addons:
//	  postgres:                                               - postgres
//	    env_prefix: DATABASE                                  - redis
//	  redis: true
func parseManifestAddons(raw string) ([]addonSpec, error) {
	specs, _, err := parseManifestAddonSection(raw)
	return specs, err
}

// parseManifestAddonSection also returns the add-ons the file declares off
// (`postgres: false`): not wanted, which is an answer too. init stops suggesting
// an add-on once the file says either way.
func parseManifestAddonSection(raw string) ([]addonSpec, []string, error) {
	malformed := func(line int) error {
		return errExitMessage(2, fmt.Sprintf(T("cdnctl.yaml, line %d: the addons section could not be read. Write it as:\n  addons:\n    postgres:\n      env_prefix: DATABASE\n    redis: true"), line))
	}
	unknownAddon := func(line int, name string) error {
		return errExitMessage(2, fmt.Sprintf(T("cdnctl.yaml, line %d: unknown add-on %q. Supported: %s."), line, name, supportedAddonNames))
	}
	badValue := func(line int, key, value string) error {
		return errExitMessage(2, fmt.Sprintf(T("cdnctl.yaml, line %d: %q is not a valid value for %s."), line, value, key))
	}

	specs := []addonSpec{}
	index := map[string]int{} // type -> position in specs, -1 when declared off
	declare := func(line int, name string, enabled bool) error {
		name = strings.ToLower(name)
		if _, ok := addonKinds[name]; !ok {
			return unknownAddon(line, name)
		}
		if _, seen := index[name]; seen {
			return malformed(line)
		}
		if !enabled {
			index[name] = -1
			return nil
		}
		index[name] = len(specs)
		specs = append(specs, addonSpec{Type: name})
		return nil
	}

	misplaced := func(line int) error {
		return errExitMessage(2, fmt.Sprintf(T("cdnctl.yaml, line %d: addons must be a top-level key, at the start of the line, not nested under another key."), line))
	}

	// An editor may save the file with a byte-order mark; in front of a first-line
	// "addons:" it would hide the section.
	raw = strings.TrimPrefix(raw, "\ufeff")

	inSection := false
	entryIndent := -1
	current := "" // the add-on whose options follow
	for i, full := range strings.Split(raw, "\n") {
		line := i + 1
		text := strings.TrimRight(stripManifestComment(strings.TrimRight(full, "\r")), " \t")
		trimmed := strings.TrimLeft(text, " \t")
		if trimmed == "" {
			continue
		}
		lead := text[:len(text)-len(trimmed)]
		indent := len(lead)

		// YAML lets a list sit at the same column as its key, and that is how
		// PyYAML and other emitters write one:
		//
		//	addons:
		//	- postgres
		//
		// Read as a new top-level key, those lines would declare nothing.
		listAtColumnZero := inSection && indent == 0 && (trimmed == "-" || strings.HasPrefix(trimmed, "- "))

		if indent == 0 && !listAtColumnZero {
			inSection, current, entryIndent = false, "", -1
			key, value, ok := strings.Cut(trimmed, ":")
			if !ok || unquoteManifestValue(key) != "addons" { // "addons": is the same key
				continue
			}
			inSection = true
			value = strings.TrimSpace(value)
			switch {
			case value == "" || value == "{}" || value == "[]":
			case strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]"):
				for _, name := range strings.Split(value[1:len(value)-1], ",") {
					if name = unquoteManifestValue(name); name == "" {
						continue
					}
					if err := declare(line, name, true); err != nil {
						return nil, nil, err
					}
				}
			default:
				return nil, nil, malformed(line)
			}
			continue
		}
		if !inSection {
			// Nested under another key (deploy:, say), the section would be
			// skipped without a word.
			if key, _, ok := strings.Cut(strings.TrimPrefix(trimmed, "- "), ":"); ok && strings.EqualFold(unquoteManifestValue(key), "addons") {
				return nil, nil, misplaced(line)
			}
			continue
		}
		if strings.Contains(lead, "\t") {
			return nil, nil, malformed(line) // YAML indents with spaces; a tab's depth is a guess
		}

		if strings.HasPrefix(trimmed, "-") {
			name := unquoteManifestValue(strings.TrimSuffix(strings.TrimSpace(trimmed[1:]), ":"))
			if name == "" {
				return nil, nil, malformed(line)
			}
			if err := declare(line, name, true); err != nil {
				return nil, nil, err
			}
			current, entryIndent = "", indent
			continue
		}

		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			return nil, nil, malformed(line)
		}
		key, value = strings.TrimSpace(key), unquoteManifestValue(value)
		if entryIndent == -1 {
			entryIndent = indent
		}

		if indent == entryIndent {
			enabled := true
			switch strings.ToLower(value) {
			case "", "true", "yes", "on", "{}":
			case "false", "no", "off":
				enabled = false
			default:
				return nil, nil, badValue(line, key, value)
			}
			if err := declare(line, key, enabled); err != nil {
				return nil, nil, err
			}
			current = strings.ToLower(key)
			continue
		}
		if indent < entryIndent || current == "" {
			return nil, nil, malformed(line)
		}

		// An option of the add-on above. Options of one declared off are still
		// checked, so a typo does not wait for the day it is switched on.
		spec := addonSpec{Type: current}
		position := index[current]
		if position >= 0 {
			spec = specs[position]
		}
		switch key {
		case "env_prefix":
			if !envPrefixPattern.MatchString(value) {
				return nil, nil, badValue(line, key, value)
			}
			spec.EnvPrefix = value
		case "plan":
			if !planCodePattern.MatchString(value) {
				return nil, nil, badValue(line, key, value)
			}
			spec.Plan = value
		case "storage_mb":
			size, err := strconv.Atoi(value)
			if err != nil || size <= 0 || !addonKinds[current].storage {
				return nil, nil, badValue(line, key, value)
			}
			spec.StorageMB = size
		case "url_scheme":
			if current != "mysql" || value == "" {
				return nil, nil, badValue(line, key, value)
			}
			spec.URLScheme = value
		default:
			return nil, nil, errExitMessage(2, fmt.Sprintf(T("cdnctl.yaml, line %d: unknown add-on option %q. Supported: env_prefix, plan, storage_mb, url_scheme (mysql only)."), line, key))
		}
		if position >= 0 {
			specs[position] = spec
		}
	}
	off := []string{}
	for name, position := range index {
		if position < 0 {
			off = append(off, name)
		}
	}
	sort.Strings(off)
	return specs, off, nil
}

// deployTokenInUse: a cdnctl_ token reaches the deploy surface only, and add-ons
// are not on it.
func deployTokenInUse() bool {
	return strings.HasPrefix(readConfig().Token, "cdnctl_")
}

func deployTokenCannotEnable(specs []addonSpec) string {
	return fmt.Sprintf(T("A deploy token cannot enable add-ons (%s). Sign in with `cdnctl login` and deploy once from that session, or enable them in the panel; after that the token deploys as before."), addonNames(specs))
}

// refuseAddonsTheTokenCannotEnable runs before the build. A deploy-only token
// cannot enable an add-on, and hearing that after the archive, the upload and a
// minute of building wastes all three on every retry. A new app with declared
// add-ons always needs one enabled; an existing app is read to see whether it does.
func refuseAddonsTheTokenCannotEnable(account, appUUID string, declared []addonSpec) error {
	if len(declared) == 0 || !deployTokenInUse() {
		return nil
	}
	if appUUID == "" {
		return errExitMessage(1, deployTokenCannotEnable(declared))
	}
	show, err := requestJSON(http.MethodGet, fmt.Sprintf("accounts/%s/platform/container/apps/%s", account, appUUID), nil)
	if err != nil {
		return nil // the deploy reads the app again after the build and says what is wrong there
	}
	if _, failed := apiFailure(show); failed {
		return nil
	}
	if plan := planDeclaredAddons(show, declared, appUUID, appNeverDeployed(show)); len(plan.enable) > 0 {
		return errExitMessage(1, deployTokenCannotEnable(plan.enable))
	}
	return nil
}

// appAddons indexes the add-ons the platform has for an app by type. A deleted
// add-on is kept: an app that had one and lost it is not an app that never had
// it. A live row of the same type wins over a deleted one.
func appAddons(show map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, addon := range arrayMap(childMap(show, "app")["addons"]) {
		kind := strings.ToLower(strval(addon["type"]))
		if kind == "" {
			continue
		}
		if previous, seen := out[kind]; seen && strval(previous["status"]) != "deleted" {
			continue
		}
		out[kind] = addon
	}
	return out
}

// addonPodsReady reports whether the add-on's own pod answers. "active" in the
// panel means the add-on was applied to the cluster; a database needs a few more
// seconds before it accepts a connection, and an app started in that gap crashes
// on its first query.
//
// An add-on with no pod of its own (MySQL is a database on a shared server) counts
// as ready. One with a pod has to be reported ready: a look that does not list it
// is the cluster not having the pod yet, or the panel failing to ask the cluster
// this time (the app still reads, without runtime.addons), and either way the
// next look decides.
func addonPodsReady(show map[string]any, kind string) bool {
	if !addonKinds[kind].pod {
		return true
	}
	runtime := childMap(show, "runtime")
	if strval(runtime["mode"]) == "local-desired-state" {
		return true // a panel without a cluster behind it: there is no pod to ask about
	}
	for _, addon := range arrayMap(runtime["addons"]) {
		if strings.ToLower(strval(addon["kind"])) != kind {
			continue
		}
		ready, _ := intFrom(addon["ready"])
		healthy, known := addon["healthy"].(bool)
		return ready >= 1 && (!known || healthy)
	}
	return false
}

// appNeverDeployed: created, no revision yet. Its next deploy is its first.
func appNeverDeployed(show map[string]any) bool {
	revisions, ok := childMap(show, "app")["revisions"].([]any)
	return ok && len(revisions) == 0
}

// appDefinedKeys are the variables the app sets itself: its env, and the names of
// its secrets (the payload carries names, never values). true marks a value that
// is a ${app.VAR} reference, a variable read from another app.
func appDefinedKeys(app map[string]any) map[string]bool {
	keys := map[string]bool{}
	if env, ok := app["env"].(map[string]any); ok {
		for key, value := range env {
			if text := strval(value); strings.TrimSpace(text) != "" {
				keys[key] = strings.Contains(text, "${")
			}
		}
	}
	if names, ok := app["secret_keys"].([]any); ok {
		for _, name := range names {
			if key := strval(name); key != "" {
				if _, seen := keys[key]; !seen {
					keys[key] = false
				}
			}
		}
	}
	return keys
}

// keysTheAddonWouldReplace lists the app's own variables the add-on would take
// over, a reference shown as KEY=${…}. Only names are printed: a value set in
// env may itself hold a credential.
func keysTheAddonWouldReplace(spec addonSpec, defined map[string]bool) string {
	var hits []string
	for _, key := range spec.ownedEnvKeys() {
		reference, found := defined[key]
		if !found {
			continue
		}
		if reference {
			key += "=${…}"
		}
		hits = append(hits, key)
	}
	sort.Strings(hits)
	return strings.Join(hits, ", ")
}

// addonPlan is what a deploy does about the add-ons cdnctl.yaml declares, decided
// from one read of the app before anything is written.
type addonPlan struct {
	enable []addonSpec // missing: enabled, then waited for
	wait   []addonSpec // already being provisioned: waited for
	lines  []string    // what the person is told about the others, printed as they are
	stop   string      // set when a first deploy must not go out
}

// planDeclaredAddons decides, add-on by add-on:
//
//   - Missing: enabled, unless the app already gets that service another way. A
//     preprod that shares production's data reads production's add-ons, and the
//     panel refuses it one of its own. An app that already sets a variable the
//     add-on owns (its own DATABASE_URL secret, or ${web.DATABASE_URL} from the
//     app that holds the database) would be moved onto a new, empty add-on the
//     moment it became active. Both are said and left alone.
//   - Being provisioned: waited for. Active: left alone.
//   - Deleted, on an app that is already deployed: someone removed it, and a new
//     one would start empty. Said and left alone. Before a first deploy it is
//     treated as missing: the app never ran with it.
//   - Disabled or failed: not touched. Before a first deploy that stops the deploy
//     (the app would start without what it declares); on an app that already runs
//     it is said, and the deploy goes on, because that state was there before this
//     deploy and is not a reason to hold back a release.
//
// Every line goes to stdout with the rest of the deploy's progress: the MCP deploy
// tool hands an agent stdout and nothing else.
func planDeclaredAddons(show map[string]any, declared []addonSpec, appUUID string, firstDeploy bool) addonPlan {
	plan := addonPlan{}
	app := childMap(show, "app")
	existing := appAddons(show)
	defined := appDefinedKeys(app)
	sharedPreprod := strval(app["environment"]) == "preprod" &&
		strval(childMap(app, "promotion_meta")["data_sharing"]) == "shared"

	for _, spec := range declared {
		command := addonKinds[spec.Type].command + " --app " + appUUID
		current, found := existing[spec.Type]
		status := strval(current["status"])
		if found && status == "deleted" && firstDeploy {
			found = false
		}

		if !found {
			switch replaced := keysTheAddonWouldReplace(spec, defined); {
			case sharedPreprod:
				plan.lines = append(plan.lines, fmt.Sprintf(T("   add-on %s: not enabled: this preprod shares production's data, add-ons included (data_sharing=shared).\n"), spec.Type))
			case replaced != "":
				plan.lines = append(plan.lines, fmt.Sprintf(T("   add-on %s: not enabled: the app already has %s, and a new add-on would replace it. To do that deliberately: `cdnctl container addons %s`.\n"), spec.Type, replaced, command))
			default:
				plan.enable = append(plan.enable, spec)
			}
			continue
		}

		if status != "deleted" {
			// It exists, so its options are the ones it was enabled with.
			for _, option := range []struct{ name, declared, actual string }{
				{"env_prefix", spec.EnvPrefix, strval(current["env_prefix"])},
				{"plan", spec.Plan, strval(current["plan_code"])},
			} {
				if option.declared != "" && option.actual != "" && !strings.EqualFold(option.declared, option.actual) {
					plan.lines = append(plan.lines, fmt.Sprintf(T("note: the %s add-on exists with %s %s; cdnctl.yaml says %s. cdnctl does not change an add-on that exists.\n"),
						spec.Type, option.name, terminalSafe(option.actual), option.declared))
				}
			}
		}

		switch status {
		case "active":
			plan.lines = append(plan.lines, fmt.Sprintf(T("   add-on %s: active\n"), spec.Type))
		case "pending", "provisioning":
			plan.wait = append(plan.wait, spec)
		case "deleted":
			plan.lines = append(plan.lines, fmt.Sprintf(T("The %s add-on declared in cdnctl.yaml was deleted on the platform. cdnctl does not create it again for an app that is already deployed: a new one starts empty and takes over the app's connection variables. To create it deliberately: `cdnctl container addons %s`."), spec.Type, command)+"\n")
		default:
			message := fmt.Sprintf(T("The %s add-on declared in cdnctl.yaml is \"%s\" on the platform. cdnctl does not change an add-on that exists: enable it in the panel, or with `cdnctl container addons %s`."),
				spec.Type, terminalSafe(status), command)
			if firstDeploy {
				if plan.stop == "" {
					plan.stop = message
				}
				continue
			}
			plan.lines = append(plan.lines, message+"\n")
		}
	}
	return plan
}

// ensureDeclaredAddons makes the add-ons cdnctl.yaml declares exist and answer
// before the deploy that follows (planDeclaredAddons says which ones it touches).
func ensureDeclaredAddons(account, appUUID string, declared []addonSpec, newApp bool) error {
	if len(declared) == 0 {
		return nil
	}
	base := fmt.Sprintf("accounts/%s/platform/container/apps/%s", account, appUUID)
	show, err := requestJSON(http.MethodGet, base, nil)
	if err != nil {
		return err
	}
	if reason, failed := apiFailure(show); failed {
		return errExitMessage(1, fmt.Sprintf(T("Could not read the app's state: %s"), reason))
	}
	firstDeploy := newApp || appNeverDeployed(show)
	stop := func(message string) error {
		if firstDeploy {
			message += "\n" + T("The app exists but was not deployed: it would start without an add-on it declares. Run `cdnctl deploy` again once the add-on is ready.")
		}
		return errExitMessage(1, message)
	}

	plan := planDeclaredAddons(show, declared, appUUID, firstDeploy)
	for _, line := range plan.lines {
		fmt.Print(line)
	}
	if plan.stop != "" {
		return stop(plan.stop)
	}
	if len(plan.enable) > 0 && deployTokenInUse() {
		return stop(deployTokenCannotEnable(plan.enable))
	}

	waitFor := append([]addonSpec(nil), plan.wait...)
	for _, spec := range plan.enable {
		fmt.Printf(T("→ enabling add-on: %s\n"), spec.Type)
		resp, err := requestJSON(http.MethodPost, base+"/addons/"+addonKinds[spec.Type].path, spec.payload())
		if err != nil {
			return err
		}
		if reason, failed := apiFailure(resp); failed {
			return stop(fmt.Sprintf(T("Could not enable the %s add-on: %s"), spec.Type, reason))
		}
		waitFor = append(waitFor, spec)
	}
	if len(waitFor) == 0 {
		return nil
	}

	fmt.Printf(T("→ waiting for add-ons to be ready (%s)\n"), addonNames(waitFor))
	looks := (defaultDeployTimeout + deployPollSeconds - 1) / deployPollSeconds
	deadline := clock().Add(defaultDeployTimeout * time.Second)
	pending := waitFor
	for i := 0; i < looks; i++ {
		if i > 0 && !pauseBeforeNextLook(deadline) {
			break
		}
		show, err := requestJSON(http.MethodGet, base, nil)
		if err != nil {
			return err
		}
		if _, failed := apiFailure(show); failed {
			continue
		}
		existing := appAddons(show)
		var still []addonSpec
		for _, spec := range pending {
			current := existing[spec.Type]
			switch status := strval(current["status"]); {
			case status == "failed":
				return stop(fmt.Sprintf(T("The %s add-on could not be provisioned: %s"),
					spec.Type, terminalSafe(firstNonEmpty(strval(current["last_error"]), status))))
			case status == "active" && addonPodsReady(show, spec.Type):
				fmt.Printf(T("   add-on %s: active\n"), spec.Type)
			default:
				still = append(still, spec)
			}
		}
		if pending = still; len(pending) == 0 {
			return nil
		}
	}
	return stop(fmt.Sprintf(T("Timed out after %d seconds waiting for add-ons: %s"), defaultDeployTimeout, addonNames(pending)))
}
