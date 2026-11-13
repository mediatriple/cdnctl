package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// deployFixture is a project folder `cdnctl deploy` accepts, with the given
// cdnctl.yaml.
func deployFixture(t *testing.T, manifest string) string {
	t.Helper()
	return writeFixture(t, map[string]string{
		"Dockerfile":  "FROM node:20-alpine\nCOPY server.js .\nCMD [\"node\", \"server.js\"]\n",
		"server.js":   "require('http').createServer((q, s) => s.end('ok')).listen(process.env.PORT)\n",
		"cdnctl.yaml": manifest,
	})
}

// runDeploy runs `cdnctl deploy` on dir. said is everything a person would read on
// stderr: what the command printed there plus the message main() prints for the
// error it returns.
func runDeploy(t *testing.T, dir string, extra ...string) (stdout, said string, err error) {
	t.Helper()
	argv := append([]string{"deploy", "--dir", dir, "--account", "acct-1", "--no-healthcheck"}, extra...)
	stdout, said, err = captureOutput(t, func() error { return run(argv) })
	if exit, ok := isExitError(err); ok {
		said += exit.message
	} else if err != nil {
		said += err.Error()
	}
	return stdout, said, err
}

func mustNotCall(t *testing.T, fp *fakePlatform, what string, match func(call string) bool) {
	t.Helper()
	for _, call := range fp.recorded() {
		if match(call) {
			t.Fatalf("%s: %q was sent; all calls: %v", what, call, fp.recorded())
		}
	}
}

func isDelete(call string) bool { return strings.HasPrefix(call, "DELETE ") }

func isAddonWrite(call string) bool {
	return strings.Contains(call, "/addons") && !strings.HasPrefix(call, "GET ")
}

func TestManifestAddonsAreReadInEverySpellingWeDocument(t *testing.T) {
	cases := []struct {
		name     string
		manifest string
		want     []addonSpec
	}{
		{"no section", "name: x\nport: 3000\n", []addonSpec{}},
		{"map with options", "name: x\naddons:\n  postgres:\n    env_prefix: DATABASE\n    plan: standard\n    storage_mb: 20480\n  redis: true\napp: 123\n",
			[]addonSpec{{Type: "postgres", EnvPrefix: "DATABASE", Plan: "standard", StorageMB: 20480}, {Type: "redis"}}},
		{"empty value and braces", "addons:\n  redis:\n  nats: {}\n", []addonSpec{{Type: "redis"}, {Type: "nats"}}},
		{"declared off", "addons:\n  postgres: false\n  redis: yes\n", []addonSpec{{Type: "redis"}}},
		{"flow list", "addons: [postgres, redis]\n", []addonSpec{{Type: "postgres"}, {Type: "redis"}}},
		{"block list", "addons:\n  - postgres\n  - redis\n", []addonSpec{{Type: "postgres"}, {Type: "redis"}}},
		{"mysql url scheme", "addons:\n  mysql:\n    url_scheme: mysql+pymysql\n    env_prefix: \"DB\"\n", []addonSpec{{Type: "mysql", URLScheme: "mysql+pymysql", EnvPrefix: "DB"}}},
		{"comments and blank lines", "addons:   # what the app needs\n\n  postgres:   # the database\n    # env_prefix: OLD\n    env_prefix: DATABASE  # DATABASE_URL\n", []addonSpec{{Type: "postgres", EnvPrefix: "DATABASE"}}},
		{"commented out", "name: x\n# addons:\n#   postgres: true\n", []addonSpec{}},
		{"ends at the next top-level key", "addons:\n  redis: true\ndeploy:\n  method: source\n  postgres: true\n", []addonSpec{{Type: "redis"}}},
		{"four spaces", "addons:\n    postgres:\n        plan: large\n", []addonSpec{{Type: "postgres", Plan: "large"}}},
		// What PyYAML's safe_dump writes for a list: the items at the key's column.
		{"block list at column zero", "addons:\n- postgres\n- redis\n", []addonSpec{{Type: "postgres"}, {Type: "redis"}}},
		{"column-zero list, then the next key", "name: x\naddons:\n- nats\nport: 3000\n", []addonSpec{{Type: "nats"}}},
		{"byte-order mark before the section", "\ufeffaddons:\n  postgres: true\n", []addonSpec{{Type: "postgres"}}},
		// Quoted keys are valid YAML; an agent writing JSON-style YAML quotes them.
		{"double-quoted key", "name: demo\n\"addons\":\n  postgres: true\n", []addonSpec{{Type: "postgres"}}},
		{"single-quoted key with a flow list", "'addons': [redis]\n", []addonSpec{{Type: "redis"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseManifestAddons(tc.manifest)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// A section that cannot be read must stop the deploy. Skipping it quietly is the
// bug the section exists to prevent: the app started without its database.
func TestManifestAddonsRefuseWhatTheyCannotRead(t *testing.T) {
	englishMessages(t)
	cases := []struct {
		name     string
		manifest string
		mention  string
	}{
		{"unknown add-on", "addons:\n  mongodb: true\n", "mongodb"},
		{"unknown option", "addons:\n  postgres:\n    version: 16\n", "version"},
		{"bad prefix", "addons:\n  postgres:\n    env_prefix: 1DB\n", "env_prefix"},
		{"storage on redis", "addons:\n  redis:\n    storage_mb: 1024\n", "storage_mb"},
		{"url scheme on postgres", "addons:\n  postgres:\n    url_scheme: mysql\n", "url_scheme"},
		{"scalar value", "addons:\n  postgres: starter\n", "starter"},
		{"plain word", "addons: postgres\n", "line 1"},
		{"options under a list item", "addons:\n  - postgres:\n      plan: large\n", "line 3"},
		{"tab indent", "addons:\n\tpostgres: true\n", "line 2"},
		{"declared twice", "addons:\n  redis: true\n  redis: true\n", "line 3"},
		// Valid YAML that would otherwise declare nothing without a word.
		{"nested under deploy", "name: x\ndeploy:\n  method: source\n  addons:\n    postgres: true\n", "line 4"},
		{"nested list key", "services:\n  - addons: [postgres]\n", "line 2"},
		{"options under a column-zero list item", "addons:\n- postgres:\n    plan: large\n", "line 3"},
		{"unknown add-on in a column-zero list", "addons:\n- mongodb\n", "mongodb"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			specs, err := parseManifestAddons(tc.manifest)
			exit, ok := isExitError(err)
			if !ok || exit.code != 2 {
				t.Fatalf("want exit 2, got %#v (specs %+v)", err, specs)
			}
			if !strings.Contains(exit.message, tc.mention) || !strings.Contains(exit.message, "cdnctl.yaml") {
				t.Fatalf("the message must name the file and %q: %q", tc.mention, exit.message)
			}
		})
	}

	// ... and deploy stops on it before anything is uploaded.
	fp, _ := newFakePlatform(t)
	dir := deployFixture(t, "name: demo\naddons:\n  mongodb: true\n")
	if _, _, err := runDeploy(t, dir); exitCode(err) != 2 {
		t.Fatalf("want exit 2, got %v", err)
	}
	if calls := fp.recorded(); len(calls) != 0 {
		t.Fatalf("nothing may reach the API: %v", calls)
	}
}

// The order this work exists for: the app is created, its add-ons are enabled
// and answer, and only then does the first pod start.
func TestDeployNewAppEnablesDeclaredAddonsBeforeTheFirstDeploy(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.addonActiveAfter = 2 // "pending" for two reads
	fp.addonReadyAfter = 1  // then one more read before the database answers
	fp.readyAfter = 1
	dir := deployFixture(t, "name: demo\nport: 3000\naddons:\n  postgres:\n    env_prefix: DATABASE\n    plan: standard\n    storage_mb: 20480\n  redis: true\n")

	stdout, stderr, err := runDeploy(t, dir)
	if err != nil {
		t.Fatalf("deploy failed: %v\n%s\n%s", err, stdout, stderr)
	}

	create, postgres, redis, deploy := fp.indexOf("POST apps"), fp.indexOf("POST apps/app-1/addons/postgres"), fp.indexOf("POST apps/app-1/addons/redis"), fp.indexOf(fakeDeployCall)
	if create < 0 || postgres < 0 || redis < 0 || deploy < 0 {
		t.Fatalf("create, both add-ons and the deploy must all happen: %v", fp.recorded())
	}
	if !(create < postgres && postgres < redis && redis < deploy) {
		t.Fatalf("want create -> add-ons -> deploy, got %v", fp.recorded())
	}
	if fp.count(fakeDeployCall) != 1 {
		t.Fatalf("exactly one deploy: %v", fp.recorded())
	}
	// When the deploy was sent, every declared add-on was active and answering.
	if len(fp.addonsAtDeploy) != 2 {
		t.Fatalf("add-ons at deploy time: %v", fp.addonsAtDeploy)
	}
	for _, state := range fp.addonsAtDeploy {
		if !strings.HasSuffix(state, ":active:true") {
			t.Fatalf("the deploy went out before an add-on was ready: %v", fp.addonsAtDeploy)
		}
	}
	// Three reads waiting for the add-ons (pending, pending, active+ready is the
	// third) sit between the last enable and the deploy.
	waits := 0
	for _, call := range fp.recorded()[redis+1 : deploy] {
		if call == fakeShowCall {
			waits++
		}
	}
	if waits != 3 {
		t.Fatalf("want 3 reads while the add-ons came up, got %d: %v", waits, fp.recorded())
	}

	if body := fp.bodyOf("POST apps/app-1/addons/postgres"); body["env_prefix"] != "DATABASE" || body["plan_code"] != "standard" || body["storage_mb"] != float64(20480) {
		t.Fatalf("postgres options not sent: %#v", body)
	}
	// Undeclared options are the platform's defaults: nothing is sent for them.
	if body := fp.bodyOf("POST apps/app-1/addons/redis"); len(body) != 0 {
		t.Fatalf("redis declared without options must send none: %#v", body)
	}
	mustNotCall(t, fp, "a deploy never deletes", isDelete)

	for _, want := range []string{"add-ons in cdnctl.yaml: postgres, redis", "→ enabling add-on: postgres", "→ enabling add-on: redis", "add-on postgres: active", "✓ LIVE: https://demo.cdn.com.tr"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("progress is missing %q:\n%s", want, stdout)
		}
	}
	// The app id is recorded after the section and the section still reads.
	manifest, _ := os.ReadFile(filepath.Join(dir, "cdnctl.yaml"))
	if !strings.Contains(string(manifest), "app: app-1") {
		t.Fatalf("the app id was not recorded:\n%s", manifest)
	}
	if specs, err := readManifestAddons(dir); err != nil || len(specs) != 2 {
		t.Fatalf("the manifest no longer reads after the app id was added: %+v, %v", specs, err)
	}
}

// An existing app gets the declared add-on it lacks. The one it has is not
// enabled again, and one the file does not mention is left alone.
func TestDeployExistingAppEnablesOnlyTheMissingAddon(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.existingApp()
	fp.withAddon("postgres", "active")
	fp.withAddon("nats", "active") // on the platform, not in cdnctl.yaml
	dir := deployFixture(t, "name: demo\napp: app-1\naddons:\n  postgres: true\n  redis: true\n")

	stdout, stderr, err := runDeploy(t, dir)
	if err != nil {
		t.Fatalf("deploy failed: %v\n%s\n%s", err, stdout, stderr)
	}

	var writes []string
	for _, call := range fp.recorded() {
		if isAddonWrite(call) {
			writes = append(writes, call)
		}
	}
	if !reflect.DeepEqual(writes, []string{"POST apps/app-1/addons/redis"}) {
		t.Fatalf("only the missing add-on may be enabled, got %v", writes)
	}
	mustNotCall(t, fp, "nothing undeclared is removed", isDelete)
	if fp.addons["nats"].status != "active" || fp.addons["postgres"].status != "active" {
		t.Fatalf("existing add-ons changed: %+v %+v", fp.addons["nats"], fp.addons["postgres"])
	}

	redis, patch, deploy := fp.indexOf("POST apps/app-1/addons/redis"), fp.indexOf("PATCH apps/app-1"), fp.indexOf(fakeDeployCall)
	if !(redis >= 0 && redis < patch && patch < deploy) {
		t.Fatalf("want add-on -> new image -> deploy, got %v", fp.recorded())
	}
	if fp.count("POST apps") != 0 || fp.count("POST apps/app-1/expose") != 0 {
		t.Fatalf("an existing app is not created or exposed again: %v", fp.recorded())
	}

	// The platform rolled the running app itself when redis became active: one
	// revision with the image it already ran. The deploy's own revision comes
	// after it, with the new image, and that is the one the report names.
	if want := []string{"2:registry.cdn.com.tr/acct/demo:t0"}; !reflect.DeepEqual(fp.ownerRolls, want) {
		t.Fatalf("owner roll: got %v, want %v", fp.ownerRolls, want)
	}
	if fp.image != "registry.cdn.com.tr/acct/demo:t1" {
		t.Fatalf("the new image was not applied: %q", fp.image)
	}
	if !strings.Contains(stdout, "Revision   3") || !strings.Contains(stdout, "✓ LIVE") {
		t.Fatalf("the report must follow the deploy's revision (3), not the owner roll's (2):\n%s", stdout)
	}
}

// Without a section, and with an empty one, the platform's add-ons are not
// cdnctl's business: no add-on call of any kind.
func TestDeployNeverRemovesAnAddonTheManifestDoesNotDeclare(t *testing.T) {
	for name, manifest := range map[string]string{
		"no section":    "name: demo\napp: app-1\n",
		"empty section": "name: demo\napp: app-1\naddons:\n",
		"declared off":  "name: demo\napp: app-1\naddons:\n  postgres: false\n  redis: false\n",
	} {
		t.Run(name, func(t *testing.T) {
			fp, _ := newFakePlatform(t)
			fp.existingApp()
			fp.withAddon("postgres", "active")
			fp.withAddon("redis", "active")
			dir := deployFixture(t, manifest)

			if stdout, stderr, err := runDeploy(t, dir); err != nil {
				t.Fatalf("deploy failed: %v\n%s\n%s", err, stdout, stderr)
			}
			mustNotCall(t, fp, "no DELETE", isDelete)
			mustNotCall(t, fp, "no add-on write", isAddonWrite)
			if fp.addons["postgres"].status != "active" || fp.addons["redis"].status != "active" {
				t.Fatalf("add-ons changed: %+v %+v", fp.addons["postgres"], fp.addons["redis"])
			}
			if fp.count(fakeDeployCall) != 1 {
				t.Fatalf("the deploy itself must still happen: %v", fp.recorded())
			}
		})
	}
}

// An add-on that exists is never enabled a second time, whatever state it is in:
// the platform issues new credentials on every enable and a database keeps the
// ones it was created with.
func TestDeployLeavesAnExistingAddonAsItIs(t *testing.T) {
	// On an app that already runs, a disabled add-on is a warning, not a stop.
	fp, _ := newFakePlatform(t)
	fp.existingApp()
	fp.withAddon("postgres", "disabled").envPrefix = "PG"
	dir := deployFixture(t, "name: demo\napp: app-1\naddons:\n  postgres:\n    env_prefix: DATABASE\n")
	stdout, stderr, err := runDeploy(t, dir)
	if err != nil {
		t.Fatalf("a running app's deploy must go on: %v\n%s", err, stderr)
	}
	mustNotCall(t, fp, "no add-on write", isAddonWrite)
	// On stdout, with the rest of the progress: the MCP deploy tool returns
	// stdout to the agent and nothing else.
	for _, want := range []string{`"disabled"`, "cdnctl container addons enable-postgres --app app-1", "env_prefix PG", "cdnctl.yaml says DATABASE"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the warning must say %q on stdout:\n%s", want, stdout)
		}
	}
	if fp.count(fakeDeployCall) != 1 {
		t.Fatalf("deploy missing: %v", fp.recorded())
	}

	// Before a first deploy the same state stops it: the app would start without
	// what it declares.
	fp2, _ := newFakePlatform(t)
	fp2.exists = true // created earlier, never deployed
	fp2.withAddon("postgres", "failed")
	dir2 := deployFixture(t, "name: demo\napp: app-1\naddons:\n  postgres: true\n")
	_, stderr2, err := runDeploy(t, dir2)
	if exitCode(err) != 1 {
		t.Fatalf("want exit 1, got %v", err)
	}
	mustNotCall(t, fp2, "no add-on write", isAddonWrite)
	if fp2.count(fakeDeployCall) != 0 {
		t.Fatalf("the first deploy must not start: %v", fp2.recorded())
	}
	if !strings.Contains(stderr2, "was not deployed") {
		t.Errorf("the message must say the app was not deployed:\n%s", stderr2)
	}
}

// An add-on somebody else is already provisioning is waited for, not enabled again.
func TestDeployWaitsForAnAddonAlreadyBeingProvisioned(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.exists = true
	pending := fp.withAddon("redis", "pending")
	pending.enabled, pending.activeAt, pending.readyAt = true, 2, 3
	dir := deployFixture(t, "name: demo\napp: app-1\naddons: [redis]\n")

	if stdout, stderr, err := runDeploy(t, dir); err != nil {
		t.Fatalf("deploy failed: %v\n%s\n%s", err, stdout, stderr)
	}
	mustNotCall(t, fp, "no add-on write", isAddonWrite)
	if !reflect.DeepEqual(fp.addonsAtDeploy, []string{"redis:active:true"}) {
		t.Fatalf("the deploy went out before the add-on was ready: %v", fp.addonsAtDeploy)
	}
}

func TestDeployStopsBeforeTheFirstDeployWhenAnAddonCannotBeProvided(t *testing.T) {
	t.Run("the API refuses", func(t *testing.T) {
		fp, _ := newFakePlatform(t)
		fp.addonRefusal["postgres"] = "Your plan includes 1 database add-on, and it is in use."
		dir := deployFixture(t, "name: demo\naddons:\n  postgres: true\n")

		_, stderr, err := runDeploy(t, dir)
		if exitCode(err) != 1 {
			t.Fatalf("want exit 1, got %v", err)
		}
		if fp.count(fakeDeployCall) != 0 {
			t.Fatalf("the first deploy must not start without its database: %v", fp.recorded())
		}
		for _, want := range []string{"postgres", "Your plan includes 1 database add-on", "was not deployed", "cdnctl deploy"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("the message must say %q:\n%s", want, stderr)
			}
		}
		// The app exists and is recorded, so the next `cdnctl deploy` continues with it.
		if got := readManifestValue(dir, "app"); got != "app-1" {
			t.Fatalf("app id not recorded: %q", got)
		}
	})

	t.Run("provisioning fails", func(t *testing.T) {
		fp, _ := newFakePlatform(t)
		fp.addonActiveAfter = 5
		fp.addonFails["postgres"] = "PVC could not be bound"
		dir := deployFixture(t, "name: demo\naddons:\n  postgres: true\n")

		_, stderr, err := runDeploy(t, dir)
		if exitCode(err) != 1 {
			t.Fatalf("want exit 1, got %v", err)
		}
		if fp.count(fakeDeployCall) != 0 {
			t.Fatalf("the first deploy must not start: %v", fp.recorded())
		}
		if !strings.Contains(stderr, "PVC could not be bound") {
			t.Errorf("the platform's reason must be shown:\n%s", stderr)
		}
	})
}

// A deploy-only token reaches the deploy surface and nothing else. With add-ons
// declared for a new app it cannot do the job, and says so before the upload.
func TestDeployTokenIsToldBeforeTheBuildThatItCannotEnableAddons(t *testing.T) {
	fp, _ := newFakePlatform(t)
	t.Setenv("CDNCTL_TOKEN", "cdnctl_deploy_only")
	dir := deployFixture(t, "name: demo\naddons:\n  postgres: true\n")

	_, stderr, err := runDeploy(t, dir)
	if exitCode(err) != 1 {
		t.Fatalf("want exit 1, got %v", err)
	}
	if !strings.Contains(stderr, "deploy token") || !strings.Contains(stderr, "`cdnctl login`") || !strings.Contains(stderr, "postgres") {
		t.Errorf("the refusal must name the token, the add-on and the way out:\n%s", stderr)
	}
	for _, call := range fp.recorded() {
		if strings.Contains(call, "source/") || call == "POST apps" {
			t.Fatalf("nothing may be uploaded or created: %v", fp.recorded())
		}
	}
}

// Once the add-ons exist, a deploy-only token deploys as before: it can read the
// app, and there is nothing left to enable.
func TestDeployTokenDeploysWhenTheDeclaredAddonsAlreadyExist(t *testing.T) {
	fp, _ := newFakePlatform(t)
	t.Setenv("CDNCTL_TOKEN", "cdnctl_deploy_only")
	fp.existingApp()
	fp.withAddon("postgres", "active")
	dir := deployFixture(t, "name: demo\napp: app-1\naddons:\n  postgres: true\n")

	// A cdnctl_ token is routed to the deploy-token surface.
	fp.prefix = "/api/deploy-token/accounts/acct-1/platform/container/"
	if stdout, said, err := runDeploy(t, dir); err != nil {
		t.Fatalf("deploy failed: %v\n%s\n%s", err, stdout, said)
	}
	mustNotCall(t, fp, "no add-on write", isAddonWrite)
	if fp.count(fakeDeployCall) != 1 {
		t.Fatalf("deploy missing: %v", fp.recorded())
	}

	// ... and when one is missing it says so instead of sending a request the
	// deploy surface does not have, before the archive is uploaded and built.
	fp2, _ := newFakePlatform(t)
	t.Setenv("CDNCTL_TOKEN", "cdnctl_deploy_only")
	fp2.prefix = "/api/deploy-token/accounts/acct-1/platform/container/"
	fp2.existingApp()
	fp2.withAddon("postgres", "active")
	dir2 := deployFixture(t, "name: demo\napp: app-1\naddons:\n  postgres: true\n  redis: true\n")
	_, said, err := runDeploy(t, dir2)
	if exitCode(err) != 1 || !strings.Contains(said, "deploy token") || !strings.Contains(said, "(redis)") {
		t.Fatalf("want exit 1 naming the token and only the missing add-on, got %v: %s", err, said)
	}
	if calls := fp2.recorded(); !reflect.DeepEqual(calls, []string{fakeShowCall}) {
		t.Fatalf("one read of the app, then nothing: no upload, no build, no add-on write, no deploy: %v", calls)
	}
}

// The MCP deploy tool runs the same command. stdout belongs to the protocol, so
// the progress, add-on lines included, has to arrive inside the tool result.
func TestMcpDeployToolCarriesTheAddonSteps(t *testing.T) {
	fp, _ := newFakePlatform(t)
	dir := deployFixture(t, "name: demo\naddons:\n  redis: true\n")

	var result any
	var rerr *rpcError
	stdout, _, _ := captureOutput(t, func() error {
		result, rerr = mcpCallTool("deploy", mcpArgs{Dir: dir, Account: "acct-1", Health: "none"})
		return nil
	})
	if rerr != nil {
		t.Fatalf("rpc error: %+v", rerr)
	}
	if stdout != "" {
		t.Fatalf("the tool must not write to the protocol stream: %q", stdout)
	}
	out, _ := result.(map[string]any)
	if out["succeeded"] != true {
		t.Fatalf("deploy tool failed: %#v", out)
	}
	log, _ := out["log"].(string)
	for _, want := range []string{"→ enabling add-on: redis", "✓ LIVE: https://demo.cdn.com.tr", "Revision   1"} {
		if !strings.Contains(log, want) {
			t.Errorf("tool log is missing %q:\n%s", want, log)
		}
	}
	if redis, deploy := fp.indexOf("POST apps/app-1/addons/redis"), fp.indexOf(fakeDeployCall); !(redis >= 0 && redis < deploy) {
		t.Fatalf("add-on before deploy: %v", fp.recorded())
	}

	// A failed revision reaches the agent as succeeded=false with the reason in the log.
	fp2, _ := newFakePlatform(t)
	fp2.failsWith = "CrashLoopBackOff: back-off 10s restarting failed container=app"
	dir2 := deployFixture(t, "name: demo\n")
	_, _, _ = captureOutput(t, func() error {
		result, rerr = mcpCallTool("deploy", mcpArgs{Dir: dir2, Account: "acct-1", Health: "none"})
		return nil
	})
	out, _ = result.(map[string]any)
	if out["succeeded"] != false {
		t.Fatalf("a failed revision must not be reported as success: %#v", out)
	}
	if log, _ := out["log"].(string); !strings.Contains(log, "CrashLoopBackOff") || !strings.Contains(log, "cdnctl container apps logs --app app-1") {
		t.Errorf("the reason and the logs command must be in the tool log:\n%s", log)
	}

	// A declared add-on the app has but cannot use (disabled) does not stop the
	// release of a running app; the agent still has to hear about it.
	fp3, _ := newFakePlatform(t)
	fp3.existingApp()
	fp3.withAddon("postgres", "disabled")
	dir3 := deployFixture(t, "name: demo\napp: app-1\naddons:\n  postgres: true\n")
	_, _, _ = captureOutput(t, func() error {
		result, rerr = mcpCallTool("deploy", mcpArgs{Dir: dir3, Account: "acct-1", Health: "none"})
		return nil
	})
	out, _ = result.(map[string]any)
	if log, _ := out["log"].(string); out["succeeded"] != true || !strings.Contains(log, `"disabled"`) || !strings.Contains(log, "enable-postgres --app app-1") {
		t.Errorf("the add-on warning must reach the agent in the tool log: %#v", out)
	}
}

// init sees a database client among the dependencies, says so, and leaves the
// decision in the file as a comment: an add-on is billed, and the same client may
// point at a database hosted elsewhere.
func TestInitPointsAtAddonsTheDependenciesAskFor(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"node", map[string]string{"package.json": `{"name":"api","dependencies":{"express":"^4","pg":"^8","ioredis":"^5"},"scripts":{"mysql":"docker run mysql"}}`}, []string{"postgres", "redis"}},
		{"python requirements", map[string]string{"requirements.txt": "flask==3.0\npsycopg2-binary>=2.9\n# redis\nredis[hiredis]==5.0\n"}, []string{"postgres", "redis"}},
		{"pyproject", map[string]string{"pyproject.toml": "[project]\nname = \"redis\"\ndependencies = [\n  \"fastapi\",\n  \"asyncpg>=0.29\",\n]\n"}, []string{"postgres"}},
		{"go", map[string]string{"go.mod": "module x\n\nrequire (\n\tgithub.com/jackc/pgx/v5 v5.5.0\n\tgithub.com/nats-io/nats.go v1.31.0\n)\n"}, []string{"postgres", "nats"}},
		{"php", map[string]string{"composer.json": `{"require":{"php":"^8.2","ext-pdo_mysql":"*","predis/predis":"^2"}}`}, []string{"mysql", "redis"}},
		{"an ORM alone names no database", map[string]string{"package.json": `{"dependencies":{"prisma":"^5","sequelize":"^6"}}`}, []string{}},
	}
	// The same project names the same evidence on every run.
	both := writeFixture(t, map[string]string{
		"package.json":  `{"dependencies":{"ioredis":"^5"}}`,
		"composer.json": `{"require":{"predis/predis":"^2"}}`,
	})
	for i := 0; i < 20; i++ {
		if needs := detectAddonNeeds(both); len(needs) != 1 || needs[0].Evidence != "ioredis in package.json" {
			t.Fatalf("run %d: evidence must be stable, got %+v", i, needs)
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeFixture(t, tc.files)
			got := []string{}
			for _, need := range detectAddonNeeds(dir) {
				got = append(got, need.Type)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}

	dir := writeFixture(t, map[string]string{"package.json": `{"name":"api","dependencies":{"pg":"^8","redis":"^4"}}`})
	if wrote, err := writeManifest(dir, detectProject(dir), "source"); err != nil || !wrote {
		t.Fatalf("writeManifest: %v %v", wrote, err)
	}
	manifest, _ := os.ReadFile(filepath.Join(dir, "cdnctl.yaml"))
	for _, want := range []string{"# addons:", "#   postgres: true", "#   redis: true", "pg in package.json", "DATABASE_URL", "REDIS_URL"} {
		if !strings.Contains(string(manifest), want) {
			t.Fatalf("manifest is missing %q:\n%s", want, manifest)
		}
	}
	// Commented means not declared: deploy provisions nothing until a person or
	// an agent removes the comment marks.
	if specs, err := readManifestAddons(dir); err != nil || len(specs) != 0 {
		t.Fatalf("a commented block must declare nothing: %+v, %v", specs, err)
	}
	kinds, phrase := undeclaredAddonNeeds(dir)
	if !reflect.DeepEqual(kinds, []string{"postgres", "redis"}) || !strings.Contains(phrase, "postgres (pg in package.json)") {
		t.Fatalf("undeclared needs: %v %q", kinds, phrase)
	}
	// Uncommented, the block is exactly what deploy reads, and the note goes away.
	uncommented := strings.ReplaceAll(strings.ReplaceAll(string(manifest), "# addons:", "addons:"), "#   ", "  ")
	if err := os.WriteFile(filepath.Join(dir, "cdnctl.yaml"), []byte(uncommented), 0o644); err != nil {
		t.Fatal(err)
	}
	specs, err := readManifestAddons(dir)
	if err != nil || !reflect.DeepEqual(specs, []addonSpec{{Type: "postgres"}, {Type: "redis"}}) {
		t.Fatalf("the uncommented block must read as two add-ons: %+v, %v", specs, err)
	}
	if kinds, _ := undeclaredAddonNeeds(dir); len(kinds) != 0 {
		t.Fatalf("declared add-ons must not be suggested again: %v", kinds)
	}
	// "false" is an answer too: the database lives elsewhere, stop suggesting it.
	declinedOne := strings.Replace(uncommented, "  postgres: true", "  postgres: false", 1)
	if err := os.WriteFile(filepath.Join(dir, "cdnctl.yaml"), []byte(declinedOne), 0o644); err != nil {
		t.Fatal(err)
	}
	if specs, err := readManifestAddons(dir); err != nil || !reflect.DeepEqual(specs, []addonSpec{{Type: "redis"}}) {
		t.Fatalf("postgres: false must declare only redis: %+v, %v", specs, err)
	}
	if kinds, _ := undeclaredAddonNeeds(dir); len(kinds) != 0 {
		t.Fatalf("an add-on declared off must not be suggested again: %v", kinds)
	}
	// The values deploy reads from the same file are untouched by the block.
	if readManifestValue(dir, "name") != "api" || readManifestValue(dir, "port") == "" {
		t.Fatalf("name/port no longer read:\n%s", uncommented)
	}

	// A project without such a dependency gets no block at all.
	plain := writeFixture(t, map[string]string{"package.json": `{"name":"site","dependencies":{"express":"^4"}}`})
	if _, err := writeManifest(plain, detectProject(plain), "source"); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(filepath.Join(plain, "cdnctl.yaml")); strings.Contains(string(raw), "addons") {
		t.Fatalf("no dependency, no block:\n%s", raw)
	}
}

// PyYAML writes a list at the key's column. Read as a new top-level key, the
// section declared nothing and a new app was deployed without its database.
func TestDeployReadsTheListPyYAMLWrites(t *testing.T) {
	fp, _ := newFakePlatform(t)
	dir := deployFixture(t, "name: demo\naddons:\n- postgres\n")

	if stdout, said, err := runDeploy(t, dir); err != nil {
		t.Fatalf("deploy failed: %v\n%s\n%s", err, stdout, said)
	}
	create, postgres, deploy := fp.indexOf("POST apps"), fp.indexOf("POST apps/app-1/addons/postgres"), fp.indexOf(fakeDeployCall)
	if !(create >= 0 && create < postgres && postgres < deploy) {
		t.Fatalf("want create -> postgres -> deploy, got %v", fp.recorded())
	}
}

// An app that already gets its database from another app reads it through
// ${app.VAR} references (a prod app on a shared database, a preprod on prod's).
// A new add-on would take over those variables the moment it became active and
// move the running app onto an empty database. cdnctl says so and leaves it.
func TestDeployLeavesAnAddonTheAppAlreadyGetsElsewhere(t *testing.T) {
	t.Run("references to another app", func(t *testing.T) {
		fp, _ := newFakePlatform(t)
		fp.existingApp()
		fp.environment = "prod"
		fp.env = map[string]any{
			"APP_URL":           "https://api.example.com",
			"DATABASE_URL":      "${web.DATABASE_URL}",
			"DATABASE_HOST":     "${web.DATABASE_HOST}",
			"DATABASE_USER":     "${web.DATABASE_USER}",
			"DATABASE_PASSWORD": "${web.DATABASE_PASSWORD}",
		}
		dir := deployFixture(t, "name: demo\napp: app-1\naddons:\n  postgres: true\n")

		stdout, said, err := runDeploy(t, dir)
		if err != nil {
			t.Fatalf("the deploy must go on: %v\n%s\n%s", err, stdout, said)
		}
		mustNotCall(t, fp, "no add-on write", isAddonWrite)
		if fp.count(fakeDeployCall) != 1 || len(fp.ownerRolls) != 0 {
			t.Fatalf("one deploy, no roll onto a new database: %v %v", fp.recorded(), fp.ownerRolls)
		}
		for _, want := range []string{"add-on postgres: not enabled", "DATABASE_URL=${…}", "`cdnctl container addons enable-postgres --app app-1`"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("the note must say %q:\n%s", want, stdout)
			}
		}
		if strings.Contains(stdout, "web.DATABASE") {
			t.Errorf("only variable names are printed, never values:\n%s", stdout)
		}
	})

	t.Run("its own connection secret", func(t *testing.T) {
		// A second database under another prefix would still take DATABASE_URL:
		// postgres and mysql always set it.
		fp, _ := newFakePlatform(t)
		fp.existingApp()
		fp.secretKeys = []string{"DATABASE_URL", "STRIPE_KEY"}
		dir := deployFixture(t, "name: demo\napp: app-1\naddons:\n  postgres:\n    env_prefix: ANALYTICS\n  redis: true\n")

		stdout, said, err := runDeploy(t, dir)
		if err != nil {
			t.Fatalf("the deploy must go on: %v\n%s\n%s", err, stdout, said)
		}
		var writes []string
		for _, call := range fp.recorded() {
			if isAddonWrite(call) {
				writes = append(writes, call)
			}
		}
		if !reflect.DeepEqual(writes, []string{"POST apps/app-1/addons/redis"}) {
			t.Fatalf("redis has nothing to replace and is enabled; postgres is not: %v", writes)
		}
		if !strings.Contains(stdout, "the app already has DATABASE_URL,") {
			t.Errorf("the note must name the variable:\n%s", stdout)
		}
	})

	t.Run("a preprod that shares production's data", func(t *testing.T) {
		// The panel refuses such a preprod an add-on of its own (422), after the
		// upload and the build. cdnctl knows from the app and does not ask.
		fp, _ := newFakePlatform(t)
		fp.existingApp()
		fp.environment = "preprod"
		fp.promotionMeta = map[string]any{"data_sharing": "shared"}
		dir := deployFixture(t, "name: demo\napp: app-1\naddons:\n  postgres: true\n  redis: true\n")

		stdout, said, err := runDeploy(t, dir)
		if err != nil {
			t.Fatalf("the preprod's deploy must go on: %v\n%s\n%s", err, stdout, said)
		}
		mustNotCall(t, fp, "no add-on write", isAddonWrite)
		if fp.count(fakeDeployCall) != 1 {
			t.Fatalf("deploy missing: %v", fp.recorded())
		}
		for _, want := range []string{"add-on postgres: not enabled", "add-on redis: not enabled", "data_sharing=shared"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("the note must say %q:\n%s", want, stdout)
			}
		}
	})
}

// Someone deleted the add-on. On an app that is deployed, a new one would start
// empty and take over its connection: said, not done. An app that never ran gets
// it like a new app does.
func TestDeployDoesNotRecreateADeletedAddonOnADeployedApp(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.existingApp()
	fp.withAddon("postgres", "deleted")
	dir := deployFixture(t, "name: demo\napp: app-1\naddons:\n  postgres: true\n")

	stdout, said, err := runDeploy(t, dir)
	if err != nil {
		t.Fatalf("the deploy must go on: %v\n%s\n%s", err, stdout, said)
	}
	mustNotCall(t, fp, "no add-on write", isAddonWrite)
	for _, want := range []string{"postgres add-on declared in cdnctl.yaml was deleted", "`cdnctl container addons enable-postgres --app app-1`"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the warning must say %q:\n%s", want, stdout)
		}
	}

	fp2, _ := newFakePlatform(t)
	fp2.exists = true // created earlier, never deployed
	fp2.withAddon("postgres", "deleted")
	dir2 := deployFixture(t, "name: demo\napp: app-1\naddons:\n  postgres: true\n")
	if stdout, said, err := runDeploy(t, dir2); err != nil {
		t.Fatalf("deploy failed: %v\n%s\n%s", err, stdout, said)
	}
	if postgres, deploy := fp2.indexOf("POST apps/app-1/addons/postgres"), fp2.indexOf(fakeDeployCall); !(postgres >= 0 && postgres < deploy) {
		t.Fatalf("a first deploy gets the add-on first: %v", fp2.recorded())
	}
}

// The panel answers 200 without runtime.addons when its own call to the cluster
// failed. That look says nothing about the database's pod: it is not a "ready".
func TestDeployWaitsForTheAddonPodWhenTheClusterDidNotAnswer(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.addonReadyAfter = 2 // active at once, the pod answers on the second read
	fp.runtimeGaps = 1     // the first read after the enable has no runtime.addons
	dir := deployFixture(t, "name: demo\naddons:\n  postgres: true\n")

	if stdout, said, err := runDeploy(t, dir); err != nil {
		t.Fatalf("deploy failed: %v\n%s\n%s", err, stdout, said)
	}
	if !reflect.DeepEqual(fp.addonsAtDeploy, []string{"postgres:active:true"}) {
		t.Fatalf("the deploy went out before the database answered: %v", fp.addonsAtDeploy)
	}
}

// A refused image update leaves the old image in place. Deploying after it would
// roll the old image out again and report it live.
func TestDeployStopsWhenTheNewImageIsRefused(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.existingApp()
	fp.patchStatus = 422
	fp.patchRefusal = "The image reference is not valid."
	dir := deployFixture(t, "name: demo\napp: app-1\n")

	_, said, err := runDeploy(t, dir)
	if exitCode(err) != 1 {
		t.Fatalf("want exit 1, got %v", err)
	}
	if fp.count(fakeDeployCall) != 0 {
		t.Fatalf("no deploy after a refused update: %v", fp.recorded())
	}
	if !strings.Contains(said, "The new image was not applied: The image reference is not valid.") {
		t.Fatalf("the refusal must be shown: %s", said)
	}
}
