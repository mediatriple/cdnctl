package main

import (
	"strings"
	"testing"
	"time"
)

const fakeDeployCall = "POST apps/app-1/deploy"
const fakeShowCall = "GET apps/app-1"

func appsDeploy(extra ...string) []string {
	return append([]string{"container", "apps", "deploy", "--account", "acct-1", "--app", "app-1"}, extra...)
}

// The command used to print "queued" and return. It now follows the revision it
// created until that revision serves, and says so in one object.
func TestAppsDeployWaitsForTheNewRevisionAndReportsIt(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.existingApp()
	fp.readyAfter = 2

	stdout, stderr, err := captureOutput(t, func() error { return run(appsDeploy()) })
	if err != nil {
		t.Fatalf("a deploy that comes up must exit 0, got %v\nstderr: %s", err, stderr)
	}
	if got := fp.count(fakeShowCall); got != 3 {
		t.Fatalf("want 3 reads of the app (2 not ready, 1 ready), got %d: %v", got, fp.recorded())
	}

	out := oneJSONObject(t, stdout)
	for key, want := range map[string]any{
		"status":          "success",
		"outcome":         "running",
		"waited":          true,
		"app_status":      "running",
		"runtime_status":  "running",
		"revision_number": float64(2),
		"operation_uuid":  "op-2",
		"url":             "https://demo.cdn.com.tr",
	} {
		if out[key] != want {
			t.Errorf("%s = %#v, want %#v", key, out[key], want)
		}
	}
	// The keys of the API's 202 answer stay where a script reads them.
	if revision, _ := out["revision"].(map[string]any); revision["uuid"] != "rev-2" || revision["revision_number"] != float64(2) {
		t.Errorf("revision must stay the revision object of this deploy: %#v", out["revision"])
	}
	if app, _ := out["app"].(map[string]any); app["uuid"] != "app-1" || app["status"] != "running" {
		t.Errorf("app must be the app as the wait left it: %#v", out["app"])
	}
	if operation, _ := out["operation"].(map[string]any); operation["uuid"] != "op-2" {
		t.Errorf("operation must be this deploy's operation: %#v", out["operation"])
	}
	if _, ok := out["runtime"].(map[string]any); !ok {
		t.Errorf("runtime is missing: %#v", out)
	}
	for _, key := range []string{"reason", "logs_command"} {
		if _, present := out[key]; present {
			t.Errorf("%s belongs to a deploy that did not come up", key)
		}
	}
	if out["_http_status"] != float64(202) {
		t.Errorf("_http_status of the deploy call must survive: %#v", out["_http_status"])
	}
}

// --no-wait is the command as it was: the API's answer, no look at the app, exit 0.
func TestAppsDeployNoWaitPrintsTheQueuedAnswerAndReturns(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.existingApp()
	fp.failsWith = "CrashLoopBackOff: back-off 40s restarting failed container"

	stdout, _, err := captureOutput(t, func() error { return run(appsDeploy("--no-wait")) })
	if err != nil {
		t.Fatalf("--no-wait must not judge the deploy: %v", err)
	}
	if calls := fp.recorded(); len(calls) != 1 || calls[0] != fakeDeployCall {
		t.Fatalf("--no-wait must send the deploy and nothing else: %v", calls)
	}
	out := oneJSONObject(t, stdout)
	if out["message"] != "Container app deploy queued." || out["_http_status"] != float64(202) {
		t.Fatalf("--no-wait must print the API's own answer: %#v", out)
	}
	if _, waited := out["outcome"]; waited {
		t.Fatalf("--no-wait has no outcome to report: %#v", out)
	}
}

func TestAppsDeployExitsNonZeroWhenTheRevisionFails(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.existingApp()
	fp.failsWith = "CrashLoopBackOff: back-off 40s restarting failed container=app"

	stdout, _, err := captureOutput(t, func() error { return run(appsDeploy()) })
	if exitCode(err) != 1 {
		t.Fatalf("a failed revision must exit 1, got %v", err)
	}
	out := oneJSONObject(t, stdout)
	if out["status"] != "error" || out["outcome"] != "failed" || out["app_status"] != "failed" {
		t.Fatalf("failure not reported: %#v", out)
	}
	if out["reason"] != fp.failsWith {
		t.Fatalf("reason = %#v, want the platform's own words", out["reason"])
	}
	if got, _ := out["logs_command"].(string); got != "cdnctl container apps logs --account acct-1 --app app-1 --tail 100" {
		t.Fatalf("logs_command = %q", got)
	}
	// "failed" is believed once it has held for about a minute of looks.
	if got := fp.count(fakeShowCall); got != failedLooksToBelieve {
		t.Fatalf("want %d reads before calling it failed, got %d", failedLooksToBelieve, got)
	}
}

// A container that crashes twice while a dependency warms up and starts on its
// third try is in CrashLoopBackOff, and "failed" in the panel, during both
// back-offs. That is a deploy coming up, not one that failed.
func TestAppsDeployWaitsOutACrashThatRecovers(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.existingApp()
	fp.failsWith = "CrashLoopBackOff: back-off 20s restarting failed container=app"
	fp.failsFor = 3

	stdout, _, err := captureOutput(t, func() error { return run(appsDeploy()) })
	if err != nil {
		t.Fatalf("an app that comes up on its third start must exit 0, got %v\n%s", err, stdout)
	}
	if out := oneJSONObject(t, stdout); out["outcome"] != "running" {
		t.Fatalf("outcome: %#v", out)
	}
	if got := fp.count(fakeShowCall); got != 4 {
		t.Fatalf("three failed looks, then running: want 4 reads, got %d", got)
	}
}

// A short --timeout that ends while the revision keeps failing reports the
// failure, not a timeout.
func TestAppsDeployReportsAFailureThatOutlastsAShortTimeout(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.existingApp()
	fp.failsWith = "ImagePullBackOff: image not found"

	stdout, _, err := captureOutput(t, func() error { return run(appsDeploy("--timeout", "30")) })
	if exitCode(err) != 1 {
		t.Fatalf("want exit 1, got %v", err)
	}
	if out := oneJSONObject(t, stdout); out["outcome"] != "failed" || out["reason"] != fp.failsWith {
		t.Fatalf("want outcome failed with the reason: %#v", out)
	}
}

// The timeout is a time, not a number of looks: answers that take long end the
// wait at its deadline.
func TestAppsDeployWaitEndsAtItsDeadline(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.existingApp()
	fp.readyAfter = 1000
	fp.readTakes = 40 * time.Second // each read of the app takes 40 s

	stdout, _, err := captureOutput(t, func() error { return run(appsDeploy()) })
	if exitCode(err) != 1 {
		t.Fatalf("want exit 1, got %v", err)
	}
	// 300 s at 40 s a read: the eighth read starts at 280 s, and none after 300 s.
	if got := fp.count(fakeShowCall); got != 8 {
		t.Fatalf("want 8 reads inside 300 s, got %d (30 looks would be 1200 s)", got)
	}
	if out := oneJSONObject(t, stdout); out["outcome"] != "timeout" {
		t.Fatalf("outcome: %#v", out)
	}
}

// An app scaled to zero runs no pod after a deploy, by its owner's choice.
// Waiting for one ended in a five-minute timeout and exit 1.
func TestAppsDeployOnAnAppScaledToZero(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.existingApp()
	fp.scaledToZero = true

	stdout, _, err := captureOutput(t, func() error { return run(appsDeploy()) })
	if err != nil {
		t.Fatalf("a deploy recorded on a scaled-to-zero app must exit 0, got %v\n%s", err, stdout)
	}
	if got := fp.count(fakeShowCall); got != 1 {
		t.Fatalf("one read says it: got %d", got)
	}
	out := oneJSONObject(t, stdout)
	if out["status"] != "success" || out["outcome"] != "stopped" || out["revision_number"] != float64(2) {
		t.Fatalf("outcome: %#v", out)
	}
	if _, present := out["logs_command"]; present {
		t.Fatalf("nothing failed, so no logs command: %#v", out)
	}

	fp2, _ := newFakePlatform(t)
	fp2.existingApp()
	fp2.scaledToZero = true
	text, _, err := captureOutput(t, func() error { return deployAndReport("acct-1", "app-1", defaultDeployTimeout, false) })
	if err != nil || !strings.Contains(text, "scaled to 0 replicas") || !strings.Contains(text, "cdnctl container apps scale --app app-1 --replicas 1") {
		t.Fatalf("the text report must say why nothing runs and how to change it: %v\n%s", err, text)
	}
}

func TestAppsDeployExitsNonZeroOnTimeout(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.existingApp()
	fp.readyAfter = 1000

	stdout, _, err := captureOutput(t, func() error { return run(appsDeploy("--timeout", "30")) })
	if exitCode(err) != 1 {
		t.Fatalf("a timeout must exit 1, got %v", err)
	}
	if got := fp.count(fakeShowCall); got != 3 {
		t.Fatalf("--timeout 30 is three looks 10 s apart, got %d", got)
	}
	out := oneJSONObject(t, stdout)
	if out["status"] != "error" || out["outcome"] != "timeout" || out["app_status"] != "deploying" {
		t.Fatalf("timeout not reported: %#v", out)
	}
	if message, _ := out["message"].(string); !strings.Contains(message, "30 seconds") {
		t.Fatalf("message must say how long it waited: %q", message)
	}
	if _, ok := out["logs_command"]; !ok {
		t.Fatalf("a timeout needs the logs command too: %#v", out)
	}
}

// During a rolling update the old pod keeps serving and the Deployment says
// "running". That is not this deploy coming up.
func TestAppsDeployIsNotFooledByThePreviousRevisionStillServing(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.existingApp()
	fp.oldPodServes = true
	fp.readyAfter = 3

	stdout, _, err := captureOutput(t, func() error { return run(appsDeploy()) })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := fp.count(fakeShowCall); got != 4 {
		t.Fatalf("the wait must outlast the old pod: want 4 reads, got %d", got)
	}
	if out := oneJSONObject(t, stdout); out["outcome"] != "running" || out["revision_number"] != float64(2) {
		t.Fatalf("outcome: %#v", out)
	}

	// ... and when the new revision never comes up, the old pod serving is not success.
	fp2, _ := newFakePlatform(t)
	fp2.existingApp()
	fp2.oldPodServes = true
	fp2.failsWith = "ImagePullBackOff: image not found"
	_, _, err = captureOutput(t, func() error { return run(appsDeploy()) })
	if exitCode(err) != 1 {
		t.Fatalf("a revision that never came up must exit 1 even while the old pod serves, got %v", err)
	}
}

// Right after a deploy the panel may still be looking at the previous revision's
// pods. One "failed" look is not the new revision failing.
func TestAppsDeployDoesNotReportThePreviousRevisionsCrash(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.existingApp()
	fp.staleFailure = true
	fp.readyAfter = 2

	stdout, _, err := captureOutput(t, func() error { return run(appsDeploy()) })
	if err != nil {
		t.Fatalf("the redeploy that fixes a crash loop must not be reported as that crash: %v", err)
	}
	if out := oneJSONObject(t, stdout); out["outcome"] != "running" {
		t.Fatalf("outcome: %#v", out)
	}
}

func TestAppsDeployRefusedByTheApiExitsWithoutWaiting(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.existingApp()
	fp.deployStatus = 422
	fp.deployRefusal = "Complete the required import before deploying."

	stdout, _, err := captureOutput(t, func() error { return run(appsDeploy()) })
	if exitCode(err) != 1 {
		t.Fatalf("a refused deploy must exit 1, got %v", err)
	}
	if fp.count(fakeShowCall) != 0 {
		t.Fatalf("nothing was queued, so there is nothing to wait for: %v", fp.recorded())
	}
	// The API's own answer, with the outcome keys every other end carries.
	out := oneJSONObject(t, stdout)
	for key, want := range map[string]any{
		"status":       "error",
		"outcome":      "refused",
		"waited":       false,
		"reason":       fp.deployRefusal,
		"message":      fp.deployRefusal,
		"_http_status": float64(422),
	} {
		if out[key] != want {
			t.Errorf("%s = %#v, want %#v", key, out[key], want)
		}
	}
}

// The provisioner refusing a deploy is in the 202 answer. The next status read
// would find the old pods healthy and call the app running.
func TestAppsDeployReportsAProvisionerRefusalFromTheAnswer(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.existingApp()
	fp.provisionerNo = "Deployment is invalid: spec.template.spec.containers[0].image"

	stdout, _, err := captureOutput(t, func() error { return run(appsDeploy()) })
	if exitCode(err) != 1 {
		t.Fatalf("want exit 1, got %v", err)
	}
	out := oneJSONObject(t, stdout)
	if out["outcome"] != "failed" || out["reason"] != fp.provisionerNo {
		t.Fatalf("provisioner refusal not reported: %#v", out)
	}
	if fp.count(fakeShowCall) != 0 {
		t.Fatalf("the answer was final; no read needed: %v", fp.recorded())
	}
}

// The deploy was queued and the app could not be read afterwards (the session
// ended during the wait): a program still gets its one object, and exit 1.
func TestAppsDeployJSONReportsAnUnreadableEndAsOneObject(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.existingApp()
	fp.readStatus = 401

	stdout, _, err := captureOutput(t, func() error { return run(appsDeploy("--json")) })
	if exitCode(err) != 1 {
		t.Fatalf("an unreadable end must exit 1, got %v", err)
	}
	if got := fp.count(fakeShowCall); got != 1 {
		t.Fatalf("a refused read ends the wait at once, got %d reads", got)
	}
	out := oneJSONObject(t, stdout)
	for key, want := range map[string]any{
		"status":          "error",
		"outcome":         "unknown",
		"waited":          true,
		"revision_number": float64(2),
		"operation_uuid":  "op-2",
		"reason":          "Unauthenticated.",
		"logs_command":    "cdnctl container apps logs --account acct-1 --app app-1 --tail 100",
	} {
		if out[key] != want {
			t.Errorf("%s = %#v, want %#v", key, out[key], want)
		}
	}
	if revision, _ := out["revision"].(map[string]any); revision["uuid"] != "rev-2" {
		t.Errorf("revision must stay the revision object of this deploy: %#v", out["revision"])
	}
}

// What a person sees: the state, the revision, and when it failed the reason and
// where the logs are.
func TestDeployReportForAPerson(t *testing.T) {
	fp, _ := newFakePlatform(t)
	fp.existingApp()
	fp.readyAfter = 1

	stdout, _, err := captureOutput(t, func() error { return deployAndReport("acct-1", "app-1", defaultDeployTimeout, false) })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"→ waiting for the app to come up", "✓ LIVE: https://demo.cdn.com.tr", "State      running", "Revision   2"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("success report is missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "{") {
		t.Errorf("a terminal gets text, not JSON:\n%s", stdout)
	}

	fp2, _ := newFakePlatform(t)
	fp2.existingApp()
	fp2.failsWith = "CrashLoopBackOff: back-off 40s restarting failed container=app"
	stdout, _, err = captureOutput(t, func() error { return deployAndReport("acct-1", "app-1", defaultDeployTimeout, false) })
	if exitCode(err) != 1 {
		t.Fatalf("want exit 1, got %v", err)
	}
	for _, want := range []string{
		"✗ The deploy failed", "State      failed", "Revision   2",
		"Reason     CrashLoopBackOff: back-off 40s restarting failed container=app",
		"cdnctl container apps logs --app app-1",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("failure report is missing %q:\n%s", want, stdout)
		}
	}

	fp3, _ := newFakePlatform(t)
	fp3.existingApp()
	fp3.readyAfter = 1000
	stdout, _, err = captureOutput(t, func() error { return deployAndReport("acct-1", "app-1", 20, false) })
	if exitCode(err) != 1 {
		t.Fatalf("want exit 1, got %v", err)
	}
	for _, want := range []string{"✗ Timed out after 20 seconds", "State      deploying", "cdnctl container apps logs --app app-1", "cdnctl container apps show --app app-1"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("timeout report is missing %q:\n%s", want, stdout)
		}
	}
}

// An API that does not say which revision a pod runs leaves the Deployment's own
// verdict, which is what the wait used before.
func TestRolloutFallsBackToTheDeploymentVerdictWithoutRevisionData(t *testing.T) {
	bare := map[string]any{"app": map[string]any{"status": "running"}, "runtime": map[string]any{"runtime_status": "running"}}
	if !rolloutIsUp(bare, 7) {
		t.Fatal("running with no pod data must count as up")
	}
	if rolloutIsUp(map[string]any{"runtime": map[string]any{"runtime_status": "deploying"}}, 7) {
		t.Fatal("deploying is not up")
	}
	// The cluster still on the previous revision: not this deploy.
	behind := map[string]any{"runtime": map[string]any{"runtime_status": "running", "current_revision": map[string]any{"revision_number": "6"}}}
	if rolloutIsUp(behind, 7) {
		t.Fatal("a Deployment still on revision 6 has not rolled out revision 7")
	}
	// A pod without its own revision number is judged by the current-ReplicaSet flag.
	flagged := map[string]any{"runtime": map[string]any{"runtime_status": "running", "pods": []any{
		map[string]any{"phase": "Running", "current": false, "containers": []any{map[string]any{"ready": true}}},
		map[string]any{"phase": "Running", "current": true, "containers": []any{map[string]any{"ready": false}}},
	}}}
	if rolloutIsUp(flagged, 7) {
		t.Fatal("only the old ReplicaSet's pod is ready")
	}
	// Every replica of the new revision has to be ready, not the first one.
	two := map[string]any{"runtime": map[string]any{"runtime_status": "running", "replicas": float64(2), "pods": []any{
		map[string]any{"phase": "Running", "revision_number": "7", "containers": []any{map[string]any{"ready": true}}},
		map[string]any{"phase": "Running", "revision_number": "7", "containers": []any{map[string]any{"ready": false}}},
	}}}
	if rolloutIsUp(two, 7) {
		t.Fatal("one of two replicas ready is a rollout in progress")
	}
}

// `apps show` printed the state of the app's FIRST revision: the payload lists
// every revision oldest first. An app whose first deploy failed (before its
// database existed) read "failed" forever while it was running.
func TestAppStateIsTheAppsOwnStatus(t *testing.T) {
	app := map[string]any{
		"status": "running",
		"revisions": []any{
			map[string]any{"revision_number": float64(1), "status": "failed"},
			map[string]any{"revision_number": float64(2), "status": "running"},
		},
	}
	if got := appState(app); got != "running" {
		t.Fatalf("appState = %q, want the app's own status", got)
	}
	if hint := failureHint(app); hint != "" {
		t.Fatalf("a running app must not get the failure hint: %q", hint)
	}
}
