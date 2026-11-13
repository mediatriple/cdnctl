package main

// What happens after "deploy queued": the wait and the report that `cdnctl deploy`
// and `cdnctl container apps deploy` share.
//
// `container apps deploy` used to print the API's 202 and return. A customer whose
// app had been crash-looping ran it, got "queued", looked at the app and found the
// old pod's log and a panel still saying "deploying" (2026-11-12): the new pod had
// started correctly and nothing told them. The panel learns an app's state when it
// is asked, so the wait is also what moves the app out of "deploying".
//
// The wait judges the revision this deploy created. A Deployment reports "running"
// as soon as enough pods are ready, and during a rolling update those are the old
// revision's pods: an app that was healthy before the deploy would be called live
// on the first look, whatever happens to the new image a few seconds later.

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// deployPollInterval is the pause between two looks at the app. A wait ends at the
// first of two limits: its looks (the timeout divided by deployPollSeconds), which
// lets a test shorten the pause without changing how often the API is asked, and
// its deadline on the clock, which keeps slow answers from stretching a five-minute
// wait into twenty.
var deployPollInterval = deployPollSeconds * time.Second

// clock is time.Now; a test moves it to reach a deadline without waiting for it.
var clock = time.Now

const (
	deployPollSeconds = 10
	// 30 looks, 10 s apart: the window `cdnctl deploy` has always given a rollout.
	defaultDeployTimeout = 300

	// failedLooksToBelieve: how many looks in a row "failed" has to hold before
	// the wait gives up early. Six looks is about a minute: a container that
	// crashes while a dependency warms up goes through the kubelet's 10 s and
	// 20 s back-offs and starts on its third try inside that minute, and the
	// panel says "failed" during each back-off.
	failedLooksToBelieve = 6

	rolloutRunning = "running"
	rolloutFailed  = "failed"
	rolloutTimeout = "timeout"
	// The deploy was queued and then the app could not be read (the session
	// ended, the app was deleted): only `container apps deploy --json` reports it,
	// so that a program still gets its one object.
	rolloutUnknown = "unknown"
	// The app is scaled to zero replicas: the revision is recorded and nothing is
	// meant to run. Waiting for a pod would only end in a timeout.
	rolloutStopped = "stopped"
	// The API did not accept the deploy: nothing was queued.
	rolloutRefused = "refused"
)

// pauseBeforeNextLook sleeps until the next look and reports whether the deadline
// leaves time for one. The last pause is cut short so the final look is at the
// deadline, not after it.
func pauseBeforeNextLook(deadline time.Time) bool {
	remaining := deadline.Sub(clock())
	if remaining <= 0 {
		return false
	}
	pause := deployPollInterval
	if pause > remaining {
		pause = remaining
	}
	time.Sleep(pause)
	return true
}

// succeeded: the deploy did what was asked. A revision recorded on an app scaled
// to zero is that too.
func (outcome rolloutOutcome) succeeded() bool {
	return outcome.State == rolloutRunning || outcome.State == rolloutStopped
}

// rolloutOutcome is how a deploy ended, in the terms both commands report.
type rolloutOutcome struct {
	State         string // running | failed | timeout | unknown | stopped
	AppStatus     string // the panel's verdict: running, deploying, failed, ...
	RuntimeStatus string // the Deployment's own state
	Revision      int    // the revision this deploy created; 0 when the API did not say
	Reason        string
	Domain        string
	Seconds       int            // how long the wait was allowed to take
	Show          map[string]any // the last app payload read
}

func childMap(node map[string]any, key string) map[string]any {
	child, _ := node[key].(map[string]any)
	return child
}

// intFrom reads a number the API may send as a JSON number or as a string (the
// cluster's annotations are strings).
func intFrom(value any) (int, bool) {
	switch v := value.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n, true
		}
	}
	return 0, false
}

// apiFailure reports a call the API refused, or one that never arrived, in the API's
// own words. requestJSON returns no error for either: it hands back the body.
func apiFailure(resp map[string]any) (string, bool) {
	status := httpStatusOf(resp)
	transport := status == 0 && resp["http_status"] != nil && resp["error"] != nil
	if status < 400 && !transport {
		return "", false
	}
	// A validation refusal carries the sentence to act on under errors; its
	// message is often the generic "The given data was invalid."
	if errs, ok := resp["errors"].(map[string]any); ok {
		fields := make([]string, 0, len(errs))
		for field := range errs {
			fields = append(fields, field)
		}
		sort.Strings(fields)
		for _, field := range fields {
			if list, ok := errs[field].([]any); ok && len(list) > 0 {
				if text := strval(list[0]); text != "" {
					return terminalSafe(text), true
				}
			}
		}
	}
	fallback := T("unexpected response from the API")
	if status >= 400 {
		fallback = fmt.Sprintf("HTTP %d", status)
	}
	return terminalSafe(firstString(resp, "message", "error", fallback)), true
}

// startDeploy asks the panel for a new revision. An answer that is a refusal (a
// required import not finished, an app that is gone) ends the command here: waiting
// five minutes for a deploy that was never queued tells nobody anything.
func startDeploy(account, appUUID string) (map[string]any, error) {
	queued, err := requestJSON(http.MethodPost,
		fmt.Sprintf("accounts/%s/platform/container/apps/%s/deploy", account, appUUID),
		map[string]any{})
	if err != nil {
		return nil, err
	}
	if reason, failed := apiFailure(queued); failed {
		return queued, errExitMessage(1, fmt.Sprintf(T("The deploy was not accepted: %s"), reason))
	}
	return queued, nil
}

// deployRevisionNumber reads which revision a deploy answer created.
func deployRevisionNumber(queued map[string]any) int {
	if n, ok := intFrom(childMap(queued, "revision")["revision_number"]); ok {
		return n
	}
	if n, ok := intFrom(childMap(childMap(queued, "operation"), "input")["revision"]); ok {
		return n
	}
	return 0
}

// runtimeStatusOf reads the Deployment's state from an app payload. Older payloads
// carried it elsewhere, so the search of the whole tree stays as the fallback.
func runtimeStatusOf(show map[string]any) string {
	if status := strval(childMap(show, "runtime")["runtime_status"]); status != "" {
		return status
	}
	return findString(show, "runtime_status")
}

// podIsReady: running, staying, and every container passing its probe.
func podIsReady(pod map[string]any) bool {
	if terminating, _ := pod["terminating"].(bool); terminating {
		return false
	}
	if phase := strval(pod["phase"]); phase != "" && phase != "Running" {
		return false
	}
	containers := arrayMap(pod["containers"])
	if len(containers) == 0 {
		return false
	}
	for _, container := range containers {
		if ready, _ := container["ready"].(bool); !ready {
			return false
		}
	}
	return true
}

// rolloutIsUp reports whether the revision this deploy created is serving.
//
// A pod says which revision it runs (its own cdn.com.tr/revision-number), and the
// API marks the pods of the Deployment's current ReplicaSet. The pod's own number
// is preferred: for a moment after a deploy the "current" ReplicaSet is still the
// old one. With neither (an API that does not send them) the Deployment's verdict
// is all there is, which is what this wait used before.
func rolloutIsUp(show map[string]any, revision int) bool {
	if runtimeStatusOf(show) != "running" {
		return false
	}
	runtime := childMap(show, "runtime")
	if deployed, ok := intFrom(childMap(runtime, "current_revision")["revision_number"]); ok && revision > 0 && deployed < revision {
		return false // the cluster has not taken this revision yet
	}

	judged, ready := 0, 0
	for _, pod := range arrayMap(runtime["pods"]) {
		ours, known := false, false
		if number, ok := intFrom(pod["revision_number"]); ok && revision > 0 {
			ours, known = number >= revision, true
		} else if current, ok := pod["current"].(bool); ok {
			ours, known = current, true
		}
		if !known {
			continue
		}
		judged++
		if ours && podIsReady(pod) {
			ready++
		}
	}
	if judged == 0 {
		return true
	}
	want := 1
	if replicas, ok := intFrom(runtime["replicas"]); ok && replicas > want {
		want = replicas
	}
	return ready >= want
}

// scaledToZero: the owner asked for no replicas and the Deployment has none. The
// panel sends replicas 0 for such an app on every deploy, so no pod will come.
func scaledToZero(show map[string]any) bool {
	replicas, ok := intFrom(childMap(show, "app")["replicas"])
	return ok && replicas == 0 && runtimeStatusOf(show) == "stopped"
}

// rolloutFailureReason is why the platform gave up on a revision.
func rolloutFailureReason(show map[string]any) string {
	return firstNonEmpty(
		strval(childMap(show, "app")["last_error"]),
		strval(childMap(show, "operation")["last_error"]),
	)
}

// waitForRollout follows the app until the deployed revision serves, the platform
// calls it failed, or the time is up.
//
// "failed" has to hold for failedLooksToBelieve looks in a row before the wait
// gives up early. The panel says "failed" while a container of the current
// ReplicaSet is in CrashLoopBackOff, which is also what a container that crashes
// twice while a dependency warms up looks like for its first half-minute; and for
// an instant after a deploy the current ReplicaSet is still the previous one, so
// an app redeployed because it was crash-looping would otherwise be reported
// failed for the crash it is being redeployed to fix. A wait that runs out while
// the last two looks said "failed" reports a failure, not a timeout.
func waitForRollout(account, appUUID string, queued map[string]any, timeoutSeconds int, fallbackDomain string) (rolloutOutcome, error) {
	if timeoutSeconds < 1 {
		timeoutSeconds = defaultDeployTimeout
	}
	outcome := rolloutOutcome{
		State:    rolloutTimeout,
		Revision: deployRevisionNumber(queued),
		Domain:   fallbackDomain,
		Seconds:  timeoutSeconds,
	}

	// The provisioner refusing the deploy is final, and the answer already says so.
	// (The next status read would find the old pods healthy and call it "running".)
	if operation := childMap(queued, "operation"); strval(operation["step"]) == "provisioner_failed" {
		outcome.State = rolloutFailed
		outcome.AppStatus = firstNonEmpty(strval(childMap(queued, "app")["status"]), rolloutFailed)
		outcome.Reason = rolloutFailureReason(queued)
		outcome.Show = queued
		return outcome, nil
	}

	looks := (timeoutSeconds + deployPollSeconds - 1) / deployPollSeconds
	deadline := clock().Add(time.Duration(timeoutSeconds) * time.Second)
	failedLooks := 0
	for i := 0; i < looks; i++ {
		if i > 0 && !pauseBeforeNextLook(deadline) {
			break
		}
		show, err := requestJSON(http.MethodGet,
			fmt.Sprintf("accounts/%s/platform/container/apps/%s", account, appUUID), nil)
		if err != nil {
			outcome.Reason = err.Error()
			return outcome, err
		}
		if status := httpStatusOf(show); status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound {
			reason, _ := apiFailure(show)
			outcome.Reason = reason
			return outcome, errExitMessage(1, fmt.Sprintf(T("Could not read the app's state: %s"), reason))
		}
		if _, failed := apiFailure(show); failed {
			continue // a passing API error is not the app's state; look again
		}

		outcome.Show = show
		outcome.AppStatus = strval(childMap(show, "app")["status"])
		outcome.RuntimeStatus = runtimeStatusOf(show)
		if domain := appDomain(show); domain != "" {
			outcome.Domain = domain
		}

		if rolloutIsUp(show, outcome.Revision) {
			outcome.State = rolloutRunning
			outcome.Reason = ""
			return outcome, nil
		}
		if scaledToZero(show) {
			outcome.State = rolloutStopped
			outcome.Reason = ""
			return outcome, nil
		}
		if outcome.AppStatus == rolloutFailed {
			failedLooks++
			outcome.Reason = rolloutFailureReason(show)
			if failedLooks >= failedLooksToBelieve {
				outcome.State = rolloutFailed
				return outcome, nil
			}
			continue
		}
		failedLooks = 0
		// Not running and not failed: the last reason on record (a probe that keeps
		// failing) is the best explanation a timeout can offer.
		outcome.Reason = rolloutFailureReason(show)
	}
	if failedLooks >= 2 {
		outcome.State = rolloutFailed
	}
	return outcome, nil
}

// reportRollout prints the outcome for a person: the address when it is up, the
// state, the revision, and when it is not up the reason and where the logs are.
func reportRollout(outcome rolloutOutcome, appUUID string) {
	row := func(label, value string) {
		if value != "" {
			fmt.Printf("%-10s %s\n", label, value)
		}
	}
	revision := ""
	if outcome.Revision > 0 {
		revision = strconv.Itoa(outcome.Revision)
	}

	switch outcome.State {
	case rolloutRunning:
		if outcome.Domain != "" {
			fmt.Printf(T("\n✓ LIVE: https://%s\n"), outcome.Domain)
		} else {
			fmt.Println(T("\n✓ LIVE — for the address: cdnctl container apps show --app ") + appUUID)
		}
		row(T("State"), firstNonEmpty(outcome.AppStatus, rolloutRunning))
		row(T("Revision"), revision)
		return
	case rolloutStopped:
		fmt.Printf(T("\n✓ Deployed. The app is scaled to 0 replicas, so it runs once it is scaled up: cdnctl container apps scale --app %s --replicas 1\n"), appUUID)
		row(T("State"), firstNonEmpty(outcome.AppStatus, rolloutStopped))
		row(T("Revision"), revision)
		return
	case rolloutFailed:
		fmt.Println()
		fmt.Println(T("✗ The deploy failed: the new revision did not come up."))
	default:
		fmt.Println()
		fmt.Printf(T("✗ Timed out after %d seconds: the new revision is not running yet.\n"), outcome.Seconds)
	}

	row(T("State"), firstNonEmpty(outcome.AppStatus, T("unknown")))
	row(T("Revision"), revision)
	row(T("Reason"), terminalSafe(outcome.Reason))

	app := childMap(outcome.Show, "app")
	if app == nil {
		app = map[string]any{}
	}
	if strval(app["uuid"]) == "" {
		app["uuid"] = appUUID
	}
	fmt.Println()
	if hint := failureHint(app); hint != "" {
		fmt.Println(hint)
	} else {
		fmt.Printf(T("Read the logs: cdnctl container apps logs --app %s --tail 50")+"\n", appUUID)
	}
	if outcome.State == rolloutTimeout {
		fmt.Println(T("The app is not running yet — follow its state: cdnctl container apps show --app ") + appUUID)
	}
}

// rolloutJSON is the one object `container apps deploy` prints for a program. It
// keeps the keys of the API's 202 answer (status, message, app, revision,
// operation_uuid, operation) so a script that read those still finds them, now
// describing how the deploy ended, and adds the outcome.
func rolloutJSON(queued map[string]any, outcome rolloutOutcome, account, appUUID string) map[string]any {
	out := map[string]any{
		"status":         "error",
		"outcome":        outcome.State,
		"waited":         true,
		"app_status":     outcome.AppStatus,
		"runtime_status": outcome.RuntimeStatus,
		"app":            queued["app"],
		"revision":       queued["revision"],
		"operation_uuid": queued["operation_uuid"],
		"operation":      queued["operation"],
	}
	if status, ok := queued["_http_status"]; ok {
		out["_http_status"] = status
	}
	if outcome.Revision > 0 {
		out["revision_number"] = outcome.Revision
	}

	// The final state of the same rows, where the last read has them.
	if app := childMap(outcome.Show, "app"); app != nil {
		out["app"] = app
		wanted := strval(childMap(queued, "revision")["uuid"])
		for _, revision := range arrayMap(app["revisions"]) {
			if wanted != "" && strval(revision["uuid"]) == wanted {
				out["revision"] = revision
			}
		}
	}
	if operation := childMap(outcome.Show, "operation"); operation != nil && strval(operation["uuid"]) == strval(queued["operation_uuid"]) {
		out["operation"] = operation
	}
	if runtime := childMap(outcome.Show, "runtime"); runtime != nil {
		out["runtime"] = runtime
	}
	if outcome.Domain != "" {
		out["url"] = "https://" + outcome.Domain
	}

	switch outcome.State {
	case rolloutRunning:
		out["status"] = "success"
		out["message"] = "Deploy finished: the new revision is running."
	case rolloutStopped:
		out["status"] = "success"
		out["message"] = "Deploy recorded: the app is scaled to 0 replicas, so the new revision runs once it is scaled up."
	case rolloutFailed:
		out["message"] = "Deploy failed: the new revision did not come up."
	case rolloutUnknown:
		out["message"] = "The deploy was queued, but the app's state could not be read afterwards."
	default:
		out["message"] = fmt.Sprintf("Timed out after %d seconds: the new revision is not running yet.", outcome.Seconds)
	}
	if !outcome.succeeded() {
		if outcome.Reason != "" {
			out["reason"] = outcome.Reason
		}
		out["logs_command"] = fmt.Sprintf("cdnctl container apps logs --account %s --app %s --tail 100", account, appUUID)
	}
	return out
}

// refusedJSON is the one object for a deploy the API did not accept. It keeps the
// API's own answer (message, errors, _http_status) and carries the same outcome
// keys as a deploy that was waited for, so a program reads .outcome either way.
func refusedJSON(answer map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range answer {
		out[key] = value
	}
	reason, _ := apiFailure(answer)
	out["status"] = "error"
	out["outcome"] = rolloutRefused
	out["waited"] = false
	out["reason"] = reason
	return out
}

// cmdAppsDeploy is `cdnctl container apps deploy`: queue the deploy, wait for the
// revision it created, report how it ended. --no-wait is the command as it was:
// the API's answer, printed, exit 0.
func cmdAppsDeploy(account, appUUID string, args parsedArgs) error {
	if args.Bools["no_wait"] {
		return printRequest(http.MethodPost,
			fmt.Sprintf("accounts/%s/platform/container/apps/%s/deploy", account, appUUID),
			map[string]any{})
	}
	return deployAndReport(account, appUUID, intOption(args, "timeout", defaultDeployTimeout), wantsJSON(args))
}

// deployAndReport runs the deploy for a person (progress, then the outcome) or for a
// program (one JSON object, nothing else on stdout). Exit 1 unless the new revision
// is running, or the app is scaled to zero and the revision is recorded.
func deployAndReport(account, appUUID string, timeoutSeconds int, jsonOut bool) error {
	if !jsonOut {
		fmt.Println(T("→ triggering rollout"))
	}
	queued, err := startDeploy(account, appUUID)
	if err != nil {
		if jsonOut && queued != nil {
			// Nothing was queued to wait for: the refusal is the object.
			_ = printJSON(refusedJSON(queued))
			return errExit(1)
		}
		return err
	}
	if !jsonOut {
		fmt.Println(T("→ waiting for the app to come up"))
	}
	outcome, err := waitForRollout(account, appUUID, queued, timeoutSeconds, "")
	if err != nil {
		if !jsonOut {
			return err
		}
		// The deploy was queued, so a program is owed its one object even when
		// the end of the deploy could not be read.
		outcome.State = rolloutUnknown
		if err := printJSON(rolloutJSON(queued, outcome, account, appUUID)); err != nil {
			return err
		}
		return errExit(1)
	}
	if jsonOut {
		if err := printJSON(rolloutJSON(queued, outcome, account, appUUID)); err != nil {
			return err
		}
	} else {
		reportRollout(outcome, appUUID)
	}
	if !outcome.succeeded() {
		return errExit(1)
	}
	return nil
}
