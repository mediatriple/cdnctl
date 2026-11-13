package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakePlatform is the container platform API as cdnctl sees it: create, expose,
// deploy and the add-on endpoints as separate calls, and an app payload whose state
// moves as it is read (the panel learns an app's state when it is asked).
//
// It answers with the shapes the panel sends: the deploy answer carries the revision
// it created, the app payload carries app.status, app.addons, app.revisions and a
// runtime block with the pods and their revision.
type fakePlatform struct {
	t  *testing.T
	mu sync.Mutex

	account string
	prefix  string           // URL prefix of the surface; empty = the full-session one
	calls   []string         // "METHOD path" under platform/container, in order
	bodies  []map[string]any // the JSON body of each call, same index

	// the app
	exists        bool
	uuid          string
	appName       string
	revisions     int                   // revisions the app has had
	addons        map[string]*fakeAddon // by type
	image         string                // what the app runs; PATCH changes it
	env           map[string]any        // app.env as the panel returns it
	secretKeys    []string              // app.secret_keys: names only
	environment   string                // app.environment: prod, preprod, ...
	promotionMeta map[string]any        // app.promotion_meta
	scaledToZero  bool                  // app.replicas 0: the Deployment runs no pod
	patchStatus   int                   // HTTP status of PATCH app (200 when 0)
	patchRefusal  string
	ownerRolls    []string // "revision:image" of each roll the platform made itself

	// how a deploy behaves
	readyAfter    int    // app reads after a deploy before the new revision's pod is ready
	oldPodServes  bool   // the previous revision's pod stays ready meanwhile (rolling update)
	failsWith     string // the new revision crash-loops with this reason from the first read on
	staleFailure  bool   // only the first read after a deploy says "failed" (the previous revision's crash)
	deployStatus  int    // HTTP status of POST deploy (202 by default)
	deployRefusal string // message of a refused deploy
	provisionerNo string // the provisioner refuses: the 202 answer already says failed
	readStatus    int    // HTTP status of GET app once a deploy was sent (200 when 0)
	failsFor      int    // the new revision is "failed" for this many reads, then comes up
	runtimeGaps   int    // after an add-on is enabled, this many reads answer without runtime.addons (the panel's cluster call failed)
	readTakes     time.Duration
	clockOffset   *atomic.Int64 // the fake clock the waits read, moved by readTakes per read

	// how enabling an add-on behaves
	addonActiveAfter int               // app reads before an enabled add-on is "active"
	addonReadyAfter  int               // app reads before its pod answers
	addonRefusal     map[string]string // type -> 422 message
	addonFails       map[string]string // type -> last_error once provisioning fails

	readsSinceDeploy int
	deployed         bool
	addonsAtDeploy   []string // "type:status:ready" of every add-on when deploy was called
}

type fakeAddon struct {
	status    string
	envPrefix string
	plan      string
	lastError string
	reads     int // app reads since it was enabled
	enabled   bool
	activeAt  int
	readyAt   int
	podReady  bool
	hasPod    bool
}

// englishMessages pins the language a test reads messages in. Without it T()
// follows the developer's own ~/.cdn/config.json, and a test that looks for an
// English sentence fails on a machine configured for another language.
func englishMessages(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CDNCTL_LANG", "en")
	previous := langOverride
	langOverride = ""
	t.Cleanup(func() { langOverride = previous })
}

func newFakePlatform(t *testing.T) (*fakePlatform, *httptest.Server) {
	t.Helper()
	fp := &fakePlatform{
		t:            t,
		account:      "acct-1",
		uuid:         "app-1",
		appName:      "demo",
		image:        "registry.cdn.com.tr/acct/demo:t0",
		addons:       map[string]*fakeAddon{},
		addonRefusal: map[string]string{},
		addonFails:   map[string]string{},
	}
	srv := httptest.NewServer(http.HandlerFunc(fp.serve))
	t.Cleanup(srv.Close)

	englishMessages(t)
	t.Setenv("CDN_ENDPOINT", "")
	t.Setenv("CDN_ACCESS_TOKEN", "")
	t.Setenv("CDN_ACCOUNT", "")
	t.Setenv("CDNCTL_ENDPOINT", srv.URL)
	t.Setenv("CDNCTL_TOKEN", "tok")
	previousInterval := deployPollInterval
	deployPollInterval = time.Millisecond
	t.Cleanup(func() { deployPollInterval = previousInterval })

	// The waits read a clock the fake moves: a read can "take" as long as a
	// test says without the test waiting for it.
	fp.clockOffset = &atomic.Int64{}
	start := time.Now()
	previousClock := clock
	clock = func() time.Time { return start.Add(time.Duration(fp.clockOffset.Load())) }
	t.Cleanup(func() { clock = previousClock })
	return fp, srv
}

// ownerRoll is what the platform does when an add-on of a deployed app becomes
// active (panel #510): it deploys the app again, with the image it runs and the
// add-on's variables. A new revision, made without cdnctl asking.
func (fp *fakePlatform) ownerRoll() {
	if fp.revisions == 0 {
		return // never deployed: the first deploy brings the add-on's variables
	}
	fp.revisions++
	fp.ownerRolls = append(fp.ownerRolls, fmt.Sprintf("%d:%s", fp.revisions, fp.image))
}

// existingApp makes the app one that was deployed before: one revision, running.
func (fp *fakePlatform) existingApp() {
	fp.exists = true
	fp.revisions = 1
	fp.deployed = false
}

func (fp *fakePlatform) withAddon(kind, status string) *fakeAddon {
	addon := &fakeAddon{status: status, envPrefix: strings.ToUpper(kind), plan: "starter", hasPod: kind != "mysql", podReady: status == "active"}
	fp.addons[kind] = addon
	return addon
}

func (fp *fakePlatform) recorded() []string {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	return append([]string(nil), fp.calls...)
}

// bodyOf returns the JSON body of the first recorded call that matches.
func (fp *fakePlatform) bodyOf(call string) map[string]any {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	for i, recorded := range fp.calls {
		if recorded == call {
			return fp.bodies[i]
		}
	}
	return nil
}

func (fp *fakePlatform) count(call string) int {
	n := 0
	for _, recorded := range fp.recorded() {
		if recorded == call {
			n++
		}
	}
	return n
}

// indexOf is the position of the first matching call, -1 when it never happened.
func (fp *fakePlatform) indexOf(call string) int {
	for i, recorded := range fp.recorded() {
		if recorded == call {
			return i
		}
	}
	return -1
}

func (fp *fakePlatform) serve(w http.ResponseWriter, r *http.Request) {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	prefix := fp.prefix
	if prefix == "" {
		prefix = "/api/accounts/" + fp.account + "/platform/container/"
	}
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, prefix)
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	fp.calls = append(fp.calls, r.Method+" "+path)
	fp.bodies = append(fp.bodies, body)

	answer := func(status int, payload map[string]any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)
	}
	app := "apps/" + fp.uuid

	switch {
	case r.Method == http.MethodPost && path == "source/upload":
		answer(200, map[string]any{"status": "success", "source_id": "src-1"})
	case r.Method == http.MethodPost && path == "source/build":
		answer(200, map[string]any{"status": "success", "build_id": "build-1", "image": "registry.cdn.com.tr/acct/demo", "tag": "t1"})
	case r.Method == http.MethodPost && path == "source/build/status":
		answer(200, map[string]any{"status": "success", "phase": "success"})
	case r.Method == http.MethodGet && path == "apps":
		apps := []any{}
		if fp.exists {
			apps = append(apps, map[string]any{"uuid": fp.uuid, "name": fp.appName, "status": "running"})
		}
		answer(200, map[string]any{"status": "success", "apps": apps})
	case r.Method == http.MethodPost && path == "apps":
		fp.exists = true
		answer(202, map[string]any{"status": "success", "message": "Container app creation queued.", "app": map[string]any{"uuid": fp.uuid, "name": fp.appName, "status": "stopped"}})
	case !fp.exists:
		answer(404, map[string]any{"status": "error", "message": "Container app not found."})
	case r.Method == http.MethodGet && path == app && fp.deployed && fp.readStatus >= 400:
		answer(fp.readStatus, map[string]any{"message": "Unauthenticated."})
	case r.Method == http.MethodGet && path == app:
		fp.clockOffset.Add(int64(fp.readTakes))
		answer(200, fp.show())
	case r.Method == http.MethodPatch && path == app:
		if fp.patchStatus >= 400 {
			answer(fp.patchStatus, map[string]any{"message": "The given data was invalid.", "errors": map[string]any{"image": []any{fp.patchRefusal}}})
			return
		}
		if image, _ := body["image"].(string); image != "" {
			fp.image = image + ":" + fmt.Sprint(body["tag"])
		}
		answer(200, map[string]any{"status": "success"})
	case r.Method == http.MethodPost && path == app+"/expose":
		answer(200, map[string]any{"status": "success", "app": map[string]any{"public_subdomain": "demo.cdn.com.tr"}})
	case r.Method == http.MethodPost && path == app+"/deploy":
		fp.deploy(answer)
	case r.Method == http.MethodPost && strings.HasPrefix(path, app+"/addons/"):
		fp.enableAddon(strings.TrimPrefix(path, app+"/addons/"), body, answer)
	default:
		// Anything else (a DELETE above all) is recorded and refused: no test
		// expects it, and the assertions on fp.calls say so.
		answer(405, map[string]any{"status": "error", "message": "not part of this fake"})
	}
}

func (fp *fakePlatform) deploy(answer func(int, map[string]any)) {
	for kind, addon := range fp.addons {
		fp.addonsAtDeploy = append(fp.addonsAtDeploy, fmt.Sprintf("%s:%s:%v", kind, addon.status, addon.podReady || !addon.hasPod))
	}
	if fp.deployStatus >= 400 {
		answer(fp.deployStatus, map[string]any{"status": "error", "message": fp.deployRefusal})
		return
	}
	fp.revisions++
	fp.deployed = true
	fp.readsSinceDeploy = 0
	operation := map[string]any{"uuid": fmt.Sprintf("op-%d", fp.revisions), "status": "in_progress", "step": "waiting_readiness", "input": map[string]any{"revision": fp.revisions}}
	appStatus := "deploying"
	if fp.provisionerNo != "" {
		operation["status"], operation["step"], operation["last_error"] = "failed", "provisioner_failed", fp.provisionerNo
		appStatus = "failed"
	}
	answer(202, map[string]any{
		"status":         "success",
		"message":        "Container app deploy queued.",
		"app":            map[string]any{"uuid": fp.uuid, "name": fp.appName, "status": appStatus, "last_error": fp.provisionerNo},
		"revision":       map[string]any{"uuid": fmt.Sprintf("rev-%d", fp.revisions), "revision_number": fp.revisions, "status": "queued"},
		"operation_uuid": operation["uuid"],
		"operation":      operation,
	})
}

func (fp *fakePlatform) enableAddon(apiPath string, body map[string]any, answer func(int, map[string]any)) {
	kind := map[string]string{"postgres": "postgres", "redis": "redis", "database": "mysql", "nats": "nats"}[apiPath]
	if kind == "" {
		answer(404, map[string]any{"status": "error", "message": "unknown add-on"})
		return
	}
	if message := fp.addonRefusal[kind]; message != "" {
		// The shape of a plan-limit refusal: a validation error, the sentence
		// to act on under errors.
		answer(422, map[string]any{"message": "The given data was invalid.", "errors": map[string]any{"entitlement": []any{message}}})
		return
	}
	addon := &fakeAddon{status: "pending", enabled: true, hasPod: kind != "mysql", activeAt: fp.addonActiveAfter, readyAt: fp.addonActiveAfter + fp.addonReadyAfter}
	addon.envPrefix, _ = body["env_prefix"].(string)
	addon.plan, _ = body["plan_code"].(string)
	if fp.addonActiveAfter == 0 {
		addon.status = "active"
		addon.podReady = fp.addonReadyAfter == 0
	}
	fp.addons[kind] = addon
	if addon.status == "active" {
		fp.ownerRoll()
	}
	answer(202, map[string]any{"status": "success", "message": "Managed add-on request recorded.", "addon": map[string]any{"type": kind, "status": addon.status}})
}

// show is GET apps/{uuid}: reading it is what advances the state.
func (fp *fakePlatform) show() map[string]any {
	// add-ons first: provisioning progresses with every read
	addonRows, addonPods := []any{}, []any{}
	for kind, addon := range fp.addons {
		if addon.enabled {
			addon.reads++
			if message := fp.addonFails[kind]; message != "" {
				addon.status, addon.lastError = "failed", message
			} else {
				if addon.reads >= addon.activeAt && addon.status != "active" {
					addon.status = "active"
					fp.ownerRoll()
				}
				addon.podReady = addon.reads >= addon.readyAt
			}
		}
		row := map[string]any{"type": kind, "status": addon.status, "env_prefix": addon.envPrefix, "plan_code": addon.plan}
		if addon.lastError != "" {
			row["last_error"] = addon.lastError
		}
		addonRows = append(addonRows, row)
		if addon.hasPod && addon.status != "deleted" && addon.status != "disabled" {
			ready := 0
			if addon.podReady {
				ready = 1
			}
			addonPods = append(addonPods, map[string]any{"name": "ca-x-" + kind, "kind": kind, "replicas": 1, "ready": ready, "healthy": ready == 1})
		}
	}

	revisions := []any{}
	for n := 1; n <= fp.revisions; n++ {
		revisions = append(revisions, map[string]any{"uuid": fmt.Sprintf("rev-%d", n), "revision_number": n, "status": "running"})
	}

	pod := func(revision int, current, ready bool, waiting string) map[string]any {
		state := map[string]any{"running": map[string]any{}}
		if waiting != "" {
			state = map[string]any{"waiting": map[string]any{"reason": waiting}}
		}
		return map[string]any{
			"name": fmt.Sprintf("ca-x-%d", revision), "phase": "Running", "terminating": false,
			"revision_number": fmt.Sprint(revision), "current": current,
			"containers": []any{map[string]any{"name": "app", "ready": ready, "state": state}},
		}
	}

	appStatus, runtimeStatus, lastError := "stopped", "stopped", ""
	pods := []any{}
	operation := map[string]any{"uuid": fmt.Sprintf("op-%d", fp.revisions), "status": "success"}
	replicas := 1
	switch {
	case fp.revisions == 0:
		// created, never deployed
	case fp.scaledToZero:
		// deployed with replicas 0: the Deployment is updated and runs nothing
		replicas, appStatus = 0, "stopped"
	case !fp.deployed:
		appStatus, runtimeStatus = "running", "running"
		pods = append(pods, pod(fp.revisions, true, true, ""))
	default:
		fp.readsSinceDeploy++
		crashing := fp.failsWith != "" && (fp.failsFor == 0 || fp.readsSinceDeploy <= fp.failsFor)
		up := !crashing && fp.readsSinceDeploy > fp.readyAfter
		switch {
		case up:
			appStatus, runtimeStatus = "running", "running"
			pods = append(pods, pod(fp.revisions, true, true, ""))
		case crashing:
			appStatus, runtimeStatus, lastError = "failed", "deploying", fp.failsWith
			pods = append(pods, pod(fp.revisions, true, false, "CrashLoopBackOff"))
			operation["status"], operation["step"], operation["last_error"] = "failed", "runtime_failed", fp.failsWith
		default:
			appStatus, runtimeStatus = "deploying", "deploying"
			if fp.staleFailure && fp.readsSinceDeploy == 1 {
				appStatus, lastError = "failed", "CrashLoopBackOff: the previous revision"
			}
			pods = append(pods, pod(fp.revisions, true, false, ""))
			operation["status"], operation["step"] = "in_progress", "waiting_readiness"
		}
		if !up && fp.oldPodServes {
			// A rolling update keeps the old pod until the new one is ready, and
			// the Deployment counts it: "running" with nothing new serving yet.
			runtimeStatus = "running"
			pods = append(pods, pod(fp.revisions-1, false, true, ""))
		}
	}

	env := any(fp.env)
	if fp.env == nil {
		env = []any{} // PHP sends an empty map as []
	}
	secretKeys := []any{}
	for _, key := range fp.secretKeys {
		secretKeys = append(secretKeys, key)
	}
	runtime := map[string]any{
		"mode":             "provisioner",
		"runtime_status":   runtimeStatus,
		"replicas":         replicas,
		"pods":             pods,
		"addons":           addonPods,
		"current_revision": map[string]any{"resolved": true, "revision_number": fmt.Sprint(fp.revisions)},
	}
	anyEnabled := false
	for _, addon := range fp.addons {
		anyEnabled = anyEnabled || addon.enabled
	}
	if fp.runtimeGaps > 0 && anyEnabled {
		// The panel's call to the cluster failed this time (counted from the
		// first read after an add-on was enabled): it still answers 200, and its
		// runtime block says only that.
		fp.runtimeGaps--
		runtime = map[string]any{"mode": "provisioner", "message": "Provisioner status is not available yet."}
	}
	return map[string]any{
		"status": "success",
		"app": map[string]any{
			"uuid": fp.uuid, "name": fp.appName, "status": appStatus, "last_error": lastError,
			"public_subdomain": "demo.cdn.com.tr", "healthcheck_type": "tcp", "image": fp.image,
			"replicas": replicas, "environment": fp.environment, "promotion_meta": fp.promotionMeta,
			"env": env, "secret_keys": secretKeys,
			"revisions": revisions, "addons": addonRows,
		},
		"operation": operation,
		"runtime":   runtime,
	}
}

// oneJSONObject asserts stdout is exactly one JSON object and returns it.
func oneJSONObject(t *testing.T, stdout string) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(stdout))
	var first map[string]any
	if err := decoder.Decode(&first); err != nil {
		t.Fatalf("stdout is not a JSON object: %v\n%s", err, stdout)
	}
	var second any
	if err := decoder.Decode(&second); err != io.EOF {
		t.Fatalf("stdout must hold ONE JSON object, found more: %q", stdout)
	}
	return first
}
