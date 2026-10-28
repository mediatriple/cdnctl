package main

import (
	"bytes"
	"strings"
	"testing"
)

// The platform probes exactly /health. Detection that counts anything else as
// that route configures an HTTP probe the app answers with 404, and Kubernetes
// restarts a healthy app until it gives up (a static site app, 2026-10-24).
func TestHealthRouteDetectionMatchesOnlyTheWholePath(t *testing.T) {
	cases := []struct {
		name  string
		file  string
		body  string
		found bool
	}{
		{"express", "server.js", "app.get('/health', (req, res) => res.send('ok'));", true},
		{"flask", "app.py", "@app.route(\"/health\")\ndef health():\n    return 'ok'", true},
		{"fastapi", "main.py", "@app.get(\"/health\")", true},
		{"go mux", "main.go", "http.HandleFunc(\"/health\", health)", true},
		{"go 1.22 pattern", "main.go", "mux.HandleFunc(\"GET /health\", health)", true},
		{"trailing slash", "app.py", "@app.route('/health/')", true},
		{"template literal", "server.ts", "router.get(`/health`, h)", true},
		{"healthz", "server.js", "app.get('/healthz', h)", false},
		{"healthz in a dockerfile", "Dockerfile", "HEALTHCHECK CMD wget -qO- http://localhost/healthz || exit 1", false},
		{"health-check", "server.js", "app.get('/health-check', h)", false},
		{"health_check", "app.py", "@app.route('/health_check')", false},
		{"nested under api", "server.js", "app.get('/api/health', h)", false},
		{"sub route", "server.js", "app.get('/health/live', h)", false},
		{"actuator", "application.yml", "management.endpoints.web.base-path: /actuator/health", false},
		{"commented out", "server.js", "// app.get('/health', h)\napp.listen(process.env.PORT)", false},
		{"word only", "server.js", "const health = checkHealth();", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeFixture(t, map[string]string{tc.file: tc.body})
			if got := projectHasHealthRoute(dir); got != tc.found {
				t.Fatalf("projectHasHealthRoute(%q) = %v, want %v", tc.body, got, tc.found)
			}
			// cdnctl check reads the same signal; the two must never disagree.
			_, warned := rulesOf(runChecks(dir))["no-healthcheck"]
			if warned == tc.found {
				t.Fatalf("check no-healthcheck warning = %v, but route found = %v", warned, tc.found)
			}
		})
	}
}

func healthArgs(pairs ...string) parsedArgs {
	return parseArgs(pairs)
}

func TestDeployHealthcheckFlagsAndDetection(t *testing.T) {
	withRoute := writeFixture(t, map[string]string{"server.js": "app.get('/health', h)"})
	withoutRoute := writeFixture(t, map[string]string{"server.js": "app.get('/healthz', h)"})
	withManifest := writeFixture(t, map[string]string{
		"server.js":   "app.get('/ready', h)",
		"cdnctl.yaml": "name: x\nhealthcheck: /ready\n",
	})

	cases := []struct {
		name   string
		dir    string
		args   parsedArgs
		newApp bool
		want   healthChoice
	}{
		{"route found", withRoute, healthArgs(), true, healthChoice{Type: "http", Path: "/health"}},
		{"manifest path", withManifest, healthArgs(), true, healthChoice{Type: "http", Path: "/ready"}},
		{"explicit path", withoutRoute, healthArgs("--healthcheck", "/status"), true, healthChoice{Type: "http", Path: "/status"}},
		{"no-healthcheck", withoutRoute, healthArgs("--no-healthcheck"), true, healthChoice{Type: "none"}},
		{"type tcp", withoutRoute, healthArgs("--healthcheck-type", "tcp"), true, healthChoice{Type: "tcp"}},
		{"type none", withoutRoute, healthArgs("--healthcheck-type", "none"), true, healthChoice{Type: "none"}},
		{"type http with path", withoutRoute, healthArgs("--healthcheck-type", "http", "--healthcheck", "/up"), true, healthChoice{Type: "http", Path: "/up"}},
		{"existing app keeps its probe", withoutRoute, healthArgs(), false, healthChoice{}},
		{"existing app, explicit flag", withoutRoute, healthArgs("--no-healthcheck"), false, healthChoice{Type: "none"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			got, err := resolveDeployHealthcheck(tc.dir, tc.args, tc.newApp, false, strings.NewReader(""), &out)
			if err != nil {
				t.Fatalf("unexpected error: %v (%s)", err, out.String())
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// With nobody to ask (an agent, CI), deploy must neither guess HTTP nor quietly
// drop the check: it stops and names the two flags.
func TestDeployHealthcheckWithoutRouteRefusesWithoutATerminal(t *testing.T) {
	dir := writeFixture(t, map[string]string{"server.js": "app.listen(process.env.PORT)"})
	var out bytes.Buffer
	_, err := resolveDeployHealthcheck(dir, healthArgs(), true, false, strings.NewReader("yes\n"), &out)
	exit, ok := isExitError(err)
	if !ok || exit.code != 1 {
		t.Fatalf("want exit 1, got %#v", err)
	}
	for _, want := range []string{"--no-healthcheck", "--healthcheck /path"} {
		if !strings.Contains(exit.message, want) {
			t.Fatalf("refusal must name %s: %q", want, exit.message)
		}
	}
	if out.Len() != 0 {
		t.Fatalf("no prompt may be printed without a terminal: %q", out.String())
	}
}

func TestDeployHealthcheckWithoutRouteAsks(t *testing.T) {
	dir := writeFixture(t, map[string]string{"server.js": "app.listen(process.env.PORT)"})

	var out bytes.Buffer
	got, err := resolveDeployHealthcheck(dir, healthArgs(), true, true, strings.NewReader("y\n"), &out)
	if err != nil || got.Type != "none" {
		t.Fatalf("yes must deploy without a health check: %+v, %v", got, err)
	}
	if !strings.Contains(out.String(), "Deploy without a health check?") {
		t.Fatalf("prompt not shown: %q", out.String())
	}

	for _, answer := range []string{"n\n", "\n", ""} {
		out.Reset()
		_, err = resolveDeployHealthcheck(dir, healthArgs(), true, true, strings.NewReader(answer), &out)
		if exit, ok := isExitError(err); !ok || exit.code != 1 {
			t.Fatalf("answer %q must cancel with exit 1, got %#v", answer, err)
		}
		if !strings.Contains(out.String(), "GET /health") {
			t.Fatalf("cancel must say how to fix it: %q", out.String())
		}
	}
}

func TestDeployHealthcheckRejectsBadFlags(t *testing.T) {
	dir := writeFixture(t, map[string]string{"server.js": "app.get('/health', h)"})
	for name, args := range map[string]parsedArgs{
		"path without value":  healthArgs("--healthcheck"),
		"path not a path":     healthArgs("--healthcheck", "health"),
		"unknown type":        healthArgs("--healthcheck-type", "grpc"),
		"none plus a path":    healthArgs("--no-healthcheck", "--healthcheck", "/health"),
		"none plus type http": healthArgs("--no-healthcheck", "--healthcheck-type", "http"),
	} {
		_, err := resolveDeployHealthcheck(dir, args, true, true, strings.NewReader("yes\n"), &bytes.Buffer{})
		if exit, ok := isExitError(err); !ok || exit.code != 2 {
			t.Errorf("%s: want usage exit 2, got %#v", name, err)
		}
	}
}

// The panel API validates healthcheck_path; deploy used to send "healthcheck",
// which nothing reads, so a manifest path was replaced by the default.
func TestHealthChoiceUsesTheAPIFieldNames(t *testing.T) {
	body := map[string]any{}
	healthChoice{Type: "http", Path: "/ready"}.addTo(body)
	if body["healthcheck_path"] != "/ready" || body["healthcheck_type"] != "http" {
		t.Fatalf("unexpected body: %#v", body)
	}
	if _, ok := body["healthcheck"]; ok {
		t.Fatalf("the API does not read \"healthcheck\": %#v", body)
	}

	body = map[string]any{}
	healthChoice{Type: "none"}.addTo(body)
	if body["healthcheck_type"] != "none" {
		t.Fatalf("unexpected body: %#v", body)
	}
	if _, ok := body["healthcheck_path"]; ok {
		t.Fatalf("no path is sent without an HTTP probe: %#v", body)
	}

	body = map[string]any{}
	healthChoice{}.addTo(body)
	if len(body) != 0 {
		t.Fatalf("an unset choice must leave the app's probe alone: %#v", body)
	}
}
