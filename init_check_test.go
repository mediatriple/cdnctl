package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixture mirrors the 2026-08-25 measurement app: every planted flaw that a real
// "AI Friday night" project shipped with. If a rule stops catching its flaw, the local
// report card silently degrades — these tests are the contract.

func writeFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func rulesOf(findings []finding) map[string]string {
	out := map[string]string{}
	for _, f := range findings {
		out[f.Rule] = f.Severity
	}
	return out
}

func TestRunChecksFindsPlantedFlaws(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"package.json": `{"name":"vibe","dependencies":{"express":"^4","better-sqlite3":"^11"}}`,
		"server.js": `const ADMIN_TOKEN = 'gizli-token-1234';
app.listen(3000, '127.0.0.1', () => {});`,
		".env": "DB_PASSWORD=hunter2\n",
	})

	got := rulesOf(runChecks(dir))
	for rule, wantSev := range map[string]string{
		"bind-localhost":    "error",
		"secret-in-code":    "error",
		"env-not-ignored":   "error",
		"sqlite-single-pod": "warning",
		"no-healthcheck":    "warning",
		"no-dockerfile":     "info",
	} {
		if got[rule] != wantSev {
			t.Errorf("rule %s: severity %q istendi, %q bulundu (tum bulgular: %v)", rule, wantSev, got[rule], got)
		}
	}
}

func TestRunChecksCleanAppPasses(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"package.json": `{"name":"clean","dependencies":{"express":"^4"}}`,
		"server.js": `const PORT = process.env.PORT || 8080;
app.get('/health', (req, res) => res.send('ok'));
app.listen(PORT);`,
		"Dockerfile": "FROM node:20-alpine\n",
		".gitignore": "node_modules/\n.env\n",
	})

	findings := runChecks(dir)
	if hasErrors(findings) {
		t.Fatalf("temiz uygulamada hata cikmamali: %+v", findings)
	}
	for _, f := range findings {
		if f.Rule == "no-healthcheck" || f.Rule == "hardcoded-port" {
			t.Errorf("temiz uygulamada %s tetiklenmemeli", f.Rule)
		}
	}
}

func TestOwnManifestDoesNotPaintTheReportCard(t *testing.T) {
	// cdnctl.yaml içindeki "healthcheck: /health" satırı, uygulamada route varmış
	// yanılsaması yaratıyordu (canlıda yakalandı, 2026-08-25).
	dir := writeFixture(t, map[string]string{
		"package.json": `{"name":"x","dependencies":{"express":"^4"}}`,
		"server.js":    `app.listen(process.env.PORT || 3000);`,
		"cdnctl.yaml":  "healthcheck: /health\n",
	})
	got := rulesOf(runChecks(dir))
	if got["no-healthcheck"] != "warning" {
		t.Fatalf("cdnctl.yaml no-healthcheck kuralini susturmamali: %v", got)
	}
}

func TestCopyNodeModulesRule(t *testing.T) {
	// 2026-08-25 deneyinde GERCEK cokme: COPY . . + lokal node_modules + .dockerignore yok
	// -> better-sqlite3 ERR_DLOPEN_FAILED. Kural bunu deploy'dan ONCE yakalamali.
	base := map[string]string{
		"package.json":            `{"name":"x","dependencies":{"express":"^4"}}`,
		"server.js":               `app.get('/health',h);app.listen(process.env.PORT || 3000);`,
		"Dockerfile":              "FROM node:20-alpine\nCOPY . .\n",
		"node_modules/x/index.js": "// derlenmis yerel modul temsili\n",
	}
	dir := writeFixture(t, base)
	if rulesOf(runChecks(dir))["copy-node-modules"] != "error" {
		t.Fatal(".dockerignore yokken copy-node-modules HATA vermeli")
	}

	base[".dockerignore"] = "node_modules\n"
	dir2 := writeFixture(t, base)
	if _, ok := rulesOf(runChecks(dir2))["copy-node-modules"]; ok {
		t.Fatal(".dockerignore node_modules iceriyorsa kural susmali")
	}
}

func TestDetectProjectNodeExpress(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"package.json":       `{"name":"gorev-takip","dependencies":{"express":"^4"}}`,
		"server.js":          `app.listen(process.env.PORT || 3177);`,
		"docker-compose.yml": "services: {}\n",
	})
	info := detectProject(dir)
	if info.Language != "node" || info.Framework != "express" {
		t.Fatalf("node/express bekleniyordu: %+v", info)
	}
	if info.Name != "gorev-takip" {
		t.Fatalf("isim package.json'dan gelmeli: %+v", info)
	}
	if info.Port != 3177 {
		t.Fatalf("port 3177 bekleniyordu: %+v", info)
	}
	if !info.HasCompose || info.HasDockerfile {
		t.Fatalf("compose var, dockerfile yok olmali: %+v", info)
	}
}

func TestDetectAgentsProjectMarkersWin(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"CLAUDE.md":    "# proj\n",
		".cursorrules": "rules\n",
	})
	agents := detectAgents(dir)
	byName := map[string]agentInfo{}
	for _, a := range agents {
		byName[a.Name] = a
	}
	if byName["claude-code"].Scope != "project" {
		t.Fatalf("CLAUDE.md varken claude-code scope=project olmali: %+v", agents)
	}
	if byName["cursor"].Scope != "project" {
		t.Fatalf(".cursorrules varken cursor scope=project olmali: %+v", agents)
	}
}

func TestAgentBridgeIdempotentAndMirrorsClaudeMd(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"CLAUDE.md": "# Mevcut proje notlari\nBunlara dokunulmamali.\n",
	})
	project := projectInfo{Name: "x", Language: "node", Port: 3000}

	touched, err := writeAgentBridge(dir, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(touched) != 2 {
		t.Fatalf("AGENTS.md + CLAUDE.md yazilmaliydi: %v", touched)
	}

	// İkinci çalıştırma: içerik değişmediği için hiçbir dosyaya dokunmamalı.
	touched2, err := writeAgentBridge(dir, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(touched2) != 0 {
		t.Fatalf("ikinci calistirma no-op olmali, dokundu: %v", touched2)
	}

	claude, _ := os.ReadFile(filepath.Join(dir, "CLAUDE.md"))
	if !strings.Contains(string(claude), "Mevcut proje notlari") {
		t.Fatal("mevcut CLAUDE.md icerigi korunmali")
	}
	if strings.Count(string(claude), bridgeBegin) != 1 {
		t.Fatal("CLAUDE.md'de tek bridge bolumu olmali")
	}
	agentsMd, _ := os.ReadFile(filepath.Join(dir, "AGENTS.md"))
	if strings.Count(string(agentsMd), bridgeBegin) != 1 {
		t.Fatal("AGENTS.md'de tek bridge bolumu olmali")
	}
}

func TestOpenDecisionsOfferSourceAndPackage(t *testing.T) {
	project := projectInfo{HasGit: true, HasCompose: true}
	ent := entitlementState{LoggedIn: true, PlatformEnabled: false}
	decisions := openDecisions(project, ent, "auto")
	ids := map[string]bool{}
	for _, d := range decisions {
		ids[d.ID] = true
	}
	if !ids["deploy-method"] || !ids["package"] {
		t.Fatalf("deploy-method + package karari bekleniyordu: %+v", decisions)
	}
}

// init promises a Dockerfile and deploy refuses to run without one. For the
// first three months that promise was unimplemented: init wrote only
// cdnctl.yaml and AGENTS.md, so a Flask user ran init, ran deploy, was told to
// run init, and had no way out of the loop.
func TestInitWritesRunnableDockerfileForDetectedStacks(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		wantIn  []string
		wantIgn string
	}{
		{
			name:    "python-flask",
			files:   map[string]string{"requirements.txt": "flask==3.0.0\n", "app.py": "app.run(host=\"0.0.0.0\", port=5001)\n"},
			wantIn:  []string{"FROM python:", "0.0.0.0:5001", "pip install"},
			wantIgn: "__pycache__",
		},
		{
			name:    "node",
			files:   map[string]string{"package.json": `{"name":"x","dependencies":{"express":"^4"}}`, "server.js": ".listen(3000"},
			wantIn:  []string{"FROM node:", "npm ci"},
			wantIgn: "node_modules",
		},
		{
			name:    "static",
			files:   map[string]string{"index.html": "<h1>x</h1>"},
			wantIn:  []string{"FROM nginx:"},
			wantIgn: ".git",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			wrote, err := writeDockerfile(dir, detectProject(dir))
			if err != nil {
				t.Fatalf("writeDockerfile: %v", err)
			}
			if len(wrote) == 0 {
				t.Fatal("no Dockerfile written — deploy would dead-end here")
			}

			body, err := os.ReadFile(filepath.Join(dir, "Dockerfile"))
			if err != nil {
				t.Fatalf("Dockerfile unreadable: %v", err)
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(string(body), want) {
					t.Errorf("Dockerfile missing %q:\n%s", want, body)
				}
			}
			// The .dockerignore is half the fix: without it COPY . . bakes the
			// host dependency directory into the image (the ERR_DLOPEN_FAILED
			// crashloop we hit in testing).
			ignore, err := os.ReadFile(filepath.Join(dir, ".dockerignore"))
			if err != nil {
				t.Fatalf(".dockerignore not written: %v", err)
			}
			if !strings.Contains(string(ignore), tc.wantIgn) {
				t.Errorf(".dockerignore missing %q:\n%s", tc.wantIgn, ignore)
			}
		})
	}
}

// A hand-written Dockerfile is the author's decision; init must never replace it.
func TestInitLeavesAnExistingDockerfileAlone(t *testing.T) {
	dir := t.TempDir()
	mine := "FROM scratch\n# mine\n"
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(mine), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	wrote, err := writeDockerfile(dir, detectProject(dir))
	if err != nil {
		t.Fatalf("writeDockerfile: %v", err)
	}
	if len(wrote) != 0 {
		t.Errorf("wrote %v over an existing Dockerfile", wrote)
	}
	body, _ := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	if string(body) != mine {
		t.Errorf("existing Dockerfile was modified:\n%s", body)
	}
}

// An unrecognised stack gets no guessed Dockerfile — init says so instead, which
// is the honest exit from the loop.
func TestInitWritesNoDockerfileForUnknownStack(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.c"), []byte("int main(){}"), 0o644); err != nil {
		t.Fatal(err)
	}
	wrote, err := writeDockerfile(dir, detectProject(dir))
	if err != nil {
		t.Fatalf("writeDockerfile: %v", err)
	}
	if len(wrote) != 0 {
		t.Errorf("guessed a Dockerfile for an unknown stack: %v", wrote)
	}
}

// The rules read code, not comments. cdnctl's own generated Dockerfile carries
// the line "Bind 0.0.0.0, not 127.0.0.1" as advice; bind-localhost matched that
// comment and blocked deploy on a file cdnctl had just written itself.
func TestChecksIgnoreCommentedLocalhost(t *testing.T) {
	dir := t.TempDir()
	dockerfile := "FROM python:3.12-slim\n" +
		"# Bind 0.0.0.0, not 127.0.0.1: the platform reaches the container from outside.\n" +
		"CMD [\"gunicorn\", \"--bind\", \"0.0.0.0:5001\", \"app:app\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, f := range runChecks(dir) {
		if f.Rule == "bind-localhost" {
			t.Errorf("commented advice flagged as a real bind: %s:%d %s", f.File, f.Line, f.Message)
		}
	}
}

// A genuine localhost bind in code must still be caught — the comment skip
// must not become a way to hide the defect.
func TestChecksStillCatchRealLocalhostBind(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("app.run(host=\"127.0.0.1\", port=5001)\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range runChecks(dir) {
		if f.Rule == "bind-localhost" {
			found = true
		}
	}
	if !found {
		t.Error("a real 127.0.0.1 bind was not reported")
	}
}

// The tarball IS the build context, so the Dockerfile must be inside it even
// though .dockerignore lists it — listing it there is idiomatic (it keeps the
// file out of the image) and used to strip it from the upload, leaving Kaniko
// with "error resolving dockerfile path" on a project cdnctl had just scaffolded.
func TestSourceArchiveKeepsDockerfileDespiteDockerignore(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"Dockerfile":    "FROM python:3.12-slim\n",
		".dockerignore": "Dockerfile\n.dockerignore\ncdnctl.yaml\n__pycache__\n",
		"app.py":        "print(1)\n",
		"cdnctl.yaml":   "name: x\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	archive, _, err := makeSourceArchive(dir, "Dockerfile")
	if err != nil {
		t.Fatalf("makeSourceArchive: %v", err)
	}
	defer os.Remove(archive)

	names := map[string]bool{}
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		names[hdr.Name] = true
	}

	if !names["Dockerfile"] {
		t.Error("Dockerfile missing from the build context — the build cannot start")
	}
	if !names["app.py"] {
		t.Error("app.py missing from the build context")
	}
	// The rest of .dockerignore must still be honoured.
	if names["cdnctl.yaml"] {
		t.Error("cdnctl.yaml was uploaded despite .dockerignore")
	}
}

// The manifest calls itself "the file cdnctl deploy reads", and deploy did not
// read it: editing name: did nothing and the folder name silently won, so
// renaming a folder would have created a second app instead of updating the
// first. These helpers are what makes the manifest authoritative.
func TestManifestValuesAreReadableAndWritable(t *testing.T) {
	dir := t.TempDir()
	manifest := "# comment\nname: gorev-takip   # trailing note\nport: 5001\n"
	if err := os.WriteFile(filepath.Join(dir, "cdnctl.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := readManifestValue(dir, "name"); got != "gorev-takip" {
		t.Errorf("name = %q, want gorev-takip (trailing comment must not leak in)", got)
	}
	if got := readManifestValue(dir, "port"); got != "5001" {
		t.Errorf("port = %q, want 5001", got)
	}
	if got := readManifestValue(dir, "app"); got != "" {
		t.Errorf("missing key returned %q, want empty", got)
	}

	// Recording the app id is what separates "the app this folder created" from
	// "some app with a matching name" on the next deploy.
	if err := setManifestValue(dir, "app", "abc-123"); err != nil {
		t.Fatalf("setManifestValue: %v", err)
	}
	if got := readManifestValue(dir, "app"); got != "abc-123" {
		t.Errorf("app = %q after write, want abc-123", got)
	}
	if got := readManifestValue(dir, "name"); got != "gorev-takip" {
		t.Errorf("writing app clobbered name: %q", got)
	}

	if err := setManifestValue(dir, "app", "def-456"); err != nil {
		t.Fatalf("setManifestValue (update): %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, "cdnctl.yaml"))
	if strings.Count(string(body), "app:") != 1 {
		t.Errorf("updating app duplicated the key:\n%s", body)
	}
}

// The last line of a successful deploy must contain the address. The API never
// returns a plain "domain" key — it reports public_subdomain and domains lists —
// so the lookup came back empty and the flow ended by telling people to run
// another command to find out where their app was.
func TestAppDomainReadsTheShapesTheApiActuallyReturns(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]any
		want    string
	}{
		{
			name: "public_subdomain",
			payload: map[string]any{"app": map[string]any{
				"public_subdomain": "camap769.cdn.com.tr",
			}},
			want: "camap769.cdn.com.tr",
		},
		{
			name: "domains list",
			payload: map[string]any{"app": map[string]any{
				"domains": []any{"camap769.cdn.com.tr"},
			}},
			want: "camap769.cdn.com.tr",
		},
		{
			name: "routed_domains nested",
			payload: map[string]any{"operation": map[string]any{"output": map[string]any{
				"routed_domains": []any{"camap769.cdn.com.tr"},
			}}},
			want: "camap769.cdn.com.tr",
		},
		{
			name:    "nothing to report",
			payload: map[string]any{"app": map[string]any{"name": "x"}},
			want:    "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := appDomain(tc.payload); got != tc.want {
				t.Errorf("appDomain = %q, want %q", got, tc.want)
			}
		})
	}
}

// The bridge must land in the file each detected agent actually reads. Writing
// only to AGENTS.md — and to CLAUDE.md merely when it already existed — is how
// a Claude Code session sat inside an already-deployed project and recommended
// Render and GitHub Pages: the instructions were two files away, in a file
// that agent never opens.
func TestAgentBridgeCreatesNativeFilesForDetectedAgents(t *testing.T) {
	dir := t.TempDir()
	project := projectInfo{Name: "x", Language: "python", Port: 5001}
	agents := []agentInfo{
		{Name: "claude-code", Evidence: "claude on PATH", Scope: "cli"},
		{Name: "gemini-cli", Evidence: "gemini on PATH", Scope: "cli"},
		{Name: "cursor", Evidence: "cursor-agent on PATH", Scope: "cli"},
	}

	touched, err := writeAgentBridge(dir, project, agents)
	if err != nil {
		t.Fatal(err)
	}

	for _, file := range []string{"AGENTS.md", "CLAUDE.md", "GEMINI.md"} {
		body, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatalf("%s was not created (touched: %v)", file, touched)
		}
		if !strings.Contains(string(body), "cdnctl deploy") {
			t.Errorf("%s does not carry the deploy instructions", file)
		}
		// The one sentence that prevents the observed failure: the agent must
		// be told not to invent another hosting provider.
		if !strings.Contains(string(body), "Do NOT propose") {
			t.Errorf("%s lacks the do-not-propose-other-hosting instruction", file)
		}
	}

	// No cursor-specific file exists; cursor reads AGENTS.md.
	if _, err := os.Stat(filepath.Join(dir, "CURSOR.md")); err == nil {
		t.Error("a cursor-specific file was invented")
	}
}

// --- Next.js Dockerfile template ---
//
// The generic node template never ran a build and its .dockerignore excluded
// .next anyway, so `next start` crash-looped on the platform with "Could not
// find a production build" on every single request. These tests are the
// contract that replaces it.

func writeNextApp(t *testing.T, extra map[string]string) string {
	t.Helper()
	files := map[string]string{
		"package.json":   `{"name":"my-next-app","dependencies":{"next":"^14.2.0","react":"^18","react-dom":"^18"}}`,
		"pages/index.js": "export default function Home() { return null }\n",
	}
	for k, v := range extra {
		files[k] = v
	}
	return writeFixture(t, files)
}

func TestDetectProjectNextFramework(t *testing.T) {
	dir := writeNextApp(t, nil)
	info := detectProject(dir)
	if info.Language != "node" || info.Framework != "next" {
		t.Fatalf("node/next bekleniyordu: %+v", info)
	}
}

// Without a build step `next start` has nothing to serve. This is the actual
// defect being fixed: the old template wrote FROM node / COPY / CMD npm run
// start with no RUN npm run build anywhere in between.
func TestNextjsDockerfileRunsBuildStep(t *testing.T) {
	dir := writeNextApp(t, nil)
	wrote, err := writeDockerfile(dir, detectProject(dir))
	if err != nil {
		t.Fatalf("writeDockerfile: %v", err)
	}
	if len(wrote) == 0 {
		t.Fatal("no Dockerfile written for a Next.js project")
	}
	body, err := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	if err != nil {
		t.Fatalf("Dockerfile unreadable: %v", err)
	}
	text := string(body)

	if !strings.Contains(text, "RUN npm run build") {
		t.Errorf("Dockerfile never runs a build step:\n%s", text)
	}
	// The build needs devDependencies (TypeScript, the Next compiler plugins,
	// etc.) — omitting them is what a generic node template does, and it is
	// wrong here.
	if strings.Contains(text, "--omit=dev") {
		t.Errorf("Dockerfile omits devDependencies, which the build step needs:\n%s", text)
	}
	if !strings.Contains(text, "0.0.0.0") {
		t.Errorf("Dockerfile does not bind HOSTNAME to 0.0.0.0:\n%s", text)
	}
	if !strings.Contains(text, "ENV PORT=") {
		t.Errorf("Dockerfile does not set PORT:\n%s", text)
	}
	// Non-standalone: runs next start against the full node_modules + .next
	// this same build produced, via the package.json "start" script.
	if !strings.Contains(text, "start") {
		t.Errorf("Dockerfile has no start command:\n%s", text)
	}

	ignore, err := os.ReadFile(filepath.Join(dir, ".dockerignore"))
	if err != nil {
		t.Fatalf(".dockerignore not written: %v", err)
	}
	ignoreText := string(ignore)
	// node_modules and .next are excluded from the BUILD CONTEXT (what gets
	// uploaded), not from the image — the build stage installs and builds
	// its own fresh copies inside the container. A host .next/node_modules
	// would be stale or built for the wrong platform/ABI.
	for _, must := range []string{"node_modules", ".next"} {
		if !strings.Contains(ignoreText, must) {
			t.Errorf(".dockerignore should still exclude %q (rebuilt inside the image):\n%s", must, ignoreText)
		}
	}
	// But it must not exclude what COPY . . needs to actually produce a build:
	// no blanket wildcard line, and not the source files we just wrote.
	for _, line := range strings.Split(ignoreText, "\n") {
		if strings.TrimSpace(line) == "*" {
			t.Errorf(".dockerignore has a blanket wildcard line, which would starve the build:\n%s", ignoreText)
		}
	}
	for _, mustNot := range []string{"pages", "package.json"} {
		if strings.Contains(ignoreText, mustNot) {
			t.Errorf(".dockerignore excludes %q, which the build needs:\n%s", mustNot, ignoreText)
		}
	}
}

// output: 'standalone' changes the Dockerfile shape, not just a flag: Next's
// build already traced the minimal node_modules the app needs, so shipping
// the full tree on top of that in the final image is wasted space.
func TestNextjsDockerfileStandaloneVariant(t *testing.T) {
	dir := writeNextApp(t, map[string]string{
		"next.config.js": "module.exports = { output: 'standalone' }\n",
	})
	if _, err := writeDockerfile(dir, detectProject(dir)); err != nil {
		t.Fatalf("writeDockerfile: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	if err != nil {
		t.Fatalf("Dockerfile unreadable: %v", err)
	}
	text := string(body)

	if strings.Count(text, "FROM ") < 3 {
		t.Errorf("standalone output expected a multi-stage build (deps/builder/runner):\n%s", text)
	}
	if !strings.Contains(text, "RUN npm run build") {
		t.Errorf("standalone Dockerfile never builds:\n%s", text)
	}
	for _, must := range []string{
		"COPY --from=builder /app/public ./public",
		".next/standalone",
		".next/static",
		`CMD ["node", "server.js"]`,
		`ENV HOSTNAME="0.0.0.0"`,
	} {
		if !strings.Contains(text, must) {
			t.Errorf("standalone Dockerfile missing %q:\n%s", must, text)
		}
	}
	// The trimmed server, not `next start`, is what standalone output ships.
	if strings.Contains(text, "next start") || strings.Contains(text, `"start"`) {
		t.Errorf("standalone Dockerfile should run server.js directly, not a start script:\n%s", text)
	}
}

// The build and start commands must match whichever package manager's
// lockfile the project actually checked in — using npm against a pnpm
// project (or vice versa) either fails outright or silently resolves a
// different dependency tree than the one that was tested.
func TestNextjsDockerfilePackageManagerVariants(t *testing.T) {
	cases := []struct {
		name       string
		lockfile   string
		wantInstal string
		wantBuild  string
		wantCopy   string
	}{
		{"npm-default", "", "npm ci", "npm run build", "package-lock.json*"},
		{"yarn", "yarn.lock", "yarn install --frozen-lockfile", "yarn build", "yarn.lock*"},
		{"pnpm", "pnpm-lock.yaml", "pnpm install --frozen-lockfile", "pnpm build", "pnpm-lock.yaml*"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			extra := map[string]string{}
			if tc.lockfile != "" {
				extra[tc.lockfile] = "# lockfile\n"
			}
			dir := writeNextApp(t, extra)
			if _, err := writeDockerfile(dir, detectProject(dir)); err != nil {
				t.Fatalf("writeDockerfile: %v", err)
			}
			body, err := os.ReadFile(filepath.Join(dir, "Dockerfile"))
			if err != nil {
				t.Fatalf("Dockerfile unreadable: %v", err)
			}
			text := string(body)
			if !strings.Contains(text, tc.wantInstal) {
				t.Errorf("%s: missing install command %q:\n%s", tc.name, tc.wantInstal, text)
			}
			if !strings.Contains(text, tc.wantBuild) {
				t.Errorf("%s: missing build command %q:\n%s", tc.name, tc.wantBuild, text)
			}
			if !strings.Contains(text, tc.wantCopy) {
				t.Errorf("%s: missing lockfile COPY %q:\n%s", tc.name, tc.wantCopy, text)
			}
		})
	}

	// pnpm specifically needs corepack — the node:20 image does not have pnpm
	// pre-installed, and `npm install -g pnpm` would install whatever
	// "latest" happens to be the day the base image was built.
	dir := writeNextApp(t, map[string]string{"pnpm-lock.yaml": "# lockfile\n"})
	if _, err := writeDockerfile(dir, detectProject(dir)); err != nil {
		t.Fatalf("writeDockerfile: %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	if !strings.Contains(string(body), "corepack") {
		t.Errorf("pnpm variant should enable pnpm via corepack:\n%s", body)
	}
}

// nextConfigIsStandalone must recognise every extension next.config is
// allowed to use, and not care which quote style the project wrote.
func TestNextConfigIsStandaloneDetection(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		content string
		want    bool
	}{
		{"js-single-quote", "next.config.js", "module.exports = { output: 'standalone' }\n", true},
		{"mjs-double-quote", "next.config.mjs", `export default { output: "standalone" }` + "\n", true},
		{"ts", "next.config.ts", "const config = { output: 'standalone' }\nexport default config\n", true},
		{"no-output", "next.config.js", "module.exports = { reactStrictMode: true }\n", false},
		{"other-output", "next.config.js", "module.exports = { output: 'export' }\n", false},
		{"absent", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.file != "" {
				if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := nextConfigIsStandalone(dir); got != tc.want {
				t.Errorf("nextConfigIsStandalone(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// The standalone hint is informational only: it must fire exactly for a
// Next.js project that has not opted in yet, and stay silent otherwise (other
// frameworks, or a project that already set output: 'standalone').
func TestNextStandaloneHint(t *testing.T) {
	plain := t.TempDir()
	if got := nextStandaloneHint(plain, "next"); got == "" {
		t.Error("expected a hint for a Next.js project without output: 'standalone'")
	}
	if got := nextStandaloneHint(plain, "express"); got != "" {
		t.Errorf("non-Next.js framework should get no hint, got %q", got)
	}

	standalone := t.TempDir()
	if err := os.WriteFile(filepath.Join(standalone, "next.config.js"), []byte("module.exports = { output: 'standalone' }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := nextStandaloneHint(standalone, "next"); got != "" {
		t.Errorf("project already on standalone output should get no hint, got %q", got)
	}
}

// ---------- generic Node template (not Next.js) ----------

// This is the actual defect being fixed: the old generic Node template never
// ran a build step, so a project whose "start" script expects compiled
// output (tsc, esbuild, webpack...) shipped the unbuilt source into the
// image and crashed on first request.
func TestGenericNodeDockerfileRunsBuildStepWhenPresent(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"package.json": `{"name":"api","scripts":{"build":"tsc","start":"node dist/index.js"},"dependencies":{"express":"^4"},"devDependencies":{"typescript":"^5"}}`,
		"src/index.ts": "import express from 'express'\n",
	})
	if _, err := writeDockerfile(dir, detectProject(dir)); err != nil {
		t.Fatalf("writeDockerfile: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	if err != nil {
		t.Fatalf("Dockerfile unreadable: %v", err)
	}
	text := string(body)

	if !strings.Contains(text, "RUN npm run build") {
		t.Errorf("Dockerfile never runs the build script:\n%s", text)
	}
	// The build needs devDependencies (the TypeScript compiler here) —
	// --omit=dev would strip exactly what the build step depends on.
	if strings.Contains(text, "--omit=dev") {
		t.Errorf("Dockerfile omits devDependencies, which the build step needs:\n%s", text)
	}
	// The CMD defers to the package manager's own "start" alias — like the
	// Next.js template, it runs whatever "start" script package.json
	// actually defines (here, the compiled dist/index.js), not a literal
	// invocation this template would have to keep in sync with it.
	if !strings.Contains(text, `CMD ["sh", "-c", "npm run start"]`) {
		t.Errorf("Dockerfile does not start via npm's start script:\n%s", text)
	}
	if !strings.Contains(text, "0.0.0.0") {
		t.Errorf("Dockerfile comment should still call out 0.0.0.0 binding:\n%s", text)
	}
}

// A project with no build script must keep the original lean install —
// devDependencies have no reason to ship in an image nothing compiles.
func TestGenericNodeDockerfileOmitsDevWhenNoBuildScript(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"package.json": `{"name":"api","scripts":{"start":"node server.js"},"dependencies":{"express":"^4"}}`,
		"server.js":    "require('express')().listen(process.env.PORT || 8080)\n",
	})
	if _, err := writeDockerfile(dir, detectProject(dir)); err != nil {
		t.Fatalf("writeDockerfile: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	if err != nil {
		t.Fatalf("Dockerfile unreadable: %v", err)
	}
	text := string(body)

	if strings.Contains(text, "RUN npm run build") {
		t.Errorf("no build script exists, but the Dockerfile runs one:\n%s", text)
	}
	if !strings.Contains(text, "--omit=dev") {
		t.Errorf("no build step and no devDependency install should be the lean --omit=dev path:\n%s", text)
	}
}

// Same lockfile-driven package manager detection the Next.js template uses
// must apply to the generic template too — a yarn or pnpm project built
// with hardcoded npm commands either fails or silently resolves a
// different dependency tree than the one that was tested.
func TestGenericNodeDockerfilePackageManagerVariants(t *testing.T) {
	cases := []struct {
		name       string
		lockfile   string
		wantInstal string
		wantBuild  string
		wantStart  string
	}{
		{"npm-default", "", "npm ci --omit=dev", "", "npm run start"},
		{"yarn", "yarn.lock", "yarn install --frozen-lockfile --production", "", "yarn start"},
		{"pnpm", "pnpm-lock.yaml", "pnpm install --frozen-lockfile --prod", "", "pnpm start"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{
				"package.json": `{"name":"api","scripts":{"start":"node server.js"},"dependencies":{"express":"^4"}}`,
				"server.js":    "require('express')().listen(3000)\n",
			}
			if tc.lockfile != "" {
				files[tc.lockfile] = "# lockfile\n"
			}
			dir := writeFixture(t, files)
			if _, err := writeDockerfile(dir, detectProject(dir)); err != nil {
				t.Fatalf("writeDockerfile: %v", err)
			}
			body, _ := os.ReadFile(filepath.Join(dir, "Dockerfile"))
			text := string(body)
			if !strings.Contains(text, tc.wantInstal) {
				t.Errorf("%s: missing install command %q:\n%s", tc.name, tc.wantInstal, text)
			}
			if !strings.Contains(text, tc.wantStart) {
				t.Errorf("%s: missing start command %q:\n%s", tc.name, tc.wantStart, text)
			}
		})
	}
}

func TestNodePackageHasScript(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"package.json": `{"name":"x","scripts":{"build":"tsc","test":"  "}}`,
	})
	if !nodePackageHasScript(dir, "build") {
		t.Error("build script present but not detected")
	}
	if nodePackageHasScript(dir, "test") {
		t.Error("blank script body should not count as present")
	}
	if nodePackageHasScript(dir, "start") {
		t.Error("missing script reported as present")
	}
}

// ---------- PHP template ----------

// This is the actual defect being fixed: composer install ran before the
// project's own files were copied in. For a classmap (or any autoload entry
// that scans a directory rather than trusting composer.json alone) that
// directory does not exist yet, so the generated autoloader silently maps
// zero classes instead of failing loudly.
func TestPhpDockerfileInstallsAutoloaderAfterSourceIsCopied(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"composer.json":   `{"autoload":{"classmap":["app/"]}}`,
		"app/Greeter.php": "<?php\nnamespace App;\nclass Greeter {}\n",
		"index.php":       "<?php\necho 'ok';\n",
	})
	if _, err := writeDockerfile(dir, detectProject(dir)); err != nil {
		t.Fatalf("writeDockerfile: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	if err != nil {
		t.Fatalf("Dockerfile unreadable: %v", err)
	}
	text := string(body)

	copyAll := strings.Index(text, "COPY . .")
	if copyAll < 0 {
		t.Fatalf("Dockerfile never copies the project source:\n%s", text)
	}
	// The first composer install (before COPY . .) must not build the
	// autoloader yet — the directories it would scan are not there.
	firstInstall := strings.Index(text, "composer install")
	if firstInstall < 0 || firstInstall > copyAll {
		t.Fatalf("expected a composer install before COPY . . (for the cached dependency fetch):\n%s", text)
	}
	before := text[:copyAll]
	if !strings.Contains(before, "--no-autoloader") {
		t.Errorf("the pre-COPY composer install must skip autoloader generation (nothing to scan yet):\n%s", before)
	}
	// A second pass after the source is copied must actually build the
	// autoloader against the real project files.
	after := text[copyAll:]
	if !strings.Contains(after, "composer install") {
		t.Errorf("expected a composer install after COPY . . to build the real autoloader:\n%s", after)
	}
}

// Apache's own default config listens on 80 regardless of what EXPOSE
// claims — the port cdnctl declares for the app (and probes/routes to) must
// be the port Apache is actually told to bind.
func TestPhpDockerfileRewritesApachePort(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"composer.json": `{}`,
		"index.php":     "<?php\necho 'ok';\n",
	})
	if _, err := writeDockerfile(dir, detectProject(dir)); err != nil {
		t.Fatalf("writeDockerfile: %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	text := string(body)
	if !strings.Contains(text, "Listen 8080") {
		t.Errorf("ports.conf rewrite should target the declared port (8080 default):\n%s", text)
	}
	if !strings.Contains(text, ":8080>") {
		t.Errorf("the default vhost rewrite should target the declared port:\n%s", text)
	}
	if !strings.Contains(text, "EXPOSE 8080") {
		t.Errorf("EXPOSE should match the port Apache is told to bind:\n%s", text)
	}
}

// ---------- static template ----------

// nginx's own default config listens on 80 regardless of what EXPOSE
// claims; the same class of bug as the PHP/Apache one above.
func TestStaticDockerfileRewritesNginxPort(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"index.html": "<h1>hi</h1>\n",
	})
	if _, err := writeDockerfile(dir, detectProject(dir)); err != nil {
		t.Fatalf("writeDockerfile: %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	text := string(body)
	if !strings.Contains(text, "listen\\s*80;/listen 8080;") {
		t.Errorf("default.conf's listen 80 should be rewritten to the declared port:\n%s", text)
	}
	if !strings.Contains(text, "EXPOSE 8080") {
		t.Errorf("EXPOSE should match the port nginx is told to bind:\n%s", text)
	}
}

// ---------- Go template ----------

func TestFindGoMainPackages(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"go.mod":              "module example.com/app\n\ngo 1.22\n",
		"cmd/api/main.go":     "package main\n\nfunc main() {}\n",
		"cmd/worker/main.go":  "package main\n\nfunc main() {}\n",
		"internal/lib/lib.go": "package lib\n",
	})
	got := findGoMainPackages(dir)
	want := []string{"cmd/api", "cmd/worker"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("findGoMainPackages = %v, want %v", got, want)
	}
}

func TestFindGoMainPackagesSingleRootBinary(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"go.mod":  "module example.com/app\n\ngo 1.22\n",
		"main.go": "package main\n\nfunc main() {}\n",
	})
	got := findGoMainPackages(dir)
	if len(got) != 1 || got[0] != "" {
		t.Errorf("findGoMainPackages = %v, want a single root (\"\") entry", got)
	}
}

// Without a name match, the package whose own source actually binds a port
// wins — that is the one serving the traffic the platform routes to.
func TestGoPrimaryEntrypointFallsBackToPortPattern(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"cmd/ingest/main.go": "package main\n\nfunc main() {}\n",
		"cmd/ingest/run.go":  "package main\n\nfunc run() {}\n",
		"cmd/relay/main.go":  "package main\n\nfunc main() { _ = \"http.ListenAndServe(\\\":8080\\\", nil)\" }\n",
	})
	// Rewrite relay's file with a real, matchable pattern (the inline string
	// above would itself match — keep the fixture honest with a literal call).
	if err := os.WriteFile(filepath.Join(dir, "cmd/relay/main.go"), []byte("package main\n\nfunc main() {\n\thttp.ListenAndServe(\":8080\", nil)\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mains := findGoMainPackages(dir)
	got := goPrimaryEntrypoint(dir, mains)
	if got != "cmd/relay" {
		t.Errorf("goPrimaryEntrypoint = %q, want cmd/relay (the one that binds a port)", got)
	}
}

// Conventional names (server, api, web, app...) win over the port-pattern
// fallback — they are a stronger, deliberate signal than a regex guess.
func TestGoPrimaryEntrypointPrefersConventionalNames(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"cmd/worker/main.go": "package main\n\nfunc main() {}\n",
		"cmd/api/main.go":    "package main\n\nfunc main() {}\n",
	})
	mains := findGoMainPackages(dir)
	if got := goPrimaryEntrypoint(dir, mains); got != "cmd/api" {
		t.Errorf("goPrimaryEntrypoint = %q, want cmd/api", got)
	}
}

// A single main package (the common case, and the old template's only
// case) must keep building exactly as it did before.
func TestGoDockerfileSingleMainBuildsOnlyTheMainPackage(t *testing.T) {
	// main.go plus a library package: `go build -o /out/app ./...` fails here
	// ("cannot write multiple packages to non-directory") — the commonest Go layout.
	dir := writeFixture(t, map[string]string{
		"go.mod":                  "module example.com/app\n\ngo 1.22\n",
		"main.go":                 "package main\n\nfunc main() { _ = \"http.ListenAndServe\" }\n",
		"internal/greet/greet.go": "package greet\n\nfunc Hi() string { return \"hi\" }\n",
	})
	if _, err := writeDockerfile(dir, detectProject(dir)); err != nil {
		t.Fatalf("writeDockerfile: %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	text := string(body)
	if !strings.Contains(text, "go build -o /out/app .\n") || strings.Contains(text, "./...") {
		t.Errorf("single-main project must build its main package only:\n%s", text)
	}
	if !strings.Contains(text, `CMD ["/app"]`) {
		t.Errorf("single-main project should keep the original CMD:\n%s", text)
	}

	nested := writeFixture(t, map[string]string{
		"go.mod":             "module example.com/app\n\ngo 1.22\n",
		"cmd/server/main.go": "package main\n\nfunc main() {}\n",
		"pkg/store/store.go": "package store\n",
	})
	if _, err := writeDockerfile(nested, detectProject(nested)); err != nil {
		t.Fatalf("writeDockerfile: %v", err)
	}
	body, _ = os.ReadFile(filepath.Join(nested, "Dockerfile"))
	if !strings.Contains(string(body), "go build -o /out/app ./cmd/server\n") {
		t.Errorf("a single main under cmd/ must be built by its path:\n%s", body)
	}
}

// This is the actual defect being fixed: `go build -o /out/app ./...` is
// ambiguous once the module has several main packages (a cmd/api + cmd/worker
// layout) — -o names one output file while ./... matches several mains.
// Every binary must still get built (nothing silently dropped), and the one
// that actually serves HTTP traffic must be the one the CMD runs.
func TestGoDockerfileMultipleMainPackagesBuildsEachAndPicksServer(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"go.mod":             "module example.com/app\n\ngo 1.22\n",
		"cmd/api/main.go":    "package main\n\nfunc main() {\n\thttp.ListenAndServe(\":8080\", nil)\n}\n",
		"cmd/worker/main.go": "package main\n\nfunc main() {}\n",
	})
	if _, err := writeDockerfile(dir, detectProject(dir)); err != nil {
		t.Fatalf("writeDockerfile: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	if err != nil {
		t.Fatalf("Dockerfile unreadable: %v", err)
	}
	text := string(body)

	for _, must := range []string{
		"go build -o /out/api ./cmd/api",
		"go build -o /out/worker ./cmd/worker",
		`CMD ["/out/api"]`,
	} {
		if !strings.Contains(text, must) {
			t.Errorf("Dockerfile missing %q:\n%s", must, text)
		}
	}
	// The ambiguous single -o/./... form from the old template must be gone.
	if strings.Contains(text, "go build -o /out/app ./...") {
		t.Errorf("Dockerfile still uses the ambiguous single-binary build with multiple mains:\n%s", text)
	}
}

// A Laravel app served from the project root exposes .env and the source
// tree; the template must move Apache's document root to public/.
func TestPhpDockerfileServesLaravelFromPublic(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"composer.json":    `{}`,
		"artisan":          "#!/usr/bin/env php\n<?php\n",
		"public/index.php": "<?php\necho 'ok';\n",
		// Laravel ships one for its asset build; it must not win detection.
		"package.json": `{"private":true,"scripts":{"build":"vite build"}}`,
	})
	project := detectProject(dir)
	if project.Language != "php" || project.Framework != "laravel" {
		t.Fatalf("expected laravel detection, got %q", project.Framework)
	}
	if _, err := writeDockerfile(dir, project); err != nil {
		t.Fatalf("writeDockerfile: %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	text := string(body)
	for _, want := range []string{"APACHE_DOCUMENT_ROOT=/var/www/html/public", "a2enmod rewrite", "pdo_mysql", "unzip"} {
		if !strings.Contains(text, want) {
			t.Errorf("Laravel Dockerfile missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "artisan migrate") {
		t.Errorf("a build has no database; migrations must not run in the Dockerfile:\n%s", text)
	}
}

// Plain PHP keeps Apache's default document root.
func TestPhpDockerfilePlainPhpKeepsDefaultDocroot(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"composer.json": `{}`,
		"index.php":     "<?php\necho 'ok';\n",
	})
	project := detectProject(dir)
	if project.Framework != "" {
		t.Fatalf("plain PHP detected as %q", project.Framework)
	}
	if _, err := writeDockerfile(dir, project); err != nil {
		t.Fatalf("writeDockerfile: %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	if strings.Contains(string(body), "APACHE_DOCUMENT_ROOT") {
		t.Errorf("plain PHP must keep the default docroot:\n%s", body)
	}
}

// DB_PORT / REDIS_PORT in a Laravel .env name services the app connects to;
// taking one as the listen port routed traffic to 3306.
func TestDetectPortIgnoresPrefixedServicePorts(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		".env":      "DB_PORT=3306\nREDIS_PORT=6379\nMAIL_PORT=2525\n",
		"index.php": "<?php\necho 'ok';\n",
	})
	if got := detectPort(dir); got != 0 {
		t.Errorf("detectPort took a service port as the listen port: %d", got)
	}
	dir = writeFixture(t, map[string]string{".env": "PORT=3000\n"})
	if got := detectPort(dir); got != 3000 {
		t.Errorf("bare PORT=3000 not detected, got %d", got)
	}
}
