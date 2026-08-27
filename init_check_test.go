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

	touched, err := writeAgentBridge(dir, project)
	if err != nil {
		t.Fatal(err)
	}
	if len(touched) != 2 {
		t.Fatalf("AGENTS.md + CLAUDE.md yazilmaliydi: %v", touched)
	}

	// İkinci çalıştırma: içerik değişmediği için hiçbir dosyaya dokunmamalı.
	touched2, err := writeAgentBridge(dir, project)
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
