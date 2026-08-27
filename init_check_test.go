package main

import (
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
