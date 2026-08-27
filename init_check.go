package main

// cdnctl init / cdnctl check — the local half of the vibe-coder deploy flow.
//
// Design (kb/notes/discovery_topics/cdnctl-init-vibe-deploy.md): the primary user is
// often not a human but the AI agent sitting next to them, working in this very
// directory. So both commands speak two languages: human text, and --json whose shape
// is a NEGOTIATION interface — "these decisions are open, these are the options" — so
// a local agent can pick (--package/--method) instead of a human clicking through a
// wizard. Payment stays on cdn.com.tr in the browser; cdnctl only carries context
// there and picks the flow back up afterwards.
//
// Everything in this file runs locally. `check` never opens a network connection;
// `init` only calls the API to read entitlements, and only when a token exists.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ---------- project detection ----------

type projectInfo struct {
	Name          string `json:"name"`
	Language      string `json:"language"`
	Framework     string `json:"framework,omitempty"`
	Port          int    `json:"port,omitempty"`
	HasDockerfile bool   `json:"has_dockerfile"`
	HasCompose    bool   `json:"has_compose"`
	HasGit        bool   `json:"has_git"`
}

func detectProject(dir string) projectInfo {
	info := projectInfo{Name: filepath.Base(absOrSelf(dir))}
	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(dir, name))
		return err == nil
	}
	info.HasDockerfile = exists("Dockerfile")
	info.HasCompose = exists("docker-compose.yml") || exists("docker-compose.yaml") || exists("compose.yml") || exists("compose.yaml")
	info.HasGit = exists(".git")

	switch {
	case exists("package.json"):
		info.Language = "node"
		if raw, err := os.ReadFile(filepath.Join(dir, "package.json")); err == nil {
			var pkg struct {
				Name         string            `json:"name"`
				Dependencies map[string]string `json:"dependencies"`
			}
			if json.Unmarshal(raw, &pkg) == nil {
				if pkg.Name != "" {
					info.Name = pkg.Name
				}
				for _, fw := range []string{"next", "express", "fastify", "koa", "nest"} {
					if _, ok := pkg.Dependencies[fw]; ok {
						info.Framework = fw
						break
					}
				}
			}
		}
	case exists("requirements.txt") || exists("pyproject.toml"):
		info.Language = "python"
		for _, f := range []string{"requirements.txt", "pyproject.toml"} {
			if raw, err := os.ReadFile(filepath.Join(dir, f)); err == nil {
				low := strings.ToLower(string(raw))
				for _, fw := range []string{"django", "fastapi", "flask"} {
					if strings.Contains(low, fw) {
						info.Framework = fw
						break
					}
				}
			}
			if info.Framework != "" {
				break
			}
		}
	case exists("go.mod"):
		info.Language = "go"
	case exists("composer.json"):
		info.Language = "php"
	case exists("index.html"):
		info.Language = "static"
	default:
		info.Language = "unknown"
	}

	info.Port = detectPort(dir)
	return info
}

var portPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)process\.env\.PORT\s*\|\|\s*(\d{2,5})`),
	regexp.MustCompile(`(?i)\.listen\(\s*(\d{2,5})`),
	regexp.MustCompile(`(?i)port\s*[:=]\s*(\d{2,5})`),
	regexp.MustCompile(`(?i)^EXPOSE\s+(\d{2,5})`),
}

func detectPort(dir string) int {
	port := 0
	scanProjectFiles(dir, func(path string, content []byte) {
		if port != 0 {
			return
		}
		for _, re := range portPatterns {
			if m := re.FindSubmatch(content); m != nil {
				fmt.Sscanf(string(m[1]), "%d", &port)
				return
			}
		}
	})
	return port
}

// ---------- local AI agent detection ----------

type agentInfo struct {
	Name     string `json:"name"`
	Evidence string `json:"evidence"`
	// "project" = configured in this repo (the agent the user actually works with
	// here), "cli" = merely installed on this machine. Project evidence wins: that
	// is the agent worth talking to.
	Scope string `json:"scope"`
}

var agentProjectMarkers = []struct{ name, marker string }{
	{"claude-code", "CLAUDE.md"},
	{"claude-code", ".claude"},
	{"cursor", ".cursorrules"},
	{"cursor", ".cursor"},
	{"github-copilot", ".github/copilot-instructions.md"},
	{"gemini-cli", "GEMINI.md"},
	{"windsurf", ".windsurfrules"},
	{"aider", ".aider.conf.yml"},
	{"generic-agents-md", "AGENTS.md"},
}

var agentCLIs = []struct{ name, binary string }{
	{"claude-code", "claude"},
	{"cursor", "cursor-agent"},
	{"gemini-cli", "gemini"},
	{"aider", "aider"},
	{"codex", "codex"},
}

func detectAgents(dir string) []agentInfo {
	found := []agentInfo{}
	seen := map[string]bool{}
	for _, m := range agentProjectMarkers {
		if _, err := os.Stat(filepath.Join(dir, m.marker)); err == nil {
			key := m.name + "|project"
			if !seen[key] {
				seen[key] = true
				found = append(found, agentInfo{Name: m.name, Evidence: m.marker, Scope: "project"})
			}
		}
	}
	for _, c := range agentCLIs {
		if _, err := exec.LookPath(c.binary); err == nil {
			key := c.name + "|cli"
			if !seen[key] && !seen[c.name+"|project"] {
				seen[key] = true
				found = append(found, agentInfo{Name: c.name, Evidence: c.binary + " on PATH", Scope: "cli"})
			}
		}
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].Scope != found[j].Scope {
			return found[i].Scope == "project"
		}
		return found[i].Name < found[j].Name
	})
	return found
}

// ---------- check rules ----------

type finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"` // "error" | "warning" | "info"
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Message  string `json:"message"`
	Fix      string `json:"fix"`
}

var (
	reListenLocalhost = regexp.MustCompile(`(?i)(listen|bind|host)[^\n]{0,60}(127\.0\.0\.1|(['"])localhost(['"]))`)
	reSecretAssign    = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*["'][A-Za-z0-9_\-\.\$]{8,}["']`)
	reHealthRoute     = regexp.MustCompile(`(?i)(/health|healthz|health_check)`)
	rePortEnv         = regexp.MustCompile(`(?i)(process\.env\.PORT|os\.environ|getenv\(["']PORT)`)
	reListenLiteral   = regexp.MustCompile(`\.listen\(\s*\d{2,5}\s*[,)]`)
	reSQLiteDep       = regexp.MustCompile(`(?i)(better-sqlite3|"sqlite3"|aiosqlite|go-sqlite3|'sqlite)`)
)

var checkSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, ".venv": true, "venv": true, "__pycache__": true, ".next": true,
}

var checkTextExt = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true, ".jsx": true,
	".py": true, ".rb": true, ".php": true, ".go": true, ".java": true,
	".yml": true, ".yaml": true, ".json": true, ".env": true, ".toml": true,
}

func scanProjectFiles(dir string, visit func(path string, content []byte)) {
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if checkSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		base := d.Name()
		if !checkTextExt[ext] && base != "Dockerfile" && base != ".env" {
			return nil
		}
		if strings.HasSuffix(base, "-lock.json") || base == "package-lock.json" || base == "yarn.lock" {
			return nil
		}
		if info, err := d.Info(); err != nil || info.Size() > 512*1024 {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		visit(path, content)
		return nil
	})
}

func lineOf(content []byte, idx int) int {
	return 1 + strings.Count(string(content[:idx]), "\n")
}

// runChecks is the local half of the "karne": every rule here is a fault we PLANTED
// in the measurement app and then met for real. They run before any code leaves the
// machine — which is also why an AI agent can run this in a fix loop for free.
func runChecks(dir string) []finding {
	findings := []finding{}
	rel := func(p string) string {
		if r, err := filepath.Rel(dir, p); err == nil {
			return r
		}
		return p
	}

	sawHealth := false
	sawPortEnv := false
	sawListen := false
	sawSQLite := false

	scanProjectFiles(dir, func(path string, content []byte) {
		base := filepath.Base(path)
		// Kendi ürettiğimiz manifest karneyi boyamasın: içindeki "healthcheck: /health"
		// satırı, uygulamada gerçekten route varmış gibi görünmesine yol açıyordu.
		if base == "cdnctl.yaml" {
			return
		}
		isEnvExample := strings.Contains(base, ".env.example") || strings.Contains(base, ".env.sample")

		if loc := reListenLocalhost.FindIndex(content); loc != nil && !strings.Contains(base, "test") {
			findings = append(findings, finding{
				Rule: "bind-localhost", Severity: "error", File: rel(path), Line: lineOf(content, loc[0]),
				Message: "Uygulama 127.0.0.1/localhost'a bağlanıyor — container içinde dışarıdan erişilemez, deploy edilince site açılmaz.",
				Fix:     "0.0.0.0'a bağlanın (ör. app.listen(PORT) — host parametresini kaldırmak yeterli).",
			})
		}
		if !isEnvExample && base != "Dockerfile" {
			if loc := reSecretAssign.FindIndex(content); loc != nil {
				findings = append(findings, finding{
					Rule: "secret-in-code", Severity: "error", File: rel(path), Line: lineOf(content, loc[0]),
					Message: "Kodda gömülü bir sır (API key/token/parola) görünüyor.",
					Fix:     "Değeri koddan çıkarıp deploy sırasında `cdnctl container apps update --secret KEY=VALUE` ile verin; kodda process.env/os.environ ile okuyun.",
				})
			}
		}
		if reHealthRoute.Match(content) {
			sawHealth = true
		}
		if rePortEnv.Match(content) {
			sawPortEnv = true
		}
		if reListenLiteral.Match(content) {
			sawListen = true
		}
		if reSQLiteDep.Match(content) || strings.HasSuffix(base, ".db") || strings.HasSuffix(base, ".sqlite") {
			sawSQLite = true
		}
	})

	// SQLite dosyaları da (içerik taramasının dışında) sinyaldir.
	for _, pat := range []string{"*.db", "*.sqlite", "*.sqlite3"} {
		if matches, _ := filepath.Glob(filepath.Join(dir, pat)); len(matches) > 0 {
			sawSQLite = true
		}
	}

	if sawSQLite {
		findings = append(findings, finding{
			Rule: "sqlite-single-pod", Severity: "warning",
			Message: "SQLite kullanılıyor. Container yeniden başladığında ya da birden çok replikada dosya-veritabanı veri kaybettirir.",
			Fix:     "Kalıcı disk bağlayın (--persistent-mount-path) ya da yönetilen MySQL/Postgres add-on'una geçin — taşımada yardımcı olur: cdn.com.tr/help/platforms.",
		})
	}
	if !sawHealth {
		findings = append(findings, finding{
			Rule: "no-healthcheck", Severity: "warning",
			Message: "Bir healthcheck yolu (/health) görünmüyor. Platform, uygulamanızın canlı olduğunu anlayamaz; çökme sonrası otomatik toparlama gecikir.",
			Fix:     "200 dönen basit bir GET /health ekleyin ve deploy'da --healthcheck /health verin.",
		})
	}
	if sawListen && !sawPortEnv {
		findings = append(findings, finding{
			Rule: "hardcoded-port", Severity: "warning",
			Message: "Port sabit yazılmış ve PORT ortam değişkeni okunmuyor.",
			Fix:     "const PORT = process.env.PORT || <port> desenini kullanın; platform portu env ile verir.",
		})
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); err == nil {
		ignored := false
		if raw, err := os.ReadFile(filepath.Join(dir, ".gitignore")); err == nil {
			for _, l := range strings.Split(string(raw), "\n") {
				if strings.TrimSpace(l) == ".env" {
					ignored = true
					break
				}
			}
		}
		if !ignored {
			findings = append(findings, finding{
				Rule: "env-not-ignored", Severity: "error", File: ".env",
				Message: ".env dosyası var ama .gitignore'da değil — sırlar repoya girer.",
				Fix:     ".gitignore'a `.env` satırı ekleyin; değerleri --secret ile taşıyın.",
			})
		}
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "Dockerfile")); err != nil {
		findings = append(findings, finding{
			Rule: "no-dockerfile", Severity: "info",
			Message: "Dockerfile yok.",
			Fix:     "`cdnctl init` tespit edilen dile göre bir şablon üretebilir.",
		})
	} else if regexp.MustCompile(`(?m)^\s*COPY\s+\.{1,2}/?\s`).Match(raw) {
		// Canlı çökmeden doğan kural (2026-08-25 deneyi): imaj içindeki npm install'ın
		// üstüne "COPY . ." lokalde derlenmiş node_modules'ı kopyalar; native modüller
		// (better-sqlite3 gibi) hedef libc/ABI'de ERR_DLOPEN_FAILED ile ölür.
		if _, err := os.Stat(filepath.Join(dir, "node_modules")); err == nil {
			ignored := false
			if di, err := os.ReadFile(filepath.Join(dir, ".dockerignore")); err == nil {
				for _, l := range strings.Split(string(di), "\n") {
					if strings.TrimSpace(l) == "node_modules" || strings.TrimSpace(l) == "node_modules/" {
						ignored = true
						break
					}
				}
			}
			if !ignored {
				findings = append(findings, finding{
					Rule: "copy-node-modules", Severity: "error", File: "Dockerfile",
					Message: "Dockerfile'daki `COPY . .` lokal node_modules'ı imaja kopyalıyor — makinenizde derlenen native modüller container'da çalışmaz (ERR_DLOPEN_FAILED).",
					Fix:     ".dockerignore dosyasına `node_modules` satırı ekleyin; bağımlılıklar imaj içindeki npm install ile kurulur.",
				})
			}
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		rank := map[string]int{"error": 0, "warning": 1, "info": 2}
		return rank[findings[i].Severity] < rank[findings[j].Severity]
	})
	return findings
}

// ---------- agent bridge ----------

const bridgeBegin = "<!-- cdnctl:begin -->"
const bridgeEnd = "<!-- cdnctl:end -->"

// bridgeSection is what we tell the user's own AI agent. It is deliberately written
// FOR an agent: exact commands, exact flags, machine-readable modes — because the
// agent that built this app is the one most likely to deploy and debug it.
func bridgeSection(project projectInfo) string {
	port := project.Port
	if port == 0 {
		port = 8080
	}
	return bridgeBegin + `
## Deploy: cdn.com.tr (via cdnctl)

This project deploys to cdn.com.tr with the cdnctl CLI. As an AI agent you can drive
the whole flow yourself:

- ` + "`cdnctl check --json`" + ` — local pre-deploy report card (localhost binds, secrets in
  code, SQLite-in-container, missing healthcheck). Fix errors before deploying;
  exit code 1 means errors exist.
- ` + "`cdnctl init --json`" + ` — project/entitlement state plus OPEN DECISIONS with options.
  Pick and answer via flags (e.g. ` + "`--method`" + `, ` + "`--package`" + `). If the account lacks a
  container-platform package, cdnctl prints the purchase URL — payment happens in the
  browser on cdn.com.tr; re-run ` + "`cdnctl init`" + ` afterwards and it continues.
- ` + "`cdnctl container apps list|show|deploy|logs ...`" + ` — manage the running app
  (every command accepts --account; port for this project: ` + fmt.Sprintf("%d", port) + `).
- Never commit secrets; pass them with ` + "`--secret KEY=VALUE`" + ` on apps update.

Docs: https://cdn.com.tr/learn/deploy-from-git · https://cdn.com.tr/help/platforms
` + bridgeEnd + "\n"
}

// writeAgentBridge installs/refreshes the section in AGENTS.md (always — it is the
// cross-agent standard) and mirrors it into CLAUDE.md when the project already has
// one. Marker-guarded: re-running replaces our section and touches nothing else.
func writeAgentBridge(dir string, project projectInfo) ([]string, error) {
	section := bridgeSection(project)
	touched := []string{}
	targets := []string{filepath.Join(dir, "AGENTS.md")}
	if _, err := os.Stat(filepath.Join(dir, "CLAUDE.md")); err == nil {
		targets = append(targets, filepath.Join(dir, "CLAUDE.md"))
	}
	for _, target := range targets {
		existing := ""
		if raw, err := os.ReadFile(target); err == nil {
			existing = string(raw)
		}
		var updated string
		if b := strings.Index(existing, bridgeBegin); b >= 0 {
			e := strings.Index(existing, bridgeEnd)
			if e < b {
				continue // bozuk işaretleyici — dokunma, üzerine yazma riski alma
			}
			updated = existing[:b] + strings.TrimSuffix(section, "\n") + existing[e+len(bridgeEnd):]
		} else {
			sep := "\n"
			if existing != "" && !strings.HasSuffix(existing, "\n") {
				sep = "\n\n"
			}
			updated = existing + sep + section
		}
		if updated == existing {
			continue
		}
		if err := os.WriteFile(target, []byte(updated), 0o644); err != nil {
			return touched, err
		}
		touched = append(touched, filepath.Base(target))
	}
	return touched, nil
}

// ---------- manifest ----------

func writeManifest(dir string, project projectInfo, method string) (bool, error) {
	path := filepath.Join(dir, "cdnctl.yaml")
	if _, err := os.Stat(path); err == nil {
		return false, nil
	}
	port := project.Port
	if port == 0 {
		port = 8080
	}
	manifest := fmt.Sprintf(`# cdnctl project manifest — `+"`cdnctl deploy`"+` reads this.
name: %s
language: %s
port: %d
healthcheck: /health
deploy:
  method: %s   # source (tarball -> platform build) | git | compose
`, project.Name, project.Language, port, method)
	return true, os.WriteFile(path, []byte(manifest), 0o644)
}

// writeDockerfile generates the container recipe when the project has none.
// init used to promise this ("`cdnctl init` bir şablon üretebilir" is what
// deploy tells you) without ever writing the file, so a first-time user was
// bounced between init and deploy with no way forward. An existing Dockerfile
// is never touched — a hand-written one is the author's decision, not ours.
//
// The templates deliberately install dependencies inside the build rather than
// copying whatever sits in the project folder: host node_modules or a local
// virtualenv carry binaries built for the wrong platform, which is the
// ERR_DLOPEN_FAILED crashloop we hit in testing.
func writeDockerfile(dir string, project projectInfo) ([]string, error) {
	path := filepath.Join(dir, "Dockerfile")
	if _, err := os.Stat(path); err == nil {
		return nil, nil
	}
	port := project.Port
	if port == 0 {
		port = 8080
	}

	body, ignore := dockerfileTemplate(project, port)
	if body == "" {
		return nil, nil
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return nil, err
	}
	wrote := []string{"Dockerfile"}

	// The .dockerignore is half the fix: without it `COPY . .` bakes the host's
	// dependency directory into the image no matter how good the Dockerfile is.
	if ignore != "" {
		ignorePath := filepath.Join(dir, ".dockerignore")
		if _, err := os.Stat(ignorePath); err != nil {
			if err := os.WriteFile(ignorePath, []byte(ignore), 0o644); err != nil {
				return wrote, err
			}
			wrote = append(wrote, ".dockerignore")
		}
	}
	return wrote, nil
}

// dockerfileTemplate returns the Dockerfile body and matching .dockerignore for
// a detected stack. An empty body means "we do not know this stack well enough
// to guess" — better to say so than to write something that fails at build time.
func dockerfileTemplate(project projectInfo, port int) (dockerfile, dockerignore string) {
	commonIgnore := ".git\n.gitignore\n.env\n.env.*\n!.env.example\nDockerfile\n.dockerignore\ncdnctl.yaml\n"

	switch project.Language {
	case "node":
		start := "npm start"
		if project.Framework == "next" {
			start = "npm run start"
		}
		return fmt.Sprintf(`# Generated by cdnctl init — edit freely, it is yours now.
FROM node:20-alpine
WORKDIR /app

# Dependencies install inside the image: copying host node_modules ships
# native modules built for your machine, which crash in the container.
COPY package*.json ./
RUN npm ci --omit=dev || npm install --omit=dev

COPY . .

ENV PORT=%d
EXPOSE %d
# Listen on 0.0.0.0, not localhost: platform traffic arrives from outside the
# container's loopback interface.
CMD ["sh", "-c", "%s"]
`, port, port, start), commonIgnore + "node_modules\nnpm-debug.log\n.next\ndist\n"

	case "python":
		app := "app:app"
		cmd := fmt.Sprintf(`CMD ["gunicorn", "--bind", "0.0.0.0:%d", "%s"]`, port, app)
		extra := "RUN pip install --no-cache-dir gunicorn\n"
		switch project.Framework {
		case "fastapi":
			cmd = fmt.Sprintf(`CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "%d"]`, port)
			extra = "RUN pip install --no-cache-dir uvicorn\n"
		case "django":
			cmd = fmt.Sprintf(`CMD ["gunicorn", "--bind", "0.0.0.0:%d", "config.wsgi:application"]`, port)
		}
		return fmt.Sprintf(`# Generated by cdnctl init — edit freely, it is yours now.
FROM python:3.12-slim
WORKDIR /app

# Dependencies install inside the image: a local venv or site-packages copied
# from the host carries binaries built for the wrong platform.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
%s
COPY . .

ENV PORT=%d
EXPOSE %d
# Bind 0.0.0.0, not 127.0.0.1: the platform reaches the container from outside
# its loopback interface. Adjust the module path below if your entrypoint
# is not app.py's `+"`app`"+` object.
%s
`, extra, port, port, cmd), commonIgnore + "__pycache__\n*.pyc\n.venv\nvenv\n.pytest_cache\n"

	case "go":
		return fmt.Sprintf(`# Generated by cdnctl init — edit freely, it is yours now.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/app ./...

FROM alpine:3.20
COPY --from=build /out/app /app
ENV PORT=%d
EXPOSE %d
CMD ["/app"]
`, port, port), commonIgnore

	case "php":
		return fmt.Sprintf(`# Generated by cdnctl init — edit freely, it is yours now.
FROM php:8.3-apache
WORKDIR /var/www/html

COPY composer.json composer.lock* ./
RUN if [ -f composer.json ]; then \
      curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer && \
      composer install --no-dev --no-interaction --prefer-dist; \
    fi

COPY . .
RUN chown -R www-data:www-data /var/www/html

# Apache listens on 80 inside the container; the platform maps your port to it.
EXPOSE %d
`, port), commonIgnore + "vendor\n"

	case "static":
		return fmt.Sprintf(`# Generated by cdnctl init — edit freely, it is yours now.
FROM nginx:alpine
COPY . /usr/share/nginx/html
EXPOSE %d
`, port), commonIgnore

	default:
		return "", ""
	}
}

// ---------- entitlement ----------

type entitlementState struct {
	LoggedIn        bool   `json:"logged_in"`
	PlatformEnabled bool   `json:"platform_enabled"`
	PackageName     string `json:"package_name,omitempty"`
	MaxApps         int    `json:"max_container_apps,omitempty"`
	CheckError      string `json:"check_error,omitempty"`
}

func checkEntitlement() entitlementState {
	state := entitlementState{}
	cfg := readConfig()
	if cfg.Token == "" {
		return state
	}
	state.LoggedIn = true
	resp, err := requestJSON(http.MethodGet, "accounts", nil)
	if err != nil {
		state.CheckError = err.Error()
		return state
	}
	packages, ok := resp["account_packages"].([]any)
	if !ok {
		return state
	}
	for _, raw := range packages {
		pkg, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if enabled, ok := pkg["managed_platform_enabled"].(float64); ok && enabled == 1 {
			state.PlatformEnabled = true
			if name, ok := pkg["package_name"].(string); ok {
				state.PackageName = name
			}
			if max, ok := pkg["managed_max_container_apps"].(float64); ok {
				state.MaxApps = int(max)
			}
			break
		}
	}
	return state
}

// buyNowURL carries the need as context. The panel does not read these parameters
// YET (measured 2026-08-25) — sending them anyway is harmless today and turns into
// package pre-selection the day the page learns to read them.
func buyNowURL(endpoint string) string {
	return strings.TrimRight(endpoint, "/") + "/buy-now?ref=cdnctl&need=container-platform"
}

// ---------- decisions (the negotiation surface) ----------

type decision struct {
	ID       string   `json:"id"`
	Question string   `json:"question"`
	Options  []string `json:"options"`
	Chosen   string   `json:"chosen,omitempty"`
	Flag     string   `json:"flag"`
}

func openDecisions(project projectInfo, ent entitlementState, method string) []decision {
	methods := []string{}
	if project.HasGit {
		methods = append(methods, "git")
	}
	if project.HasCompose {
		methods = append(methods, "compose")
	}
	methods = append(methods, "source (coming-soon: tarball -> platform build)")
	decisions := []decision{{
		ID:       "deploy-method",
		Question: "Bu proje nasıl deploy edilsin?",
		Options:  methods,
		Chosen:   method,
		Flag:     "--method",
	}}
	if ent.LoggedIn && !ent.PlatformEnabled {
		decisions = append(decisions, decision{
			ID:       "package",
			Question: "Hesapta container platformu içeren paket yok — hangisi alınacak? (ödeme tarayıcıda, cdn.com.tr'de yapılır)",
			Options:  []string{"buy-now sayfasındaki container-platform içeren paketlerden biri"},
			Flag:     "--package",
		})
	}
	return decisions
}

// ---------- commands ----------

type initReport struct {
	Project     projectInfo      `json:"project"`
	Agents      []agentInfo      `json:"agents"`
	Entitlement entitlementState `json:"entitlement"`
	Decisions   []decision       `json:"decisions"`
	Findings    []finding        `json:"findings"`
	Wrote       []string         `json:"wrote"`
	NextSteps   []string         `json:"next_steps"`
}

func cmdInit(args parsedArgs) error {
	dir := option(args, "dir", ".")
	jsonOut := args.Bools["json"]
	dryRun := args.Bools["dry-run"]
	method := option(args, "method", "auto")

	report := initReport{
		Project: detectProject(dir),
		Agents:  detectAgents(dir),
	}
	report.Entitlement = checkEntitlement()

	// --wait: el sıkışmasının dönüş bacağı. Ödeme tarayıcıda biterken cdnctl burada
	// entitlement'ı yoklar ve paket aktifleşir aktifleşmez kaldığı yerden sürer —
	// panel tarafına hiçbir ek uç gerekmeden (accounts list bunu zaten görüyor).
	if args.Bools["wait"] && report.Entitlement.LoggedIn && !report.Entitlement.PlatformEnabled {
		cfg := readConfig()
		fmt.Println("✗ Hesapta container platformu içeren paket yok.")
		fmt.Println("  → Satın alma: " + buyNowURL(cfg.Endpoint))
		fmt.Println("  Ödeme tamamlanınca burada otomatik devam edeceğim (Ctrl+C ile vazgeçebilirsiniz)...")
		deadline := time.Now().Add(30 * time.Minute)
		for time.Now().Before(deadline) {
			time.Sleep(15 * time.Second)
			report.Entitlement = checkEntitlement()
			if report.Entitlement.PlatformEnabled {
				fmt.Printf("✓ Paket aktif: %s — devam ediliyor.\n\n", report.Entitlement.PackageName)
				break
			}
			fmt.Println("  ... ödeme bekleniyor")
		}
		if !report.Entitlement.PlatformEnabled {
			fmt.Println("Zaman aşımı: ödeme görünmedi. Ödemeden sonra `cdnctl init` yeterli — kaldığı yerden sürer.")
		}
	}
	report.Findings = runChecks(dir)
	report.Decisions = openDecisions(report.Project, report.Entitlement, method)

	if !dryRun {
		if wrote, err := writeManifest(dir, report.Project, method); err != nil {
			return err
		} else if wrote {
			report.Wrote = append(report.Wrote, "cdnctl.yaml")
		}
		wroteDocker, err := writeDockerfile(dir, report.Project)
		if err != nil {
			return err
		}
		report.Wrote = append(report.Wrote, wroteDocker...)
		if len(wroteDocker) > 0 {
			report.Project.HasDockerfile = true
		}
		if !args.Bools["no-agent-bridge"] {
			touched, err := writeAgentBridge(dir, report.Project)
			if err != nil {
				return err
			}
			report.Wrote = append(report.Wrote, touched...)
		}
	}

	cfg := readConfig()
	switch {
	case !report.Entitlement.LoggedIn:
		report.NextSteps = append(report.NextSteps,
			"cdnctl login  (hesabınız yoksa kayıt+paket: "+buyNowURL(cfg.Endpoint)+" — ödeme tarayıcıda biter, sonra `cdnctl init` yeniden çalıştırın, kaldığı yerden sürer)")
	case !report.Entitlement.PlatformEnabled:
		report.NextSteps = append(report.NextSteps,
			"Container platformu içeren paket gerekiyor: "+buyNowURL(cfg.Endpoint)+" (ödeme tarayıcıda; sonra `cdnctl init` tekrar — devam eder)")
	default:
		report.NextSteps = append(report.NextSteps,
			fmt.Sprintf("Paket hazır (%s, %d app hakkı). Sıradaki adım: `cdnctl deploy` — kaynak koddan build edip canlıya alır (git/registry gerekmez).",
				report.Entitlement.PackageName, report.Entitlement.MaxApps))
	}
	// Deploy needs a Dockerfile and init could not write one for this stack:
	// say so here rather than letting deploy fail with a message that points
	// back at init, which is a loop with no exit.
	if !report.Project.HasDockerfile && report.Entitlement.PlatformEnabled {
		report.NextSteps = append([]string{
			fmt.Sprintf("Bu proje tipi (%s) için hazır Dockerfile şablonumuz yok — bir Dockerfile yazın, sonra `cdnctl deploy`. (Şablon üretebildiklerimiz: node, python, go, php, statik site.)", report.Project.Language),
		}, report.NextSteps...)
	}
	if hasErrors(report.Findings) {
		report.NextSteps = append([]string{"Önce `cdnctl check` hatalarını düzeltin (deploy sonrası site açılmaz)."}, report.NextSteps...)
	}

	if jsonOut {
		return printJSONValue(report)
	}
	printInitHuman(report)
	return nil
}

func cmdCheck(args parsedArgs) error {
	dir := option(args, "dir", ".")
	findings := runChecks(dir)
	if args.Bools["json"] {
		if err := printJSONValue(map[string]any{"findings": findings, "errors": countSeverity(findings, "error"), "warnings": countSeverity(findings, "warning")}); err != nil {
			return err
		}
	} else {
		if len(findings) == 0 {
			fmt.Println("✓ Temiz: bilinen deploy engellerinden hiçbiri bulunamadı.")
		}
		for _, f := range findings {
			loc := ""
			if f.File != "" {
				loc = " (" + f.File
				if f.Line > 0 {
					loc += fmt.Sprintf(":%d", f.Line)
				}
				loc += ")"
			}
			fmt.Printf("[%s] %s%s\n        %s\n        → %s\n", strings.ToUpper(f.Severity), f.Rule, loc, f.Message, f.Fix)
		}
	}
	if hasErrors(findings) {
		return errExit(1)
	}
	return nil
}

func hasErrors(findings []finding) bool {
	return countSeverity(findings, "error") > 0
}

func countSeverity(findings []finding, sev string) int {
	n := 0
	for _, f := range findings {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

func printInitHuman(r initReport) {
	fmt.Printf("Proje    : %s (%s", r.Project.Name, r.Project.Language)
	if r.Project.Framework != "" {
		fmt.Printf("/%s", r.Project.Framework)
	}
	if r.Project.Port != 0 {
		fmt.Printf(", port %d", r.Project.Port)
	}
	fmt.Println(")")
	if len(r.Agents) > 0 {
		names := []string{}
		for _, a := range r.Agents {
			names = append(names, a.Name+" ("+a.Evidence+")")
		}
		fmt.Printf("Agent    : %s\n", strings.Join(names, ", "))
	}
	if r.Entitlement.LoggedIn {
		if r.Entitlement.PlatformEnabled {
			fmt.Printf("Paket    : ✓ %s (max %d app)\n", r.Entitlement.PackageName, r.Entitlement.MaxApps)
		} else {
			fmt.Println("Paket    : ✗ container platformu yok")
		}
	} else {
		fmt.Println("Oturum   : ✗ login gerekiyor")
	}
	if n := countSeverity(r.Findings, "error"); n > 0 {
		fmt.Printf("Karne    : %d HATA, %d uyarı — ayrıntı: cdnctl check\n", n, countSeverity(r.Findings, "warning"))
	} else if n := countSeverity(r.Findings, "warning"); n > 0 {
		fmt.Printf("Karne    : %d uyarı — ayrıntı: cdnctl check\n", n)
	}
	if len(r.Wrote) > 0 {
		fmt.Printf("Yazıldı  : %s\n", strings.Join(r.Wrote, ", "))
	}
	fmt.Println()
	for _, s := range r.NextSteps {
		fmt.Println("→ " + s)
	}
}

func printJSONValue(v any) error {
	data, err := marshalIndentNoHTMLEscape(v)
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func absOrSelf(dir string) string {
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}
