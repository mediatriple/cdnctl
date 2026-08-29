package main

// cdnctl init / cdnctl check — the local half of the vibe-coder deploy flow.
//
// Design (kb/notes/discovery_topics/cdnctl-init-vibe-deploy.md): the primary user is
// often not a human but the AI agent sitting next to them, working in this very
// directory. So both commands speak two languages: human text, and --json whose shape
// is a NEGOTIATION interface — "these decisions are open, these are the options" — so
// a local agent can pick (--method; package choice stays human, in the browser) instead of a human clicking through a
// wizard. Payment stays on cdn.com.tr in the browser; cdnctl only carries context
// there and picks the flow back up afterwards.
//
// Everything in this file runs locally. `check` never opens a network connection;
// `init` only calls the API to read entitlements, and only when a token exists.

import (
	"bytes"
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

		if loc := findOutsideComments(content, reListenLocalhost); loc != nil && !strings.Contains(base, "test") {
			findings = append(findings, finding{
				Rule: "bind-localhost", Severity: "error", File: rel(path), Line: lineOf(content, loc[0]),
				Message: T("The app binds to 127.0.0.1/localhost — nothing outside the container can reach it, so the site will not open once deployed."),
				Fix:     T("Bind 0.0.0.0 instead (e.g. app.listen(PORT) — dropping the host argument is enough)."),
			})
		}
		if !isEnvExample && base != "Dockerfile" {
			if loc := reSecretAssign.FindIndex(content); loc != nil {
				findings = append(findings, finding{
					Rule: "secret-in-code", Severity: "error", File: rel(path), Line: lineOf(content, loc[0]),
					Message: T("A secret (API key, token or password) appears to be hard-coded."),
					Fix:     T("Move the value out of the code and pass it with `cdnctl container apps update --secret KEY=VALUE`; read it via process.env/os.environ."),
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
			Message: T("SQLite is in use. A file database loses data when the container restarts, and cannot be shared across replicas."),
			Fix:     T("Attach a persistent volume (--persistent-mount-path) or move to a managed MySQL/Postgres add-on — migration help: cdn.com.tr/help/platforms."),
		})
	}
	if !sawHealth {
		findings = append(findings, finding{
			Rule: "no-healthcheck", Severity: "warning",
			Message: T("No healthcheck path (/health) found. The platform cannot tell whether your app is alive, so recovery after a crash is delayed."),
			Fix:     T("Add a simple GET /health that returns 200, and pass --healthcheck /health on deploy."),
		})
	}
	if sawListen && !sawPortEnv {
		findings = append(findings, finding{
			Rule: "hardcoded-port", Severity: "warning",
			Message: T("The port is hard-coded and the PORT environment variable is ignored."),
			Fix:     T("Use the const PORT = process.env.PORT || <port> pattern; the platform supplies the port through the environment."),
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
				Message: T("There is a .env file and .gitignore does not list it — secrets will land in the repository."),
				Fix:     T("Add a `.env` line to .gitignore and move the values to --secret."),
			})
		}
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "Dockerfile")); err != nil {
		findings = append(findings, finding{
			Rule: "no-dockerfile", Severity: "info",
			Message: T("No Dockerfile."),
			Fix:     T("`cdnctl init` can write a template for the detected language."),
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
					Message: T("`COPY . .` in the Dockerfile copies your local node_modules into the image — native modules built on your machine will not run in the container (ERR_DLOPEN_FAILED)."),
					Fix:     T("Add a `node_modules` line to .dockerignore; dependencies are installed by npm install inside the image."),
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
  Pick and answer via flags (e.g. ` + "`--method`" + `). If the account lacks a
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

// projectHasHealthRoute reports whether the code actually answers a health
// path. It is the same signal the no-healthcheck rule warns about, exposed so
// deploy can stop configuring a probe the app cannot satisfy.
func projectHasHealthRoute(dir string) bool {
	found := false
	scanProjectFiles(dir, func(path string, content []byte) {
		if found || filepath.Base(path) == "cdnctl.yaml" {
			return
		}
		if reHealthRoute.Match(content) {
			found = true
		}
	})
	return found
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
	// Only claim a health path the code actually serves. Writing "/health" into
	// the manifest of an app that has no such route makes the platform kill a
	// perfectly healthy container for failing a probe it was never going to pass.
	health := "healthcheck: /health"
	if !projectHasHealthRoute(dir) {
		health = "# healthcheck: /health   # add a route that returns 200, then uncomment"
	}
	manifest := fmt.Sprintf(`# cdnctl project manifest — `+"`cdnctl deploy`"+` reads this.
name: %s
language: %s
port: %d
%s
deploy:
  method: %s   # source (tarball -> platform build) | git | compose
`, project.Name, project.Language, port, health, method)
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

// readManifestValue reads one flat key from cdnctl.yaml. The manifest is
// deliberately a handful of top-level scalars, so this stays a line scan rather
// than pulling in a YAML dependency.
func readManifestValue(dir, key string) string {
	raw, err := os.ReadFile(filepath.Join(dir, "cdnctl.yaml"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || !strings.HasPrefix(trimmed, key+":") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, key+":"))
		if idx := strings.Index(value, " #"); idx >= 0 {
			value = strings.TrimSpace(value[:idx])
		}
		return strings.Trim(value, `"'`+"`")
	}
	return ""
}

// setManifestValue records a key in cdnctl.yaml, appending it when absent.
// Writing the app id after the first deploy is what makes later deploys
// unambiguous: "the app this folder created" instead of "some app with a
// matching name", which is the difference between a routine redeploy and
// overwriting someone else's running service.
func setManifestValue(dir, key, value string) error {
	path := filepath.Join(dir, "cdnctl.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), key+":") {
			lines[i] = key + ": " + value
			return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
		}
	}
	body := strings.TrimRight(string(raw), "\n") + "\n" + key + ": " + value + "\n"
	return os.WriteFile(path, []byte(body), 0o644)
}

// printAccountSwitchNextStep continues the sentence `cdnctl accounts use`
// starts. Outside a project folder there is nothing useful to say, so it stays
// quiet; inside one it answers the question the switch was made to answer —
// can this account deploy, and what do I run now.
func printAccountSwitchNextStep(dir string) {
	project := detectProject(dir)
	hasManifest := readManifestValue(dir, "name") != ""
	if project.Language == "unknown" && !hasManifest {
		return
	}

	ent := checkEntitlement()
	switch {
	case !ent.LoggedIn:
		return
	case !ent.PlatformEnabled:
		fmt.Println()
		fmt.Println(T("→ This account has no package that includes the container platform. `cdnctl init` shows the detail and your options."))
	case !ent.PlatformActive:
		fmt.Println()
		fmt.Println(T("→ The container platform is not active on this account either. Run `cdnctl init` to see your options."))
	case hasManifest:
		fmt.Println()
		fmt.Printf(T("✓ The container platform is ready on this account (%s). Next step: `cdnctl deploy`\n"), ent.PackageName)
	default:
		fmt.Println()
		fmt.Printf(T("✓ The container platform is ready on this account (%s). Next step: `cdnctl init`\n"), ent.PackageName)
	}
}

// ---------- entitlement ----------

type entitlementState struct {
	LoggedIn        bool   `json:"logged_in"`
	PlatformEnabled bool   `json:"platform_enabled"`
	PackageName     string `json:"package_name,omitempty"`
	MaxApps         int    `json:"max_container_apps,omitempty"`
	CheckError      string `json:"check_error,omitempty"`
	// PlatformActive separates "your package allows container apps" from "this
	// account actually has the Managed Container Apps platform". Only the first
	// was ever checked, so init reported "Paket hazır" and deploy then died at
	// upload time with a 409 the user had no way to anticipate.
	PlatformActive bool   `json:"platform_active"`
	ActivateBlock  string `json:"activate_blocked_reason,omitempty"`
	// What the user could switch to instead of being told "no". Accounts here
	// are ones that can already run container apps; SparePackages are packages
	// they have paid for and not yet assigned to any account.
	ReadyAccounts []readyAccount `json:"ready_accounts,omitempty"`
	SparePackages []sparePackage `json:"spare_packages,omitempty"`
}

type readyAccount struct {
	UUID  string `json:"uuid"`
	Label string `json:"label,omitempty"`
}

type sparePackage struct {
	Name    string `json:"package_name"`
	MaxApps int    `json:"max_container_apps,omitempty"`
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
	// account_packages is NOT this account's package — the endpoint returns the
	// packages the user has paid for and not yet assigned to any account
	// (its query is literally "account_packages row IS NULL"). Reading it as an
	// entitlement is why init announced "Paket hazır" to someone whose account
	// could not deploy at all. It is still worth reading: an unassigned package
	// is the cheapest way out of a blocked account, so we offer it as a choice.
	packages, _ := resp["account_packages"].([]any)
	for _, raw := range packages {
		pkg, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if enabled, ok := pkg["managed_platform_enabled"].(float64); !ok || enabled != 1 {
			continue
		}
		spare := sparePackage{}
		if name, ok := pkg["package_name"].(string); ok {
			spare.Name = name
		}
		if max, ok := pkg["managed_max_container_apps"].(float64); ok {
			spare.MaxApps = int(max)
		}
		state.SparePackages = append(state.SparePackages, spare)
		if !state.PlatformEnabled {
			state.PlatformEnabled = true
			state.PackageName = spare.Name
			state.MaxApps = spare.MaxApps
		}
	}

	// Accounts that already carry the container platform: switching to one of
	// these needs no purchase and no activation.
	if accounts, ok := resp["accounts"].([]any); ok {
		cfg := readConfig()
		for _, raw := range accounts {
			acc, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			enabled := false
			switch flag := acc["platform_apps_enabled"].(type) {
			case bool:
				enabled = flag
			case float64:
				enabled = flag == 1
			}
			uuid, _ := acc["uuid"].(string)
			if !enabled || uuid == "" || uuid == cfg.Account {
				continue
			}
			label, _ := acc["domain"].(string)
			state.ReadyAccounts = append(state.ReadyAccounts, readyAccount{UUID: uuid, Label: label})
		}
	}

	if state.PlatformEnabled {
		state.PlatformActive, state.ActivateBlock = containerPlatformActive()
	}
	// When the account really can deploy, its own limits come from the
	// account-scoped preflight — not from the unassigned-package list above,
	// which describes packages sitting in the user's basket rather than
	// anything this account is entitled to.
	if state.PlatformActive {
		if name, max, ok := accountEntitlement(); ok {
			if name != "" {
				state.PackageName = name
			}
			if max > 0 {
				state.MaxApps = max
			}
		}
	}
	return state
}

// accountEntitlement reads the limits the platform will actually enforce for
// the selected account.
func accountEntitlement() (string, int, bool) {
	cfg := readConfig()
	if cfg.Account == "" {
		return "", 0, false
	}
	resp, err := requestJSON(http.MethodGet, "accounts/"+cfg.Account+"/platform/container/preflight", nil)
	if err != nil {
		return "", 0, false
	}
	ent, _ := resp["entitlements"].(map[string]any)
	if ent == nil {
		return "", 0, false
	}
	name, _ := ent["package_name"].(string)
	limits, _ := ent["limits"].(map[string]any)
	max := 0
	if limits != nil {
		if v, ok := limits["max_container_apps"].(float64); ok {
			max = int(v)
		}
	}
	return name, max, true
}

// containerPlatformActive reports whether this account really has the managed
// container platform. The entitlement flag on the package is necessary but not
// sufficient: the platform row is created by a separate activation step, and
// the container endpoints answer 409 until it exists.
//
// It reads accounts/{uuid}/platform, which reports both the platform type and
// the additive platform_apps_enabled flag. Probing the apps listing instead
// looks like it works and is useless: that endpoint does not require the
// platform, so it answers 200 for an account that cannot deploy at all.
func containerPlatformActive() (bool, string) {
	cfg := readConfig()
	if cfg.Account == "" {
		return false, ""
	}
	resp, err := requestJSON(http.MethodGet, "accounts/"+cfg.Account+"/platform", nil)
	if err != nil {
		// Unknown state: do not invent a blocker the user cannot act on.
		return true, ""
	}
	platform, _ := resp["platform"].(map[string]any)
	if platform == nil {
		return false, ""
	}
	kind, _ := platform["type"].(string)
	if kind == "managed-container" {
		return true, ""
	}
	// Container apps can run alongside another delivery type, but only once the
	// additive flag is set — that is what activation does.
	if enabled, ok := platform["platform_apps_enabled"].(bool); ok && enabled {
		return true, ""
	}
	if kind != "" {
		return false, fmt.Sprintf(T("this account runs the %s platform"), kind)
	}
	return false, ""
}

// activateContainerPlatform turns the entitlement into a usable platform. The
// panel button does exactly this call; doing it from the CLI keeps a first
// deploy from dead-ending on a step nobody told the user about.
func activateContainerPlatform() (string, error) {
	cfg := readConfig()
	if cfg.Account == "" {
		return "", fmt.Errorf(T("no account selected"))
	}
	resp, err := requestJSON(http.MethodPost, "accounts/"+cfg.Account+"/platform/enable-apps", map[string]any{})
	if err != nil {
		return "", err
	}
	if status, _ := resp["status"].(string); status != "success" {
		msg, _ := resp["message"].(string)
		if msg == "" {
			msg = "aktivasyon reddedildi"
		}
		return "", fmt.Errorf("%s", msg)
	}
	msg, _ := resp["message"].(string)
	return msg, nil
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
	methods = append(methods, "source (tarball -> platform build; works with a plain folder)")
	decisions := []decision{{
		ID:       "deploy-method",
		Question: T("How should this project be deployed?"),
		Options:  methods,
		Chosen:   method,
		Flag:     "--method",
	}}
	if ent.LoggedIn && !ent.PlatformEnabled {
		// This decision is deliberately not answerable with a flag: package choice
		// and payment happen in the browser, on cdn.com.tr, by a human. The agent's
		// move is to hand over the URL and wait — advertising a --package flag here
		// promised an automation that must not exist.
		decisions = append(decisions, decision{
			ID:       "package",
			Question: T("This account has no package with the container platform — which one do you want? (payment happens in the browser, on cdn.com.tr)"),
			Options:  []string{T("have a human pick and pay on the buy-now page, then `cdnctl init --wait` resumes by itself")},
			Flag:     "",
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
	Notes       []string         `json:"notes,omitempty"`
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
		fmt.Println(T("✗ This account has no package that includes the container platform."))
		fmt.Println(T("  → Purchase: ") + buyNowURL(cfg.Endpoint))
		fmt.Println(T("  I will continue here automatically once the payment completes (Ctrl+C to stop waiting)..."))
		deadline := time.Now().Add(30 * time.Minute)
		for time.Now().Before(deadline) {
			time.Sleep(15 * time.Second)
			report.Entitlement = checkEntitlement()
			if report.Entitlement.PlatformEnabled {
				fmt.Printf(T("✓ Package active: %s — continuing.\n\n"), report.Entitlement.PackageName)
				break
			}
			fmt.Println(T("  ... waiting for payment"))
		}
		if !report.Entitlement.PlatformEnabled {
			fmt.Println(T("Timed out: no payment seen. After paying, `cdnctl init` is enough — it resumes where it left off."))
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
			T("`cdnctl login` — opens the browser: sign in there, or register if you have no account; approving links this terminal. A package purchase also finishes in the browser, and `cdnctl init` resumes afterwards."))
	case !report.Entitlement.PlatformEnabled:
		report.NextSteps = append(report.NextSteps,
			T("A package that includes the container platform is required: ")+buyNowURL(cfg.Endpoint)+T(" (payment in the browser; then `cdnctl init` again — it continues)"))
	case !report.Entitlement.PlatformActive && report.Entitlement.ActivateBlock != "":
		// A different platform type already owns this account; that is a decision
		// for a human, not something the CLI should silently rearrange. Dead-ending
		// there is not enough though — the way out is usually already paid for, so
		// list it.
		report.NextSteps = append(report.NextSteps,
			T("Container apps are not available on this account: ")+report.Entitlement.ActivateBlock+T(" — an account runs a single platform type."))
		for _, acc := range report.Entitlement.ReadyAccounts {
			label := acc.Label
			if label == "" {
				label = acc.UUID
			}
			report.NextSteps = append(report.NextSteps,
				fmt.Sprintf(T("Ready account: %s → `cdnctl accounts use %s`"), label, acc.UUID))
		}
		if len(report.Entitlement.SparePackages) > 0 {
			names := []string{}
			for _, pkg := range report.Entitlement.SparePackages {
				if pkg.MaxApps > 0 {
					names = append(names, fmt.Sprintf("%s (%d app)", pkg.Name, pkg.MaxApps))
				} else {
					names = append(names, pkg.Name)
				}
			}
			report.NextSteps = append(report.NextSteps,
				fmt.Sprintf(T("You own %d package(s) not assigned to any account: %s — assign one to a new account in the panel, then `cdnctl accounts use <uuid>`. No new purchase needed."),
					len(names), strings.Join(names, ", ")))
		}
		if len(report.Entitlement.ReadyAccounts) == 0 && len(report.Entitlement.SparePackages) == 0 {
			report.NextSteps = append(report.NextSteps,
				T("Create a separate account for container apps and assign a package to it (panel → Accounts)."))
		}
	case !report.Entitlement.PlatformActive && readConfig().Account == "":
		// Logged in with no account chosen. Nothing about the platform can be
		// decided yet — every account-scoped check is meaningless — so ask for the
		// account instead of reporting an activation that could not even be tried.
		report.NextSteps = append(report.NextSteps,
			T("No account selected yet — pick one: `cdnctl accounts use <uuid>` (list them: `cdnctl accounts ls`)"))
		for _, acc := range report.Entitlement.ReadyAccounts {
			label := acc.Label
			if label == "" {
				label = acc.UUID
			}
			report.NextSteps = append(report.NextSteps,
				fmt.Sprintf(T("Ready account: %s → `cdnctl accounts use %s`"), label, acc.UUID))
		}
	case !report.Entitlement.PlatformActive:
		// The package allows container apps but the platform was never activated.
		// Do it here: it is one idempotent call, and finding out at upload time
		// (409, mid-deploy) is exactly the dead-end this command exists to avoid.
		if msg, err := activateContainerPlatform(); err != nil {
			report.NextSteps = append(report.NextSteps,
				T("Your package covers container apps but the platform is not active, and activating it automatically failed: ")+err.Error()+T(" — enable Managed Container Apps from the panel."))
		} else {
			report.Entitlement.PlatformActive = true
			if msg != "" {
				report.Notes = append(report.Notes, T("Managed Container Apps has been enabled on this account."))
			}
			report.NextSteps = append(report.NextSteps,
				fmt.Sprintf(T("Package ready (%s, %d app allowance). Next step: `cdnctl deploy` — it builds from source and puts it live (no git, no registry)."),
					report.Entitlement.PackageName, report.Entitlement.MaxApps))
		}
	default:
		report.NextSteps = append(report.NextSteps,
			fmt.Sprintf(T("Package ready (%s, %d app allowance). Next step: `cdnctl deploy` — it builds from source and puts it live (no git, no registry)."),
				report.Entitlement.PackageName, report.Entitlement.MaxApps))
	}
	// Deploy needs a Dockerfile and init could not write one for this stack:
	// say so here rather than letting deploy fail with a message that points
	// back at init, which is a loop with no exit.
	if !report.Project.HasDockerfile && report.Entitlement.PlatformEnabled {
		report.NextSteps = append([]string{
			fmt.Sprintf(T("We have no Dockerfile template for this project type (%s) — write a Dockerfile, then `cdnctl deploy`. (We can template: node, python, go, php, static sites.)"), report.Project.Language),
		}, report.NextSteps...)
	}
	if hasErrors(report.Findings) {
		report.NextSteps = append([]string{T("Fix the `cdnctl check` errors first (otherwise the site will not open after deploy).")}, report.NextSteps...)
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
			fmt.Println(T("✓ Clean: none of the known deploy blockers were found."))
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

// findOutsideComments matches a rule against code only, skipping comment lines.
// A comment is documentation, not behaviour: the generated Dockerfile explains
// "bind 0.0.0.0, not 127.0.0.1" and the bind-localhost rule read its own advice
// as the defect, blocking deploy on a file cdnctl had just written. A user
// writing the same note in their own code hit it too.
func findOutsideComments(content []byte, re *regexp.Regexp) []int {
	offset := 0
	for _, line := range bytes.SplitAfter(content, []byte("\n")) {
		trimmed := bytes.TrimLeft(line, " \t")
		isComment := bytes.HasPrefix(trimmed, []byte("#")) ||
			bytes.HasPrefix(trimmed, []byte("//")) ||
			bytes.HasPrefix(trimmed, []byte("*")) ||
			bytes.HasPrefix(trimmed, []byte("/*"))
		if !isComment {
			if loc := re.FindIndex(line); loc != nil {
				return []int{offset + loc[0], offset + loc[1]}
			}
		}
		offset += len(line)
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
	fmt.Printf(T("Project  : %s (%s"), r.Project.Name, r.Project.Language)
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
		fmt.Printf(T("Agents   : %s\n"), strings.Join(names, ", "))
	}
	if r.Entitlement.LoggedIn {
		if r.Entitlement.PlatformEnabled {
			if r.Entitlement.PlatformActive {
				fmt.Printf(T("Package  : ✓ %s (max %d apps)\n"), r.Entitlement.PackageName, r.Entitlement.MaxApps)
			} else {
				// Do not dress an unassigned package up as this account's plan:
				// that is the line that told a blocked user everything was ready.
				fmt.Printf(T("Package  : the container platform is not active on this account (unassigned package you own: %s)\n"), r.Entitlement.PackageName)
			}
		} else {
			fmt.Println(T("Package  : ✗ no container platform"))
		}
	} else {
		fmt.Println(T("Session  : ✗ login required"))
	}
	if n := countSeverity(r.Findings, "error"); n > 0 {
		fmt.Printf(T("Report   : %d ERROR(S), %d warning(s) — detail: cdnctl check\n"), n, countSeverity(r.Findings, "warning"))
	} else if n := countSeverity(r.Findings, "warning"); n > 0 {
		fmt.Printf(T("Report   : %d warning(s) — detail: cdnctl check\n"), n)
	}
	for _, note := range r.Notes {
		fmt.Printf(T("Note     : %s\n"), note)
	}
	if len(r.Wrote) > 0 {
		fmt.Printf(T("Written  : %s\n"), strings.Join(r.Wrote, ", "))
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
