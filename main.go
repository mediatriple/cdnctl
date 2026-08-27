package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var version = "0.18.1"

// installChannel records how this binary was distributed. Direct downloads and
// `go install` builds keep the default and may self-update; builds packaged for
// a package manager are stamped (e.g. -X main.installChannel=homebrew) so
// `cdnctl update` routes the upgrade through that manager instead of fighting
// dpkg/rpm/brew over the same file — it still reports the version gap either way.
var installChannel = "direct"

type config struct {
	Endpoint string `json:"endpoint"`
	Token    string `json:"token"`
	Account  string `json:"account,omitempty"`
	Email    string `json:"email,omitempty"`
}

type parsedArgs struct {
	Positionals []string
	Options     map[string]string
	Bools       map[string]bool
	Multi       map[string][]string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		if exit, ok := isExitError(err); ok {
			if exit.message != "" {
				fmt.Fprintln(os.Stderr, exit.message)
			}
			os.Exit(exit.code)
		}
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage(os.Stderr)
		return errExit(2)
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(os.Stdout)
		return nil
	}
	if args[0] == "--version" || args[0] == "version" {
		fmt.Printf("cdnctl %s\n", version)
		return nil
	}

	command := args[0]
	parsed := parseArgs(args[1:])

	switch command {
	case "configure":
		return cmdConfigure(parsed)
	case "login":
		return cmdLogin(parsed)
	case "logout":
		return cmdLogout(parsed)
	case "whoami", "status":
		return cmdWhoami(parsed)
	case "update":
		return cmdUpdate(parsed)
	case "accounts":
		return cmdAccounts(parsed)
	case "cp":
		return cmdCp(parsed)
	case "files":
		return cmdFiles(parsed)
	case "container":
		return cmdContainer(parsed)
	case "object-storage":
		return cmdObjectStorage(parsed)
	case "purge":
		return cmdPurge(parsed)
	case "init":
		return cmdInit(parsed)
	case "check":
		return cmdCheck(parsed)
	case "deploy":
		return cmdDeploy(parsed)
	case "mcp":
		return cmdMcp(parsed)
	case "deploy-token":
		return cmdDeployToken(parsed)
	default:
		// Naming the command matters: printing the bare usage banner looks
		// identical to "that command does not exist", which is how someone on
		// an old build reads a missing `init`.
		fmt.Fprintf(os.Stderr, "cdnctl: unknown command %q\n", command)
		fmt.Fprintf(os.Stderr, "If you expected this command, this build may be too old (installed: %s). Check with: cdnctl update --check\n\n", version)
		usage(os.Stderr)
		return errExit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `cdnctl %s

Usage:
  cdnctl login [--email user@example.com] [--password <password>] [--endpoint https://cdn.com.tr]
                (omit --email/--password to be prompted; password input is hidden and never enters shell history)
  cdnctl whoami                     (show endpoint, logged-in user, and selected account; alias: status)
  cdnctl logout                     (forget the saved token, default account, and email; keeps the endpoint)
  cdnctl update --check
  cdnctl update [--yes] [--version 0.1.2] [--bin-dir "$HOME/.local/bin"] [--allow-downgrade]
                (Homebrew/apt/rpm installs: reports the version gap and the upgrade
                 command; with --yes on Homebrew cdnctl runs brew upgrade itself)
                (refuses to move to an older published version unless --allow-downgrade is given)
  cdnctl configure --endpoint https://cdn.com.tr --token <token>
  cdnctl accounts list              (full JSON for every account)
  cdnctl accounts ls                (compact list: uuid, domain, type)
  cdnctl accounts use <uuid>        (save a default account; --account is optional afterwards)
  cdnctl accounts current           (show the saved default account)
  cdnctl accounts clear             (forget the saved default account)
  cdnctl cp [-r] <localpath> [<account_uuid>:]<remotepath> [--force]
  cdnctl files put [--account <uuid>] --file <local> --target-path <path> [--force]
  cdnctl files ls [--account <uuid>] [--path <path>]
  cdnctl files rm [--account <uuid>] --path <path> --yes
  cdnctl files mkdir [--account <uuid>] --path <path>
  cdnctl container apps list --account <uuid>
  cdnctl container apps create --account <uuid> --name mobile-backend --image registry.example.com/acme/mobile-backend --tag 1.0.0 --port 8080 --healthcheck /health --healthcheck-type http|tcp|none --metrics-port 2112 --metrics-path /metrics --domain api.example.com --registry-credential <credential_uuid> --persistent-mount-path /app/data --persistent-storage-gb 5
  cdnctl container apps update --account <uuid> --app <app_uuid> --domain api.example.com --healthcheck-type tcp --metrics-port 2112 --env-json '{"APP_URL":"https://api.example.com"}' [--env KEY=VALUE ...] [--unset-env KEY ...] [--replace-env] [--secret KEY=VALUE ...] [--unset-secret KEY ...] [--persistent-storage-gb 10]
      env semantics: --env-json and --env MERGE into the existing env map by default;
      pass --replace-env to REPLACE the whole map (keys not listed are removed)
      secrets vs env: use --secret for sensitive values (API keys, tokens). A key
      lives in EITHER env or secrets, never both (last write wins); a secret of the
      same name takes precedence and the duplicate env key is dropped automatically.
  cdnctl container apps deploy --account <uuid> --app <app_uuid>
  cdnctl container apps expose --account <uuid> --app <app_uuid>
  cdnctl container apps restart --account <uuid> --app <app_uuid>
  cdnctl container apps scale --account <uuid> --app <app_uuid> --replicas 0
  cdnctl container apps delete --account <uuid> --app <app_uuid> --yes
  cdnctl container apps show --account <uuid> --app <app_uuid>
  cdnctl container apps rollback --account <uuid> --app <app_uuid> --revision <revision_uuid>
  cdnctl container apps create-preprod --account <uuid> --app <prod_app_uuid> --state shared|clone|isolated
  cdnctl container apps promote --account <uuid> --app <preprod_app_uuid>
  cdnctl container apps rollback-promotion --account <uuid> --app <prod_app_uuid>
  cdnctl container apps operations --account <uuid> --app <app_uuid>
  cdnctl container apps status --account <uuid> --app <app_uuid>
  cdnctl container apps wait --account <uuid> --app <app_uuid> --status running --timeout 300
  cdnctl container apps diagnose --account <uuid> --app <app_uuid>
  cdnctl container apps logs --account <uuid> --app <app_uuid> --tail 100 [--previous]
  cdnctl container preflight --account <uuid>
  cdnctl container registry-credentials list --account <uuid>
  cdnctl container registry-credentials create --account <uuid> --name docker --registry-url https://index.docker.io/v1/ --username <user> --password <token>
  cdnctl container registry-credentials delete --account <uuid> --credential <credential_uuid> --yes
  cdnctl container addons list --account <uuid> --app <app_uuid>
  cdnctl container addons enable-database --account <uuid> --app <app_uuid> --url-scheme mysql+pymysql
  cdnctl container addons disable-database --account <uuid> --app <app_uuid>
  cdnctl container addons enable-redis --account <uuid> --app <app_uuid> [--env-prefix REDIS]
  cdnctl container addons disable-redis --account <uuid> --app <app_uuid>
  cdnctl container addons enable-postgres --account <uuid> --app <app_uuid> [--env-prefix DATABASE] [--storage-mb 10240]
  cdnctl container addons disable-postgres --account <uuid> --app <app_uuid> [--delete-data --confirmation <app_name>]
  cdnctl container addons enable-nats --account <uuid> --app <app_uuid> [--env-prefix NATS] [--storage-mb 5120]
  cdnctl container addons disable-nats --account <uuid> --app <app_uuid> [--delete-data]
  cdnctl container imports list --account <uuid> --app <app_uuid>
  cdnctl container imports database --account <uuid> --app <app_uuid> --file dump.sql.gz
  cdnctl container imports files --account <uuid> --app <app_uuid> --file data.tar.gz --target-path /app/data
  cdnctl container imports cancel --account <uuid> --app <app_uuid> --import <import_uuid>
  cdnctl container jobs list --account <uuid> --app <app_uuid>
  cdnctl container jobs create --account <uuid> --app <app_uuid> --name order-shipping-sync --schedule "*/30 * * * *" --method POST --path "/orders/shipping-sync/run?limit=200" --secret-header-name X-Token --secret-source ORDER_SYNC_TOKEN
  cdnctl container jobs run --account <uuid> --app <app_uuid> --job <job_uuid> [--wait]
  cdnctl container jobs delete --account <uuid> --app <app_uuid> --job <job_uuid> --yes
  cdnctl container compose preview --account <uuid> --file docker-compose.yml
  cdnctl container compose apply --account <uuid> --file docker-compose.yml --yes
  cdnctl object-storage buckets list --account <uuid>
  cdnctl object-storage buckets create --account <uuid> --name <bucket>
  cdnctl object-storage buckets usage --account <uuid> --bucket <bucket_uuid>
  cdnctl object-storage buckets delete --account <uuid> --bucket <bucket_uuid> --yes
  cdnctl object-storage access-keys create --account <uuid> --bucket <bucket_uuid>
  cdnctl object-storage access-keys rotate --account <uuid> --key <key_uuid>
  cdnctl object-storage access-keys revoke --account <uuid> --key <key_uuid> --yes
  cdnctl object-storage bindings create --account <uuid> --app <app_uuid> --bucket <bucket_uuid> --access-key <key_uuid> --env-prefix S3
  cdnctl object-storage bindings delete --account <uuid> --app <app_uuid> --binding <binding_uuid> --yes
  cdnctl init [--dir .] [--json] [--dry-run] [--method auto|git|compose|source] [--no-agent-bridge] [--wait]
                (--wait: paket eksikse satin alma URL'ini gosterir ve odeme panelde
                 bitince OTOMATIK devam eder — 30 dk yoklama, 15 sn aralikla)
                (projeyi tanır, lokal AI agent'ları bulur ve AGENTS.md/CLAUDE.md'ye deploy
                 talimatı yazar, cdnctl.yaml üretir; eksik paket varsa satın alma URL'i verir —
                 ödeme tarayıcıda biter, init yeniden çalıştırılınca kaldığı yerden sürer)
  cdnctl deploy [--dir .] [--account <uuid>] [--name <app>] [--dockerfile Dockerfile] [--app <app_uuid>] [--skip-checks]
                (kaynagi tar'lar, yukler, platformda Kaniko ile build eder, uygulamayi
                 yeni imaja cevirir — yoksa olusturur+expose eder; git/registry GEREKMEZ)
  cdnctl deploy-token create [--account <uuid>] [--name "agent"]   (duz metin BIR KEZ gosterilir)
  cdnctl deploy-token list [--account <uuid>]
  cdnctl deploy-token revoke --id <token_id> [--account <uuid>]
                (deploy-only kapsam: kaynak yukle/build + uygulama yasam dongusu.
                 Agent'a bu token verilir: cdnctl configure --token cdnctl_...  —
                 panel/DNS/faturalamaya ASLA uzanamaz)
  cdnctl mcp    (cdnctl'i MCP sunucusu yapar: lokal AI agent'lar deploy/check/status
                 araclarini dogrudan kullanir — stdio, Claude Code/Cursor uyumlu)
  cdnctl check [--dir .] [--json]
                (deploy ÖNCESİ lokal karne: localhost bind, kodda secret, SQLite,
                 healthcheck eksikliği... hata varsa exit 1 — kod makineden çıkmaz)
  cdnctl purge --account <uuid> --path /sitemap.xml [--path /other] [--type exact|prefix|variants] [--save]
  cdnctl purge --account <uuid> --paths "/a,/b,/c" [--type prefix]
      --type exact     (default) just that URL
      --type prefix    that path and everything under it
      --type variants  every stored variant of the cache key
  cdnctl purge all --account <uuid> --yes
  cdnctl purge all status --account <uuid>

Destructive commands (delete/revoke/purge all) require an explicit --yes flag.

Environment:
  CDN_ENDPOINT, CDN_ACCESS_TOKEN, CDNCTL_BASE_URL, CDNCTL_BIN_DIR

Config:
  ~/.cdn/config.json

All commands print JSON.

`, version)
}

func parseArgs(args []string) parsedArgs {
	out := parsedArgs{Options: map[string]string{}, Bools: map[string]bool{}, Multi: map[string][]string{}}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			out.Positionals = append(out.Positionals, arg)
			continue
		}
		key := strings.TrimPrefix(arg, "--")
		value := "true"
		if strings.Contains(key, "=") {
			parts := strings.SplitN(key, "=", 2)
			key = parts[0]
			value = parts[1]
		} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
			i++
			value = args[i]
		}
		key = strings.ReplaceAll(key, "-", "_")
		if value == "true" {
			out.Bools[key] = true
		}
		out.Options[key] = value
		out.Multi[key] = append(out.Multi[key], value)
	}
	return out
}

func cmdConfigure(args parsedArgs) error {
	cfg := readConfig()
	if value, ok := args.Options["endpoint"]; ok && value != "" {
		cfg.Endpoint = value
	}
	if value, ok := args.Options["token"]; ok && value != "" && value != "true" {
		cfg.Token = value
	}
	if err := writeConfig(cfg); err != nil {
		return err
	}
	return printJSON(map[string]any{
		"status":      true,
		"message":     "cdnctl configured",
		"config_path": configPath(),
		"endpoint":    cfg.Endpoint,
	})
}

func cmdLogin(args parsedArgs) error {
	cfg := readConfig()
	if value, ok := args.Options["endpoint"]; ok && value != "" {
		cfg.Endpoint = value
	}
	email := requiredOrPrompt(args, "email", "Email", false)
	payload := map[string]any{
		"email":    email,
		"password": requiredOrPrompt(args, "password", "Password", true),
	}
	response, err := requestJSONPublic(cfg, http.MethodPost, "login", payload)
	if err != nil {
		return err
	}
	token, _ := response["token"].(string)
	if token == "" || response["status"] != "success" {
		_ = printJSON(map[string]any{
			"status":      false,
			"message":     firstString(response, "message", "error", "Login failed"),
			"http_status": response["_http_status"],
		})
		return errExit(1)
	}
	cfg.Token = token
	cfg.Email = email
	if err := writeConfig(cfg); err != nil {
		return err
	}
	// Login output intentionally omits user/id/email (see
	// TestLoginOutputDoesNotExposeUserIdentity); `cdnctl whoami` reveals the
	// identity on demand instead.
	return printJSON(map[string]any{
		"status":      true,
		"message":     "cdnctl logged in",
		"config_path": configPath(),
		"endpoint":    cfg.Endpoint,
	})
}

// cmdLogout forgets the saved session (token, default account, stored email)
// while keeping the endpoint, so the next command must re-authenticate. It
// edits the config file directly rather than via readConfig so a token coming
// from CDN_ACCESS_TOKEN/CDNCTL_TOKEN in the environment is never written into
// the file; that env token is out of our reach, so we point it out instead.
func cmdLogout(_ parsedArgs) error {
	var cfg config
	if data, err := os.ReadFile(configPath()); err == nil {
		_ = json.Unmarshal(data, &cfg)
	}
	hadToken := cfg.Token != ""
	cfg.Token = ""
	cfg.Account = ""
	cfg.Email = ""
	if err := writeConfig(cfg); err != nil {
		return err
	}
	if os.Getenv("CDN_ACCESS_TOKEN") != "" || os.Getenv("CDNCTL_TOKEN") != "" {
		fmt.Fprintln(os.Stderr, "Note: a token is still set via CDN_ACCESS_TOKEN/CDNCTL_TOKEN; unset it to fully log out.")
	}
	if hadToken {
		fmt.Println("Logged out. Cleared token, default account, and stored email.")
	} else {
		fmt.Println("No stored login; nothing to clear.")
	}
	return nil
}

// cmdWhoami reports the active session: the endpoint, the authenticated user
// (fetched live from /profile so it reflects the token actually in use), and
// the selected default account. It falls back to the locally stored email when
// the live lookup can't run (no token, offline, or an expired/rejected token).
func cmdWhoami(_ parsedArgs) error {
	cfg := readConfig()
	fmt.Printf("Endpoint: %s\n", cfg.Endpoint)

	if cfg.Token == "" {
		fmt.Println("User:     not logged in — run: cdnctl login")
	} else if resp, err := requestJSON(http.MethodGet, "profile", nil); err != nil {
		fmt.Printf("User:     %s (lookup error: %v)\n", storedWho(cfg), err)
	} else if user, ok := resp["user"].(map[string]any); ok && httpStatusOf(resp) == 200 {
		fmt.Printf("User:     %s\n", describeUser(user))
	} else if netErr, ok := resp["error"].(string); ok && httpStatusOf(resp) == 0 {
		fmt.Printf("User:     %s (stored; cannot reach %s: %s)\n", storedWho(cfg), cfg.Endpoint, netErr)
	} else {
		fmt.Printf("User:     %s (stored; token rejected [http %d] — re-run: cdnctl login)\n", storedWho(cfg), httpStatusOf(resp))
	}

	if cfg.Account != "" {
		switch label, state := accountLabel(cfg.Account); {
		case label != "":
			fmt.Printf("Account:  %s (%s)\n", cfg.Account, label)
		case state == "missing":
			fmt.Printf("Account:  %s (not in your accounts)\n", cfg.Account)
		default:
			fmt.Printf("Account:  %s\n", cfg.Account)
		}
	} else {
		fmt.Println("Account:  none selected — pick one with: cdnctl accounts use <uuid>")
	}
	return nil
}

// accountLabel resolves a human-friendly tag (domain or alias) for an account
// UUID via /accounts/show, so whoami can print "Account: <uuid> (example.com)".
// Return contract:
//
//	(label, "found")   -> a meaningful tag to show next to the UUID
//	("",    "found")   -> owned account but no tag worth showing (domain == uuid)
//	("",    "missing") -> the account is not among the caller's accounts
//	("",    "")        -> unknown: no token, offline, or the lookup failed
//
// Best-effort: any lookup failure degrades to ("", "") so whoami still prints
// the bare UUID rather than erroring.
func accountLabel(uuid string) (string, string) {
	resp, err := requestJSON(http.MethodGet, "accounts/show/"+uuid, nil)
	if err != nil || httpStatusOf(resp) != 200 {
		return "", ""
	}
	if resp["status"] != "success" {
		// The API answers 200 + status:error when the account is not found or
		// not owned by the caller.
		return "", "missing"
	}
	acc, ok := resp["account"].(map[string]any)
	if !ok {
		return "", "found"
	}
	// Prefer an explicit alias, then a real domain. Skip a domain that just
	// mirrors the UUID (hosting accounts with no domain assigned yet).
	if alias := firstString(acc, "alias", ""); alias != "" && alias != uuid {
		return alias, "found"
	}
	if domain := firstString(acc, "domain", ""); domain != "" && domain != uuid {
		return domain, "found"
	}
	return "", "found"
}

// storedWho returns the locally remembered login email, or "unknown".
func storedWho(cfg config) string {
	if cfg.Email != "" {
		return cfg.Email
	}
	return "unknown"
}

// describeUser renders a /profile user object as "email (Full Name)",
// omitting the name when absent. The internal numeric user id is deliberately
// NOT shown — it is an enumerable internal identifier of no use to the operator.
func describeUser(user map[string]any) string {
	// firstString treats its last arg as a literal fallback, so pass "".
	line := firstString(user, "email", "")
	if line == "" {
		line = "logged in"
	}
	if name := strings.TrimSpace(firstString(user, "name", "") + " " + firstString(user, "surname", "")); name != "" {
		line = fmt.Sprintf("%s (%s)", line, name)
	}
	return line
}

// httpStatusOf reads the status code doRequest stashed on a response map,
// tolerating both the int it writes and a float64 from any JSON round-trip.
func httpStatusOf(resp map[string]any) int {
	switch v := resp["_http_status"].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

type releaseTarget struct {
	Version      string
	OS           string
	Arch         string
	ArchiveName  string
	ChecksumName string
}

func cmdUpdate(args parsedArgs) error {
	baseURL := strings.TrimRight(option(args, "base_url", os.Getenv("CDNCTL_BASE_URL")), "/")
	if baseURL == "" {
		baseURL = "https://cdn.com.tr/downloads/cdnctl"
	}

	targetVersion := option(args, "version", "")
	if targetVersion == "" {
		latest, err := fetchText(baseURL + "/latest.txt")
		if err != nil {
			return printUpdateError("Failed to read latest cdnctl version.", err, 0)
		}
		targetVersion = strings.TrimSpace(latest)
	}
	if targetVersion == "" {
		return printUpdateError("Latest cdnctl version is empty.", nil, 0)
	}

	target, err := newReleaseTarget(targetVersion, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return printUpdateError(err.Error(), nil, 0)
	}

	// Compare installed vs published so an `update` never silently moves
	// backwards. cmp < 0: target is newer (a real update); 0: identical;
	// > 0: target is OLDER than what's installed (a downgrade).
	cmp := compareVersions(version, target.Version)

	if args.Bools["check"] {
		return printJSON(map[string]any{
			"status":           true,
			"current_version":  version,
			"latest_version":   target.Version,
			"update_available": cmp < 0,
			"is_downgrade":     cmp > 0,
		})
	}

	// A package manager owns this binary. Writing over it ourselves would leave
	// the package database pointing at a version that is no longer on disk, so
	// the upgrade has to go through that manager — but "update" should still
	// mean update: where it can be done without privilege escalation (Homebrew)
	// we run it, and everywhere else we report the exact command plus the
	// version gap, so nobody has to guess whether they are behind.
	if installChannel != "direct" {
		return updateViaPackageManager(installChannel, target.Version, cmp, args.Bools["yes"])
	}

	if cmp == 0 {
		return printJSON(map[string]any{
			"status":          true,
			"message":         "cdnctl is already current",
			"current_version": version,
			"latest_version":  target.Version,
		})
	}

	// The published version is older than what's installed. Refuse by default —
	// this is exactly what turned an accidental `update` into a downgrade — and
	// require an explicit --allow-downgrade to override.
	if cmp > 0 && !args.Bools["allow_downgrade"] {
		_ = printJSON(map[string]any{
			"status":          false,
			"message":         fmt.Sprintf("Refusing to downgrade: published cdnctl (%s) is older than the installed version (%s). Re-run with --allow-downgrade to force it, or --version <x.y.z> to target a specific build.", target.Version, version),
			"current_version": version,
			"target_version":  target.Version,
			"is_downgrade":    true,
		})
		return errExit(1)
	}

	if !args.Bools["yes"] {
		action := "Update"
		if cmp > 0 {
			action = "Downgrade"
		}
		return printJSON(map[string]any{
			"status":           true,
			"message":          action + " available. Re-run with --yes to replace the installed binary.",
			"current_version":  version,
			"latest_version":   target.Version,
			"update_available": cmp < 0,
			"is_downgrade":     cmp > 0,
		})
	}

	path, err := updateBinary(baseURL, target, option(args, "bin_dir", os.Getenv("CDNCTL_BIN_DIR")))
	if err != nil {
		return printUpdateError("cdnctl update failed.", err, 0)
	}

	message := "cdnctl updated"
	if cmp > 0 {
		message = "cdnctl downgraded"
	}
	return printJSON(map[string]any{
		"status":  true,
		"message": message,
		"from":    version,
		"to":      target.Version,
		"path":    path,
	})
}

func newReleaseTarget(versionValue, goos, goarch string) (releaseTarget, error) {
	osName := goos
	if osName != "linux" && osName != "darwin" && osName != "windows" {
		return releaseTarget{}, fmt.Errorf("Unsupported OS: %s", goos)
	}

	arch := goarch
	switch arch {
	case "amd64", "arm64":
	default:
		return releaseTarget{}, fmt.Errorf("Unsupported architecture: %s", goarch)
	}

	ext := ".tar.gz"
	if osName == "windows" {
		ext = ".zip"
	}

	archive := fmt.Sprintf("cdnctl-%s-%s-%s%s", versionValue, osName, arch, ext)
	return releaseTarget{
		Version:      versionValue,
		OS:           osName,
		Arch:         arch,
		ArchiveName:  archive,
		ChecksumName: fmt.Sprintf("cdnctl-%s-checksums.txt", versionValue),
	}, nil
}

// compareVersions compares dotted numeric versions (e.g. "0.14.0" vs "0.12.0").
// Returns -1 if a < b, 0 if equal, +1 if a > b. Missing components count as 0
// and any non-numeric suffix on a component is ignored, so "v1.2" and "1.2.0"
// compare equal.
func compareVersions(a, b string) int {
	pa, pb := parseVersion(a), parseVersion(b)
	for i := 0; i < len(pa); i++ {
		if pa[i] < pb[i] {
			return -1
		}
		if pa[i] > pb[i] {
			return 1
		}
	}
	return 0
}

func parseVersion(v string) [3]int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	var out [3]int
	for i, part := range strings.SplitN(v, ".", 3) {
		if i >= 3 {
			break
		}
		n := 0
		_, _ = fmt.Sscanf(part, "%d", &n) // stops at the first non-digit; empty -> 0
		out[i] = n
	}
	return out
}

func updateBinary(baseURL string, target releaseTarget, requestedBinDir string) (string, error) {
	checksums, err := fetchText(baseURL + "/" + target.ChecksumName)
	if err != nil {
		return "", err
	}
	expectedChecksum, err := checksumForArchive(checksums, target.ArchiveName)
	if err != nil {
		return "", err
	}

	archiveBytes, err := fetchBytes(baseURL + "/" + target.ArchiveName)
	if err != nil {
		return "", err
	}
	actual := sha256.Sum256(archiveBytes)
	if hex.EncodeToString(actual[:]) != expectedChecksum {
		return "", fmt.Errorf("checksum mismatch for %s", target.ArchiveName)
	}

	binaryBytes, err := extractCdnctlBinary(archiveBytes, target)
	if err != nil {
		return "", err
	}

	installPath := updateInstallPath(requestedBinDir)
	if err := installBinary(installPath, binaryBytes); err != nil {
		return "", err
	}
	return installPath, nil
}

// packageUpgradeCommand is the command that actually upgrades a
// package-managed install, and whether we can run it ourselves. Commands that
// need root are reported rather than executed: cdnctl never escalates
// privileges on its own.
func packageUpgradeCommand(channel string) (cmd []string, runnable bool) {
	switch channel {
	case "homebrew":
		return []string{"brew", "upgrade", "cdnctl"}, true
	case "deb":
		return []string{"sudo", "apt-get", "update", "&&", "sudo", "apt-get", "install", "--only-upgrade", "cdnctl"}, false
	case "rpm":
		return []string{"sudo", "dnf", "upgrade", "cdnctl"}, false
	case "docker":
		return []string{"docker", "pull", "cdncomtr/cdnctl:latest"}, false
	}
	return nil, false
}

// updateViaPackageManager handles `cdnctl update` for a binary owned by a
// package manager. It always reports current vs latest — the old behaviour
// returned "status": false with no version information at all, which reads as
// "nothing to do" to someone who is in fact several releases behind.
func updateViaPackageManager(channel, latest string, cmp int, assumeYes bool) error {
	cmdParts, runnable := packageUpgradeCommand(channel)
	cmdText := strings.Join(cmdParts, " ")
	if channel == "homebrew" {
		cmdText = "brew update && brew upgrade cdnctl"
	}

	if cmp >= 0 {
		message := "cdnctl is already current"
		if cmp > 0 {
			message = fmt.Sprintf("Installed cdnctl (%s) is newer than the published version (%s).", version, latest)
		}
		return printJSON(map[string]any{
			"status":           true,
			"message":          message,
			"current_version":  version,
			"latest_version":   latest,
			"update_available": false,
			"install_channel":  channel,
		})
	}

	if !runnable || !assumeYes {
		message := fmt.Sprintf("Update available: %s → %s. This cdnctl was installed with %s, so the upgrade runs through it: %s", version, latest, channelLabel(channel), cmdText)
		if runnable {
			message += " (or re-run with --yes and cdnctl will run it for you)"
		}
		return printJSON(map[string]any{
			"status":           true,
			"message":          message,
			"current_version":  version,
			"latest_version":   latest,
			"update_available": true,
			"install_channel":  channel,
			"upgrade_command":  cmdText,
		})
	}

	// Run the package manager for the user. Its own output goes straight to the
	// terminal: a brew upgrade can take a while and silence looks like a hang.
	fmt.Fprintf(os.Stderr, "cdnctl %s → %s — running: %s\n", version, latest, cmdText)
	steps := [][]string{{"brew", "update"}, cmdParts}
	for _, step := range steps {
		run := exec.Command(step[0], step[1:]...)
		run.Stdout = os.Stderr
		run.Stderr = os.Stderr
		if err := run.Run(); err != nil {
			_ = printJSON(map[string]any{
				"status":          false,
				"message":         fmt.Sprintf("%s failed. Run it yourself to see why: %s", strings.Join(step, " "), cmdText),
				"current_version": version,
				"latest_version":  latest,
				"install_channel": channel,
				"upgrade_command": cmdText,
			})
			return errExit(1)
		}
	}
	return printJSON(map[string]any{
		"status":           true,
		"message":          fmt.Sprintf("cdnctl upgraded through %s. Run `cdnctl version` to confirm.", channelLabel(channel)),
		"previous_version": version,
		"latest_version":   latest,
		"install_channel":  channel,
	})
}

// channelLabel is the human name of an install channel.
func channelLabel(channel string) string {
	switch channel {
	case "homebrew":
		return "Homebrew"
	case "deb":
		return "a .deb package"
	case "rpm":
		return "an .rpm package"
	case "docker":
		return "Docker"
	}
	return channel
}

// packageUpdateHint tells the operator which command actually upgrades a
// package-managed install.
func packageUpdateHint(channel string) string {
	switch channel {
	case "homebrew":
		return "This cdnctl was installed with Homebrew. Update it with: brew update && brew upgrade cdnctl"
	case "deb":
		return "This cdnctl was installed from a .deb package. Update it with: sudo apt-get update && sudo apt-get install --only-upgrade cdnctl"
	case "rpm":
		return "This cdnctl was installed from an .rpm package. Update it with: sudo dnf upgrade cdnctl"
	default:
		return fmt.Sprintf("This cdnctl was installed via %s; use that package manager to upgrade it.", channel)
	}
}

func updateInstallPath(requestedBinDir string) string {
	name := "cdnctl"
	if runtime.GOOS == "windows" {
		name = "cdnctl.exe"
	}
	if requestedBinDir != "" {
		return filepath.Join(requestedBinDir, name)
	}
	if current, err := os.Executable(); err == nil && current != "" && canWriteFile(current) {
		return current
	}
	return filepath.Join(homeDir(), ".local", "bin", name)
}

func canWriteFile(path string) bool {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	_ = file.Close()
	return true
}

func installBinary(path string, binary []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".cdnctl-update-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(binary); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func checksumForArchive(checksums, archiveName string) (string, error) {
	for _, line := range strings.Split(checksums, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		filename := strings.TrimPrefix(fields[1], "*")
		if filepath.Base(filename) == archiveName {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("checksum for %s not found", archiveName)
}

func extractCdnctlBinary(archive []byte, target releaseTarget) ([]byte, error) {
	if strings.HasSuffix(target.ArchiveName, ".zip") {
		return extractCdnctlFromZip(archive, target)
	}
	return extractCdnctlFromTarGz(archive, target)
}

func extractCdnctlFromTarGz(archive []byte, target releaseTarget) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	reader := tar.NewReader(gz)
	want := fmt.Sprintf("cdnctl-%s-%s-%s/cdnctl", target.Version, target.OS, target.Arch)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if header.Name == want {
			return io.ReadAll(reader)
		}
	}
	return nil, fmt.Errorf("cdnctl binary not found in %s", target.ArchiveName)
}

func extractCdnctlFromZip(archive []byte, target releaseTarget) ([]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, err
	}
	want := fmt.Sprintf("cdnctl-%s-%s-%s/cdnctl.exe", target.Version, target.OS, target.Arch)
	for _, file := range reader.File {
		if file.Name != want {
			continue
		}
		open, err := file.Open()
		if err != nil {
			return nil, err
		}
		defer open.Close()
		return io.ReadAll(open)
	}
	return nil, fmt.Errorf("cdnctl binary not found in %s", target.ArchiveName)
}

func fetchText(url string) (string, error) {
	data, err := fetchBytes(url)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func fetchBytes(url string) ([]byte, error) {
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, httpStatusError{Status: resp.StatusCode, URL: url}
	}
	return io.ReadAll(resp.Body)
}

func printUpdateError(message string, err error, httpStatus int) error {
	payload := map[string]any{
		"status":  false,
		"message": message,
	}
	if err != nil {
		payload["error"] = err.Error()
		var statusErr httpStatusError
		if errors.As(err, &statusErr) {
			httpStatus = statusErr.Status
		}
	}
	if httpStatus != 0 {
		payload["http_status"] = httpStatus
	}
	_ = printJSON(payload)
	return errExit(1)
}

type httpStatusError struct {
	Status int
	URL    string
}

func (e httpStatusError) Error() string {
	return fmt.Sprintf("HTTP %d for %s", e.Status, e.URL)
}

func cmdAccounts(args parsedArgs) error {
	action := "list"
	if len(args.Positionals) >= 1 {
		action = args.Positionals[0]
	}
	switch action {
	case "list":
		return printRequest(http.MethodGet, "accounts", nil)
	case "ls":
		return cmdAccountsLs()
	case "use":
		if len(args.Positionals) < 2 || args.Positionals[1] == "" {
			return fmt.Errorf("usage: cdnctl accounts use <uuid>")
		}
		cfg := readConfig()
		cfg.Account = args.Positionals[1]
		if err := writeConfig(cfg); err != nil {
			return err
		}
		fmt.Printf("Saved default account: %s\n", cfg.Account)
		fmt.Println("Account-scoped commands now use it automatically (override any time with --account).")
		return nil
	case "current":
		if account := readConfig().Account; account != "" {
			fmt.Println(account)
		} else {
			fmt.Println("No default account. Set one with: cdnctl accounts use <uuid>")
		}
		return nil
	case "clear":
		cfg := readConfig()
		cfg.Account = ""
		if err := writeConfig(cfg); err != nil {
			return err
		}
		fmt.Println("Cleared the default account.")
		return nil
	default:
		usage(os.Stderr)
		return errExit(2)
	}
}

// cmdAccountsLs prints a compact, human-friendly account list (uuid, domain,
// type) instead of the full `accounts list` JSON, which is large. Handy for
// finding the uuid to pass to `accounts use`.
func cmdAccountsLs() error {
	resp, err := requestJSON(http.MethodGet, "accounts", nil)
	if err != nil {
		return err
	}
	list, ok := resp["accounts"].([]any)
	if !ok {
		// Unexpected shape — fall back to the raw response so nothing is hidden.
		return printJSON(resp)
	}
	if len(list) == 0 {
		fmt.Fprintln(os.Stderr, "No accounts.")
		return nil
	}
	fmt.Fprintf(os.Stderr, "%-36s  %-32s  %s\n", "UUID", "DOMAIN", "TYPE")
	for _, item := range list {
		m, _ := item.(map[string]any)
		fmt.Printf("%-36s  %-32s  %s\n", strval(m["uuid"]), strval(m["domain"]), strval(m["cdn_method_type"]))
	}
	return nil
}

func strval(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// cmdCp is an scp-like alias for "files put": it takes a local file path and
// a "<account_uuid>:<remotepath>" destination and splits the destination on
// the FIRST colon (account UUIDs and remote paths never contain a colon, but
// this keeps the split unambiguous if a path ever does).
func cmdCp(args parsedArgs) error {
	// -r / -R (scp-style short flags) arrive as positionals because the parser
	// only recognizes --flags; pull them out here.
	recursive := args.Bools["recursive"]
	positionals := make([]string, 0, len(args.Positionals))
	for _, p := range args.Positionals {
		if p == "-r" || p == "-R" {
			recursive = true
			continue
		}
		positionals = append(positionals, p)
	}
	if len(positionals) < 2 {
		return fmt.Errorf("usage: cdnctl cp [-r] <localpath> [<account_uuid>:]<remotepath>")
	}
	localPath := positionals[0]
	destination := positionals[1]
	account, remotePath, hasColon := strings.Cut(destination, ":")
	if !hasColon {
		// No "<uuid>:" prefix: the whole token is the remote path and the
		// account comes from --account or the saved default account.
		remotePath = destination
		account = ""
	}
	if account == "" {
		resolved, err := resolveAccountE(args)
		if err != nil {
			return err
		}
		account = resolved
	}
	if remotePath == "" {
		return fmt.Errorf("destination must include a remote path, e.g. %q or %q", "uploads/pic.jpg", "<account_uuid>:uploads/pic.jpg")
	}
	info, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("cannot read local path %s: %w", localPath, err)
	}
	force := args.Bools["force"]

	if info.IsDir() {
		if !recursive {
			return fmt.Errorf("%s is a directory; pass -r to upload it recursively", localPath)
		}
		return cpRecursive(account, localPath, remotePath, force)
	}

	response, err := cpUploadFile(account, localPath, remotePath, force)
	if err != nil {
		return err
	}
	return printFileResponse(response)
}

// cpUploadFile uploads a single local file to accounts/<uuid>/files/put.
func cpUploadFile(account, localPath, target string, force bool) (map[string]any, error) {
	fields := map[string]string{"target_path": target}
	if force {
		fields["overwrite"] = "1"
	}
	return requestMultipart(http.MethodPost, fmt.Sprintf("accounts/%s/files/put", account), fields, "file", localPath)
}

// cpRecursive walks localDir and uploads every file under it to
// remoteBase/<path-relative-to-localDir>. The server creates each file's parent
// directories, so empty directories are simply skipped. Progress is written to
// stderr; a JSON summary is printed to stdout.
func cpRecursive(account, localDir, remoteBase string, force bool) error {
	localDir = filepath.Clean(localDir)
	remoteBase = strings.TrimRight(remoteBase, "/")
	uploaded, failed := 0, 0
	storageFullErr := errors.New("remote persistent storage is full")
	walkErr := filepath.Walk(localDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(localDir, path)
		if err != nil {
			return err
		}
		target := remoteBase + "/" + filepath.ToSlash(rel)
		resp, err := cpUploadFile(account, path, target, force)
		if err != nil {
			return err
		}
		if responseOK(resp) {
			uploaded++
			fmt.Fprintf(os.Stderr, "  uploaded  %s\n", target)
		} else {
			failed++
			msg := ""
			if m, ok := resp["message"].(string); ok && m != "" {
				msg = " — " + m
			}
			fmt.Fprintf(os.Stderr, "  FAILED    %s%s\n", target, msg)
			if responseStorageFull(resp) {
				return storageFullErr
			}
		}
		return nil
	})
	if errors.Is(walkErr, storageFullErr) {
		fmt.Fprintln(os.Stderr)
		_ = printJSON(map[string]any{
			"status":     false,
			"uploaded":   uploaded,
			"failed":     failed,
			"aborted":    true,
			"error_code": "storage_full",
			"message":    "Persistent storage is full; recursive upload stopped before creating more failed targets.",
		})
		return errExit(1)
	}
	if walkErr != nil {
		return walkErr
	}
	fmt.Fprintln(os.Stderr)
	if err := printJSON(map[string]any{"status": failed == 0, "uploaded": uploaded, "failed": failed}); err != nil {
		return err
	}
	if failed > 0 {
		return errExit(1)
	}
	return nil
}

// responseOK reads the {status: bool|string} envelope returned by the file API.
func responseOK(resp map[string]any) bool {
	switch v := resp["status"].(type) {
	case bool:
		return v
	case string:
		return v == "success" || v == "true"
	}
	return false
}

func responseStorageFull(resp map[string]any) bool {
	if strings.EqualFold(strval(resp["error_code"]), "storage_full") {
		return true
	}

	for _, key := range []string{"_http_status", "http_status"} {
		switch value := resp[key].(type) {
		case float64:
			if int(value) == http.StatusInsufficientStorage {
				return true
			}
		case int:
			if value == http.StatusInsufficientStorage {
				return true
			}
		case string:
			if value == strconv.Itoa(http.StatusInsufficientStorage) {
				return true
			}
		}
	}

	return false
}

func printFileResponse(response map[string]any) error {
	if err := printJSON(response); err != nil {
		return err
	}
	if !responseOK(response) {
		return errExit(1)
	}
	return nil
}

func cmdFiles(args parsedArgs) error {
	if len(args.Positionals) < 1 {
		usage(os.Stderr)
		return errExit(2)
	}
	action := args.Positionals[0]
	account := resolveAccount(args)
	switch action {
	case "put":
		localFile := required(args, "file")
		if _, err := os.Stat(localFile); err != nil {
			return fmt.Errorf("cannot read local file %s: %w", localFile, err)
		}
		fields := map[string]string{"target_path": required(args, "target_path")}
		if args.Bools["force"] {
			fields["overwrite"] = "1"
		}
		response, err := requestMultipart(http.MethodPost, fmt.Sprintf("accounts/%s/files/put", account), fields, "file", localFile)
		if err != nil {
			return err
		}
		return printFileResponse(response)
	case "ls":
		return printRequest(http.MethodPost, fmt.Sprintf("accounts/%s/files/list", account), map[string]any{
			"path": option(args, "path", ""),
		})
	case "rm":
		if err := requireYes(args, "delete file"); err != nil {
			return err
		}
		return printRequest(http.MethodPost, fmt.Sprintf("accounts/%s/files/delete", account), map[string]any{
			"path": required(args, "path"),
		})
	case "mkdir":
		return printRequest(http.MethodPost, fmt.Sprintf("accounts/%s/files/mkdir", account), map[string]any{
			"path": required(args, "path"),
		})
	default:
		usage(os.Stderr)
		return errExit(2)
	}
}

func cmdPurge(args parsedArgs) error {
	account := resolveAccount(args)

	if len(args.Positionals) >= 1 && args.Positionals[0] == "all" {
		base := fmt.Sprintf("purge_management/%s", account)
		if args.Positionals[len(args.Positionals)-1] == "status" {
			return printRequest(http.MethodGet, base+"/purge_all_status", nil)
		}
		if err := requireYes(args, "purge the entire account cache"); err != nil {
			return err
		}
		return printRequest(http.MethodPost, base+"/purge_all", map[string]any{})
	}

	// Collect paths from repeatable --path and/or comma-separated --paths.
	paths := []string{}
	for _, p := range args.Multi["path"] {
		if p != "" && p != "true" {
			paths = append(paths, p)
		}
	}
	if value, ok := args.Options["paths"]; ok && value != "" && value != "true" {
		for _, p := range strings.Split(value, ",") {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				paths = append(paths, trimmed)
			}
		}
	}
	if len(paths) == 0 {
		return fmt.Errorf("at least one --path is required (e.g. --path /sitemap.xml)")
	}

	payload := map[string]any{
		"paths": paths,
		// exact = single URL, prefix = everything under the path (wildcard),
		// variants = every stored variant of the cache key.
		//
		// NOT mobile/desktop: that dimension is gone. The edge cache key is
		// $scheme$host$uri$is_args$args — no device component — and the
		// $is_mobile map still emitted into each generated config is dead
		// leftover. The old comment here described a scheme that no longer
		// exists and sent people looking for a device split that cannot occur.
		"type": option(args, "type", "exact"),
		"save": args.Bools["save"],
	}
	return printRequest(http.MethodPost, fmt.Sprintf("purge_management/%s/purge", account), payload)
}

func cmdContainer(args parsedArgs) error {
	if len(args.Positionals) < 1 {
		usage(os.Stderr)
		return errExit(2)
	}
	resource := args.Positionals[0]

	// "preflight" is a standalone sub-command with no further positional.
	if resource == "preflight" {
		account := resolveAccount(args)
		return printRequest(http.MethodGet, fmt.Sprintf("accounts/%s/platform/container/preflight", account), nil)
	}

	if len(args.Positionals) < 2 {
		usage(os.Stderr)
		return errExit(2)
	}
	action := args.Positionals[1]
	switch resource {
	case "apps":
		return cmdContainerApps(action, args)
	case "registry-credentials":
		return cmdRegistryCredentials(action, args)
	case "addons":
		return cmdAddons(action, args)
	case "imports":
		return cmdImports(action, args)
	case "jobs":
		return cmdJobs(action, args)
	case "compose":
		return cmdCompose(action, args)
	default:
		usage(os.Stderr)
		return errExit(2)
	}
}

func cmdContainerApps(action string, args parsedArgs) error {
	account := resolveAccount(args)
	if action == "list" {
		return printRequest(http.MethodGet, fmt.Sprintf("accounts/%s/platform/container/apps", account), nil)
	}
	if action == "create" {
		env, err := jsonMapOption(args, "env_json", false)
		if err != nil {
			return err
		}
		secrets, err := jsonMapOption(args, "secrets_json", false)
		if err != nil {
			return err
		}
		for _, pair := range args.Multi["secret"] {
			k, v, ok := strings.Cut(pair, "=")
			if !ok || k == "" {
				return fmt.Errorf("--secret expects KEY=VALUE, got %q", pair)
			}
			if secrets == nil {
				secrets = map[string]any{}
			}
			secrets[k] = v
		}
		for _, pair := range args.Multi["env"] {
			k, v, ok := strings.Cut(pair, "=")
			if !ok || k == "" {
				return fmt.Errorf("--env expects KEY=VALUE, got %q", pair)
			}
			if env == nil {
				env = map[string]any{}
			}
			env[k] = v
		}
		payload := map[string]any{
			"name":                       required(args, "name"),
			"image":                      required(args, "image"),
			"tag":                        option(args, "tag", ""),
			"port":                       intOption(args, "port", 8080),
			"healthcheck_path":           option(args, "healthcheck", "/health"),
			"healthcheck_type":           nullableOption(args, "healthcheck_type"),
			"metrics_port":               nullableIntOption(args, "metrics_port"),
			"metrics_path":               nullableOption(args, "metrics_path"),
			"replicas":                   intOption(args, "replicas", 1),
			"resource_plan":              option(args, "plan", "starter"),
			"domains":                    domains(args),
			"env":                        env,
			"secrets":                    secrets,
			"registry_credential_uuid":   nullableOption(args, "registry_credential"),
			"persistent_storage_enabled": option(args, "persistent_mount_path", "") != "",
			"persistent_mount_path":      nullableOption(args, "persistent_mount_path"),
			"persistent_storage_size_gb": nullableIntOption(args, "persistent_storage_gb"),
		}
		return printRequest(http.MethodPost, fmt.Sprintf("accounts/%s/platform/container/apps", account), payload)
	}

	app := required(args, "app")
	base := fmt.Sprintf("accounts/%s/platform/container/apps/%s", account, app)
	switch action {
	case "update":
		return cmdContainerAppUpdate(base, args)
	case "deploy":
		return printRequest(http.MethodPost, base+"/deploy", map[string]any{})
	case "expose":
		return printRequest(http.MethodPost, base+"/expose", map[string]any{})
	case "restart":
		return printRequest(http.MethodPost, base+"/restart", map[string]any{})
	case "scale":
		required(args, "replicas") // validates presence before building payload
		return printRequest(http.MethodPost, base+"/scale", map[string]any{
			"replicas": intOption(args, "replicas", 0),
		})
	case "delete":
		if err := requireYes(args, "delete container app"); err != nil {
			return err
		}
		return printRequest(http.MethodDelete, base, nil)
	case "show":
		return printRequest(http.MethodGet, base, nil)
	case "rollback":
		return printRequest(http.MethodPost, base+"/rollback", map[string]any{
			"revision_uuid": required(args, "revision"),
		})
	case "create-preprod":
		state := "shared"
		if v, ok := args.Options["state"]; ok && v != "" {
			state = v
		}
		return printRequest(http.MethodPost, base+"/env/create-preprod", map[string]any{"state": state})
	case "promote":
		return printRequest(http.MethodPost, base+"/env/promote", map[string]any{})
	case "rollback-promotion":
		return printRequest(http.MethodPost, base+"/env/rollback", map[string]any{})
	case "operations":
		return printRequest(http.MethodGet, base+"/operations", nil)
	case "status":
		return printRequest(http.MethodGet, base+"/status", nil)
	case "wait":
		return waitForApp(base, args)
	case "diagnose":
		tail := intOption(args, "tail", 120)
		return printRequest(http.MethodGet, fmt.Sprintf("%s/diagnose?tail=%d", base, tail), nil)
	case "logs":
		tail := intOption(args, "tail", 100)
		path := fmt.Sprintf("%s/logs?tail=%d", base, tail)
		if args.Bools["previous"] {
			path += "&previous=1"
		}
		return printRequest(http.MethodGet, path, nil)
	default:
		usage(os.Stderr)
		return errExit(2)
	}
}

func cmdContainerAppUpdate(base string, args parsedArgs) error {
	payload := map[string]any{}
	for _, key := range []string{"image", "tag"} {
		if value, ok := args.Options[key]; ok {
			payload[key] = value
		}
	}
	for _, key := range []string{"port", "replicas"} {
		if value, ok := args.Options[key]; ok {
			i, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("--%s must be an integer", strings.ReplaceAll(key, "_", "-"))
			}
			payload[key] = i
		}
	}
	if value, ok := args.Options["healthcheck"]; ok {
		payload["healthcheck_path"] = value
	}
	if value, ok := args.Options["healthcheck_type"]; ok {
		payload["healthcheck_type"] = value
	}
	if value, ok := args.Options["metrics_port"]; ok {
		i, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("--metrics-port must be an integer")
		}
		payload["metrics_port"] = i
	}
	if value, ok := args.Options["metrics_path"]; ok {
		payload["metrics_path"] = value
	}
	if value, ok := args.Options["domain"]; ok {
		if value == "" {
			payload["domains"] = []string{}
		} else {
			payload["domains"] = []string{value}
		}
	}
	env, err := jsonMapOption(args, "env_json", true)
	if err != nil {
		return err
	}
	// Repeatable --env KEY=VALUE pairs merge over --env-json values.
	for _, pair := range args.Multi["env"] {
		k, v, ok := strings.Cut(pair, "=")
		if !ok || k == "" {
			return fmt.Errorf("--env expects KEY=VALUE, got %q", pair)
		}
		if env == nil {
			env = map[string]any{}
		}
		env[k] = v
	}
	unsetEnv := []string{}
	for _, key := range args.Multi["unset_env"] {
		if key != "" && key != "true" {
			unsetEnv = append(unsetEnv, key)
		}
	}
	if env != nil {
		payload["env"] = env
		// Safe default: merge into the existing env map. A full replace
		// (the old behaviour, which silently dropped every key not in the
		// payload) now requires the explicit --replace-env flag.
		if args.Bools["replace_env"] {
			payload["env_mode"] = "replace"
		} else {
			payload["env_mode"] = "merge"
		}
	}
	if len(unsetEnv) > 0 {
		payload["unset_env"] = unsetEnv
	}
	secrets, err := jsonMapOption(args, "secrets_json", true)
	if err != nil {
		return err
	}
	// Repeatable --secret KEY=VALUE pairs merge over --secrets-json. Use this
	// (not --env) for sensitive values like API keys: secrets are encrypted at
	// rest, and a key set as a secret takes precedence over the same env key.
	for _, pair := range args.Multi["secret"] {
		k, v, ok := strings.Cut(pair, "=")
		if !ok || k == "" {
			return fmt.Errorf("--secret expects KEY=VALUE, got %q", pair)
		}
		if secrets == nil {
			secrets = map[string]any{}
		}
		secrets[k] = v
	}
	if secrets != nil {
		payload["secrets"] = secrets
	}
	unsetSecrets := []string{}
	for _, key := range args.Multi["unset_secret"] {
		if key != "" && key != "true" {
			unsetSecrets = append(unsetSecrets, key)
		}
	}
	if len(unsetSecrets) > 0 {
		payload["unset_secrets"] = unsetSecrets
	}
	if value, ok := args.Options["registry_credential"]; ok {
		payload["registry_credential_uuid"] = emptyToNil(value)
	}
	if value, ok := args.Options["persistent_mount_path"]; ok {
		payload["persistent_storage_enabled"] = value != ""
		payload["persistent_mount_path"] = value
	}
	if value, ok := args.Options["persistent_storage_gb"]; ok {
		i, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("--persistent-storage-gb must be an integer")
		}
		payload["persistent_storage_size_gb"] = i
	}
	return printRequest(http.MethodPatch, base, payload)
}

func cmdRegistryCredentials(action string, args parsedArgs) error {
	account := resolveAccount(args)
	switch action {
	case "list":
		return printRequest(http.MethodGet, fmt.Sprintf("accounts/%s/platform/container/registry-credentials", account), nil)
	case "create":
		return printRequest(http.MethodPost, fmt.Sprintf("accounts/%s/platform/container/registry-credentials", account), map[string]any{
			"name":         required(args, "name"),
			"registry_url": option(args, "registry_url", "https://index.docker.io/v1/"),
			"username":     option(args, "username", ""),
			"password":     required(args, "password"),
		})
	case "delete":
		credential := required(args, "credential")
		if err := requireYes(args, "delete registry credential"); err != nil {
			return err
		}
		return printRequest(http.MethodDelete, fmt.Sprintf("accounts/%s/platform/container/registry-credentials/%s", account, credential), nil)
	default:
		usage(os.Stderr)
		return errExit(2)
	}
}

func cmdAddons(action string, args parsedArgs) error {
	account := resolveAccount(args)
	app := required(args, "app")
	base := fmt.Sprintf("accounts/%s/platform/container/apps/%s/addons", account, app)
	switch action {
	case "list":
		return printRequest(http.MethodGet, base, nil)
	case "enable-database":
		return printRequest(http.MethodPost, base+"/database", map[string]any{
			"plan_code":  option(args, "plan", "starter"),
			"env_prefix": option(args, "env_prefix", "DB"),
			"storage_mb": nullableIntOption(args, "storage_mb"),
			"url_scheme": option(args, "url_scheme", "mysql"),
		})
	case "disable-database":
		return printRequest(http.MethodDelete, base+"/database", nil)
	case "enable-redis":
		return printRequest(http.MethodPost, base+"/redis", map[string]any{
			"plan_code":  option(args, "plan", "starter"),
			"env_prefix": option(args, "env_prefix", "REDIS"),
		})
	case "disable-redis":
		return printRequest(http.MethodDelete, base+"/redis", nil)
	case "enable-postgres":
		return printRequest(http.MethodPost, base+"/postgres", map[string]any{
			"plan_code":  option(args, "plan", "starter"),
			"env_prefix": option(args, "env_prefix", "DATABASE"),
			"storage_mb": nullableIntOption(args, "storage_mb"),
		})
	case "disable-postgres":
		return printRequest(http.MethodDelete, base+"/postgres", map[string]any{
			"delete_data":  args.Bools["delete_data"],
			"confirmation": nullableOption(args, "confirmation"),
		})
	case "enable-nats":
		return printRequest(http.MethodPost, base+"/nats", map[string]any{
			"plan_code":  option(args, "plan", "starter"),
			"env_prefix": option(args, "env_prefix", "NATS"),
			"storage_mb": nullableIntOption(args, "storage_mb"),
		})
	case "disable-nats":
		return printRequest(http.MethodDelete, base+"/nats", map[string]any{
			"delete_data": args.Bools["delete_data"],
		})
	default:
		usage(os.Stderr)
		return errExit(2)
	}
}

func cmdImports(action string, args parsedArgs) error {
	account := resolveAccount(args)
	app := required(args, "app")
	base := fmt.Sprintf("accounts/%s/platform/container/apps/%s/imports", account, app)
	switch action {
	case "list":
		return printRequest(http.MethodGet, base, nil)
	case "database":
		response, err := requestMultipart(http.MethodPost, base+"/database", nil, "file", required(args, "file"))
		if err != nil {
			return err
		}
		return printJSON(response)
	case "files":
		response, err := requestMultipart(http.MethodPost, base+"/files", map[string]string{
			"target_path": option(args, "target_path", "/app/data"),
		}, "file", required(args, "file"))
		if err != nil {
			return err
		}
		return printJSON(response)
	case "cancel":
		return printRequest(http.MethodDelete, fmt.Sprintf("%s/%s", base, required(args, "import")), nil)
	default:
		usage(os.Stderr)
		return errExit(2)
	}
}

func cmdJobs(action string, args parsedArgs) error {
	account := resolveAccount(args)
	app := required(args, "app")
	base := fmt.Sprintf("accounts/%s/platform/container/apps/%s/scheduled-jobs", account, app)
	switch action {
	case "list":
		return printRequest(http.MethodGet, base, nil)
	case "create":
		return printRequest(http.MethodPost, base, map[string]any{
			"name":               required(args, "name"),
			"schedule":           required(args, "schedule"),
			"method":             option(args, "method", "POST"),
			"path":               required(args, "path"),
			"secret_header_name": nullableOption(args, "secret_header_name"),
			"secret_source":      nullableOption(args, "secret_source"),
			"enabled":            args.Bools["enabled"],
		})
	case "run":
		job := required(args, "job")
		response, err := requestJSON(http.MethodPost, fmt.Sprintf("%s/%s/run", base, job), map[string]any{})
		if err != nil {
			return err
		}
		if !args.Bools["wait"] {
			return printJSON(response)
		}
		return waitForJob(base, job, args, response)
	case "delete":
		job := required(args, "job")
		if err := requireYes(args, "delete scheduled job"); err != nil {
			return err
		}
		return printRequest(http.MethodDelete, fmt.Sprintf("%s/%s", base, job), nil)
	default:
		usage(os.Stderr)
		return errExit(2)
	}
}

func cmdCompose(action string, args parsedArgs) error {
	account := resolveAccount(args)
	filePath := required(args, "file")

	const maxSize = 256 * 1024
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("cannot read file %s: %w", filePath, err)
	}
	if info.Size() > maxSize {
		return fmt.Errorf("file %s exceeds 256 KB limit (%d bytes)", filePath, info.Size())
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read file %s: %w", filePath, err)
	}

	switch action {
	case "preview":
		return printRequest(http.MethodPost,
			fmt.Sprintf("accounts/%s/platform/container/compose/preview", account),
			map[string]any{"compose_yaml": string(data)},
		)
	case "apply":
		if err := requireYes(args, "apply compose import"); err != nil {
			return err
		}
		return printRequest(http.MethodPost,
			fmt.Sprintf("accounts/%s/platform/container/compose/apply", account),
			map[string]any{"compose_yaml": string(data), "confirm": true},
		)
	default:
		usage(os.Stderr)
		return errExit(2)
	}
}

func cmdObjectStorage(args parsedArgs) error {
	if len(args.Positionals) < 2 {
		usage(os.Stderr)
		return errExit(2)
	}
	resource := args.Positionals[0]
	action := args.Positionals[1]
	account := resolveAccount(args)
	switch resource {
	case "buckets":
		bucketsBase := fmt.Sprintf("accounts/%s/platform/container/object-storage/buckets", account)
		switch action {
		case "list":
			return printRequest(http.MethodGet, bucketsBase, nil)
		case "create":
			return printRequest(http.MethodPost, bucketsBase, map[string]any{
				"name":       required(args, "name"),
				"visibility": option(args, "visibility", "private"),
			})
		case "usage":
			bucket := required(args, "bucket")
			return printRequest(http.MethodGet, fmt.Sprintf("%s/%s/usage", bucketsBase, bucket), nil)
		case "delete":
			bucket := required(args, "bucket")
			if err := requireYes(args, "delete object storage bucket"); err != nil {
				return err
			}
			return printRequest(http.MethodDelete, fmt.Sprintf("%s/%s", bucketsBase, bucket), nil)
		}
	case "access-keys":
		keysBase := fmt.Sprintf("accounts/%s/platform/container/object-storage/access-keys", account)
		switch action {
		case "create":
			return printRequest(http.MethodPost, keysBase, map[string]any{
				"bucket_uuid": nullableOption(args, "bucket"),
				"name":        nullableOption(args, "name"),
			})
		case "rotate":
			key := required(args, "key")
			return printRequest(http.MethodPost, fmt.Sprintf("%s/%s/rotate", keysBase, key), map[string]any{})
		case "revoke":
			key := required(args, "key")
			if err := requireYes(args, "revoke access key"); err != nil {
				return err
			}
			return printRequest(http.MethodDelete, fmt.Sprintf("%s/%s", keysBase, key), nil)
		}
	case "bindings":
		app := required(args, "app")
		bindingsBase := fmt.Sprintf("accounts/%s/platform/container/apps/%s/object-storage/bindings", account, app)
		switch action {
		case "create":
			return printRequest(http.MethodPost, bindingsBase, map[string]any{
				"bucket_uuid":     required(args, "bucket"),
				"access_key_uuid": nullableOption(args, "access_key"),
				"env_prefix":      option(args, "env_prefix", "S3"),
			})
		case "delete":
			binding := required(args, "binding")
			if err := requireYes(args, "delete object storage binding"); err != nil {
				return err
			}
			return printRequest(http.MethodDelete, fmt.Sprintf("%s/%s", bindingsBase, binding), nil)
		}
	}
	usage(os.Stderr)
	return errExit(2)
}

func waitForApp(base string, args parsedArgs) error {
	target := option(args, "status", "running")
	timeout := intOption(args, "timeout", 300)
	interval := intOption(args, "interval", 5)
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	var last map[string]any
	for time.Now().Before(deadline) || time.Now().Equal(deadline) {
		response, err := requestJSON(http.MethodGet, base+"/status", nil)
		if err != nil {
			return err
		}
		last = response
		current := appStatus(response)
		if current == target {
			return printJSON(map[string]any{
				"status":        true,
				"message":       "Target status reached: " + target,
				"target_status": target,
				"app_status":    current,
				"app":           response["app"],
			})
		}
		if current == "failed" || current == "deleted" {
			diagnose, _ := requestJSON(http.MethodGet, base+"/diagnose", nil)
			_ = printJSON(map[string]any{
				"status":        false,
				"message":       "App reached terminal status: " + current,
				"target_status": target,
				"app_status":    current,
				"diagnose":      diagnose,
			})
			return errExit(1)
		}
		time.Sleep(time.Duration(interval) * time.Second)
	}
	diagnose, _ := requestJSON(http.MethodGet, base+"/diagnose", nil)
	_ = printJSON(map[string]any{
		"status":        false,
		"message":       "Timed out waiting for app status.",
		"target_status": target,
		"last_response": last,
		"diagnose":      diagnose,
	})
	return errExit(1)
}

func waitForJob(base, job string, args parsedArgs, first map[string]any) error {
	timeout := intOption(args, "timeout", 180)
	interval := intOption(args, "interval", 5)
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	last := first
	for time.Now().Before(deadline) || time.Now().Equal(deadline) {
		response, err := requestJSON(http.MethodGet, base, nil)
		if err != nil {
			return err
		}
		last = response
		for _, item := range arrayMap(response["scheduled_jobs"]) {
			if fmt.Sprint(item["uuid"]) != job {
				continue
			}
			status := fmt.Sprint(item["status"])
			if status == "failed" {
				_ = printJSON(map[string]any{"status": false, "message": "Scheduled job failed.", "scheduled_job": item})
				return errExit(1)
			}
			if item["last_run_at"] != nil && status != "running" {
				return printJSON(map[string]any{
					"status":        true,
					"message":       "Scheduled job run reached a terminal API state.",
					"scheduled_job": item,
				})
			}
		}
		time.Sleep(time.Duration(interval) * time.Second)
	}
	_ = printJSON(map[string]any{"status": false, "message": "Timed out waiting for scheduled job status.", "last_response": last})
	return errExit(1)
}

func requestJSON(method, path string, payload map[string]any) (map[string]any, error) {
	cfg := readConfig()
	if cfg.Token == "" {
		return nil, errExitMessage(2, "Missing token. Run: cdnctl login --email <email> --password <password>")
	}
	return requestJSONWithConfig(cfg, method, path, payload, true)
}

func requestJSONPublic(cfg config, method, path string, payload map[string]any) (map[string]any, error) {
	return requestJSONWithConfig(cfg, method, path, payload, false)
}

func requestJSONWithConfig(cfg config, method, path string, payload map[string]any, auth bool) (map[string]any, error) {
	var body io.Reader
	if method == http.MethodPost || method == http.MethodPatch || method == http.MethodPut || method == http.MethodDelete {
		data, err := json.Marshal(payloadOrEmpty(payload))
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, endpoint(cfg, path), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if auth {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	return doRequest(req)
}

func requestMultipart(method, path string, fields map[string]string, fileField, filePath string) (map[string]any, error) {
	cfg := readConfig()
	if cfg.Token == "" {
		return nil, errExitMessage(2, "Missing token. Run: cdnctl login --email <email> --password <password>")
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			return nil, err
		}
	}
	part, err := writer.CreateFormFile(fileField, filepath.Base(filePath))
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(part, file); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, endpoint(cfg, path), &body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return doRequest(req)
}

func doRequest(req *http.Request) (map[string]any, error) {
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return map[string]any{"status": false, "http_status": 0, "error": err.Error()}, nil
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		decoded = map[string]any{"raw_body": string(data)}
	}
	decoded["_http_status"] = resp.StatusCode
	return decoded, nil
}

func printRequest(method, path string, payload map[string]any) error {
	response, err := requestJSON(method, path, payload)
	if err != nil {
		return err
	}
	return printJSON(response)
}

// marshalIndentNoHTMLEscape renders JSON for a terminal, not a browser. The
// default encoder escapes &, < and > into \u0026-style sequences, which turned
// a copy-pasteable hint ("brew update && brew upgrade cdnctl") into something
// nobody can read or paste. Nothing we print is interpolated into HTML.
func marshalIndentNoHTMLEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func printJSON(payload map[string]any) error {
	data, err := marshalIndentNoHTMLEscape(payload)
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func readConfig() config {
	cfg := config{Endpoint: "https://cdn.com.tr"}
	if value := os.Getenv("CDN_ENDPOINT"); value != "" {
		cfg.Endpoint = value
	} else if value := os.Getenv("CDNCTL_ENDPOINT"); value != "" {
		cfg.Endpoint = value
	}
	if value := os.Getenv("CDN_ACCESS_TOKEN"); value != "" {
		cfg.Token = value
	} else if value := os.Getenv("CDNCTL_TOKEN"); value != "" {
		cfg.Token = value
	}
	if value := os.Getenv("CDN_ACCOUNT"); value != "" {
		cfg.Account = value
	}
	for _, path := range []string{configPath(), legacyConfigPath()} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var fileCfg config
		if json.Unmarshal(data, &fileCfg) == nil {
			if cfg.Endpoint == "https://cdn.com.tr" && fileCfg.Endpoint != "" {
				cfg.Endpoint = fileCfg.Endpoint
			}
			if cfg.Token == "" && fileCfg.Token != "" {
				cfg.Token = fileCfg.Token
			}
			if cfg.Account == "" && fileCfg.Account != "" {
				cfg.Account = fileCfg.Account
			}
			if cfg.Email == "" && fileCfg.Email != "" {
				cfg.Email = fileCfg.Email
			}
		}
	}
	return cfg
}

func writeConfig(cfg config) error {
	path := configPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := marshalIndentNoHTMLEscape(cfg)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return nil
}

func configPath() string {
	return filepath.Join(homeDir(), ".cdn", "config.json")
}

func legacyConfigPath() string {
	return filepath.Join(homeDir(), ".cdnctl", "config.json")
}

func homeDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home
	}
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	wd, _ := os.Getwd()
	return wd
}

func endpoint(cfg config, path string) string {
	p := strings.TrimLeft(path, "/")
	// Deploy-only token (cdnctl_…) yalnız /deploy-token yüzeyinde geçerlidir; aynı
	// komutlar tam-yetkili oturumla da çalışsın diye yönlendirme burada, şeffafça
	// yapılır. Kapsam dışı bir accounts/ ucu token'la 404 döner — bilerek: token
	// deploy dışında hiçbir şeye uzanamaz.
	if strings.HasPrefix(cfg.Token, "cdnctl_") && strings.HasPrefix(p, "accounts/") {
		p = "deploy-token/" + p
	}
	return strings.TrimRight(cfg.Endpoint, "/") + "/api/" + p
}

func required(args parsedArgs, key string) string {
	value := option(args, key, "")
	if value == "" || value == "true" {
		fmt.Fprintf(os.Stderr, "Missing required --%s\n", strings.ReplaceAll(key, "_", "-"))
		os.Exit(2)
	}
	return value
}

// requiredOrPrompt returns the flag value when provided; otherwise, on an
// interactive terminal, it prompts for the value (hiding secret input) so a
// password never has to appear on the command line — where it would leak into
// shell history and the process list. In non-interactive runs (pipes, cron) it
// falls back to required()'s hard error, so scripts fail loudly instead of
// hanging on a prompt nobody can answer.
func requiredOrPrompt(args parsedArgs, key, label string, hidden bool) string {
	if value := option(args, key, ""); value != "" && value != "true" {
		return value
	}
	if value, ok := promptValue(label, hidden); ok && value != "" {
		return value
	}
	return required(args, key)
}

// promptValue reads a single line from the controlling terminal. It opens
// /dev/tty directly so it still works when stdin is redirected, and for hidden
// input it disables terminal echo via stty (best effort). The bool is false
// when no interactive terminal is available (e.g. piped or cron runs), so the
// caller can fall back to a hard error rather than block.
func promptValue(label string, hidden bool) (string, bool) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", false
	}
	defer tty.Close()

	fmt.Fprintf(os.Stderr, "%s: ", label)

	restore := func() {}
	if hidden && runtime.GOOS != "windows" {
		if err := runStty(tty, "-echo"); err == nil {
			restore = func() {
				_ = runStty(tty, "echo")
				fmt.Fprintln(os.Stderr)
			}
		}
	}

	line, _ := bufio.NewReader(tty).ReadString('\n')
	restore()

	return strings.TrimRight(line, "\r\n"), true
}

// runStty toggles terminal echo on the given tty. Non-fatal by design: if stty
// is unavailable the prompt just echoes the input instead of hiding it.
func runStty(tty *os.File, arg string) error {
	cmd := exec.Command("stty", arg)
	cmd.Stdin = tty
	cmd.Stdout = tty
	return cmd.Run()
}

// resolveAccount returns the account UUID for an account-scoped command.
// Precedence: an explicit --account flag, then the saved default account
// (set once via `cdnctl accounts use <uuid>`). When the saved default is used
// it prints a short note to stderr so the user knows which account was picked.
// If neither is available it exits with guidance.
// resolveAccountE is the error-returning form (used by commands that already
// return errors, e.g. cp, so a missing account is a normal error, not a hard
// exit that would abort tests).
func resolveAccountE(args parsedArgs) (string, error) {
	if value := option(args, "account", ""); value != "" && value != "true" {
		return value, nil
	}
	if account := readConfig().Account; account != "" {
		fmt.Fprintf(os.Stderr, "(using saved account %s)\n", account)
		return account, nil
	}
	return "", errExitMessage(2, "No account selected. Pass --account <uuid>, or pick one once with: cdnctl accounts use <uuid>")
}

func resolveAccount(args parsedArgs) string {
	account, err := resolveAccountE(args)
	if err != nil {
		if exit, ok := isExitError(err); ok {
			if exit.message != "" {
				fmt.Fprintln(os.Stderr, exit.message)
			}
			os.Exit(exit.code)
		}
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
	return account
}

func option(args parsedArgs, key, fallback string) string {
	if value, ok := args.Options[key]; ok {
		return value
	}
	return fallback
}

func nullableOption(args parsedArgs, key string) any {
	if value, ok := args.Options[key]; ok && value != "" {
		return value
	}
	return nil
}

func nullableIntOption(args parsedArgs, key string) any {
	value, ok := args.Options[key]
	if !ok || value == "" {
		return nil
	}
	i, err := strconv.Atoi(value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "--%s must be an integer\n", strings.ReplaceAll(key, "_", "-"))
		os.Exit(2)
	}
	return i
}

func intOption(args parsedArgs, key string, fallback int) int {
	value, ok := args.Options[key]
	if !ok || value == "" {
		return fallback
	}
	i, err := strconv.Atoi(value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "--%s must be an integer\n", strings.ReplaceAll(key, "_", "-"))
		os.Exit(2)
	}
	return i
}

func jsonMapOption(args parsedArgs, key string, nullable bool) (map[string]any, error) {
	value, ok := args.Options[key]
	if !ok || value == "" {
		if nullable {
			return nil, nil
		}
		return map[string]any{}, nil
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(value), &decoded); err != nil {
		return nil, fmt.Errorf("--%s must be a JSON object: %w", strings.ReplaceAll(key, "_", "-"), err)
	}
	return decoded, nil
}

func domains(args parsedArgs) []string {
	if value, ok := args.Options["domain"]; ok && value != "" {
		return []string{value}
	}
	return []string{}
}

func emptyToNil(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// requireYes returns an errExit(2) error if --yes was not supplied.  Use this
// before any destructive (delete / revoke) API call so the user must opt in
// explicitly.  Callers must propagate the returned error immediately.
func requireYes(args parsedArgs, what string) error {
	if !args.Bools["yes"] {
		fmt.Fprintf(os.Stderr, "Refusing to %s without --yes. This operation is destructive; re-run with --yes to confirm.\n", what)
		return errExit(2)
	}
	return nil
}

func payloadOrEmpty(payload map[string]any) map[string]any {
	if payload == nil {
		return map[string]any{}
	}
	return payload
}

func firstString(payload map[string]any, keys ...string) string {
	fallback := ""
	if len(keys) > 0 {
		fallback = keys[len(keys)-1]
		keys = keys[:len(keys)-1]
	}
	for _, key := range keys {
		if value, ok := payload[key].(string); ok && value != "" {
			return value
		}
	}
	return fallback
}

func appStatus(response map[string]any) string {
	if app, ok := response["app"].(map[string]any); ok {
		if status, ok := app["status"].(string); ok {
			return status
		}
	}
	if status, ok := response["status"].(string); ok {
		return status
	}
	return ""
}

func arrayMap(value any) []map[string]any {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if mapped, ok := item.(map[string]any); ok {
			out = append(out, mapped)
		}
	}
	return out
}

type exitError struct {
	code    int
	message string
}

func (e exitError) Error() string {
	return e.message
}

func errExit(code int) error {
	return exitError{code: code}
}

func errExitMessage(code int, message string) error {
	return exitError{code: code, message: message}
}

func isExitError(err error) (exitError, bool) {
	var target exitError
	ok := errors.As(err, &target)
	return target, ok
}
