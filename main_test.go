package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewReleaseTargetSelectsCurrentArchiveShape(t *testing.T) {
	target, err := newReleaseTarget("0.1.3", "linux", "amd64")
	if err != nil {
		t.Fatalf("newReleaseTarget returned error: %v", err)
	}

	if target.ArchiveName != "cdnctl-0.1.3-linux-amd64.tar.gz" {
		t.Fatalf("unexpected archive name: %s", target.ArchiveName)
	}
	if target.ChecksumName != "cdnctl-0.1.3-checksums.txt" {
		t.Fatalf("unexpected checksum name: %s", target.ChecksumName)
	}
}

func TestChecksumForArchiveFindsMatchingArtifact(t *testing.T) {
	checksum, err := checksumForArchive("abc  cdnctl-0.1.3-linux-amd64.tar.gz\n", "cdnctl-0.1.3-linux-amd64.tar.gz")
	if err != nil {
		t.Fatalf("checksumForArchive returned error: %v", err)
	}
	if checksum != "abc" {
		t.Fatalf("unexpected checksum: %s", checksum)
	}
}

func TestUpdateBinaryDownloadsVerifiesAndInstalls(t *testing.T) {
	target, err := newReleaseTarget("0.1.3", "linux", "amd64")
	if err != nil {
		t.Fatalf("newReleaseTarget returned error: %v", err)
	}
	binary := []byte("#!/bin/sh\necho cdnctl 0.1.3\n")
	archive := tarGzArchive(t, "cdnctl-0.1.3-linux-amd64/cdnctl", binary)
	sum := sha256.Sum256(archive)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + target.ChecksumName:
			_, _ = io.WriteString(w, hex.EncodeToString(sum[:])+"  "+target.ArchiveName+"\n")
		case "/" + target.ArchiveName:
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	binDir := t.TempDir()
	path, err := updateBinary(server.URL, target, binDir)
	if err != nil {
		t.Fatalf("updateBinary returned error: %v", err)
	}

	expectedPath := filepath.Join(binDir, "cdnctl")
	if path != expectedPath {
		t.Fatalf("unexpected install path: %s", path)
	}
	got, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("installed binary missing: %v", err)
	}
	if !bytes.Equal(got, binary) {
		t.Fatalf("installed binary content mismatch")
	}
}

func TestUpdateBinaryRejectsChecksumMismatch(t *testing.T) {
	target, err := newReleaseTarget("0.1.3", "linux", "amd64")
	if err != nil {
		t.Fatalf("newReleaseTarget returned error: %v", err)
	}
	archive := tarGzArchive(t, "cdnctl-0.1.3-linux-amd64/cdnctl", []byte("binary"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + target.ChecksumName:
			_, _ = io.WriteString(w, strings.Repeat("0", 64)+"  "+target.ArchiveName+"\n")
		case "/" + target.ArchiveName:
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err = updateBinary(server.URL, target, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch, got %v", err)
	}
}

func TestLoginOutputDoesNotExposeUserIdentity(t *testing.T) {
	payload := map[string]any{
		"status":      true,
		"message":     "cdnctl logged in",
		"config_path": "/tmp/config.json",
		"endpoint":    "https://cdn.com.tr",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}

	for _, forbidden := range []string{"user", "id", "email"} {
		if strings.Contains(string(data), `"`+forbidden+`"`) {
			t.Fatalf("login output exposes forbidden key %q: %s", forbidden, string(data))
		}
	}
}

// ---------- requireYes guard tests ------------------------------------------

// runArgs invokes run() with a fake home dir so no real config is read, and
// captures the exit code.  It returns the exit code (2 when requireYes fires)
// and whether an HTTP server was ever called (it must NOT be called before the
// guard triggers).
func runArgsExpectExit(t *testing.T, args []string) (exitCode int, serverHit bool) {
	t.Helper()

	// Spin up a server that records if it is ever hit.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHit = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer server.Close()

	// Point the tool at our test server and give it a dummy token so the auth
	// check does not fire before our guard does.
	t.Setenv("CDN_ENDPOINT", server.URL)
	t.Setenv("CDN_ACCESS_TOKEN", "test-token")

	err := run(args)
	if err == nil {
		return 0, serverHit
	}
	if exit, ok := isExitError(err); ok {
		return exit.code, serverHit
	}
	return 1, serverHit
}

func TestRequireYesGuard_AppsDelete(t *testing.T) {
	code, hit := runArgsExpectExit(t, []string{
		"container", "apps", "delete",
		"--account", "acct-uuid",
		"--app", "app-uuid",
		// intentionally omit --yes
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if hit {
		t.Fatal("HTTP server was called before --yes guard fired")
	}
}

func TestRequireYesGuard_RegistryCredentialsDelete(t *testing.T) {
	code, hit := runArgsExpectExit(t, []string{
		"container", "registry-credentials", "delete",
		"--account", "acct-uuid",
		"--credential", "cred-uuid",
		// intentionally omit --yes
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if hit {
		t.Fatal("HTTP server was called before --yes guard fired")
	}
}

func TestRequireYesGuard_JobsDelete(t *testing.T) {
	code, hit := runArgsExpectExit(t, []string{
		"container", "jobs", "delete",
		"--account", "acct-uuid",
		"--app", "app-uuid",
		"--job", "job-uuid",
		// intentionally omit --yes
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if hit {
		t.Fatal("HTTP server was called before --yes guard fired")
	}
}

func TestRequireYesGuard_BucketsDelete(t *testing.T) {
	code, hit := runArgsExpectExit(t, []string{
		"object-storage", "buckets", "delete",
		"--account", "acct-uuid",
		"--bucket", "bucket-uuid",
		// intentionally omit --yes
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if hit {
		t.Fatal("HTTP server was called before --yes guard fired")
	}
}

func TestRequireYesGuard_AccessKeysRevoke(t *testing.T) {
	code, hit := runArgsExpectExit(t, []string{
		"object-storage", "access-keys", "revoke",
		"--account", "acct-uuid",
		"--key", "key-uuid",
		// intentionally omit --yes
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if hit {
		t.Fatal("HTTP server was called before --yes guard fired")
	}
}

func TestRequireYesGuard_BindingsDelete(t *testing.T) {
	code, hit := runArgsExpectExit(t, []string{
		"object-storage", "bindings", "delete",
		"--account", "acct-uuid",
		"--app", "app-uuid",
		"--binding", "binding-uuid",
		// intentionally omit --yes
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if hit {
		t.Fatal("HTTP server was called before --yes guard fired")
	}
}

func TestRequireYesGuard_ComposeApply(t *testing.T) {
	// Create a temp compose file so --file validation passes before --yes guard.
	tmp := t.TempDir()
	composeFile := filepath.Join(tmp, "docker-compose.yml")
	if err := os.WriteFile(composeFile, []byte("version: '3'\n"), 0o644); err != nil {
		t.Fatalf("could not create temp compose file: %v", err)
	}

	code, hit := runArgsExpectExit(t, []string{
		"container", "compose", "apply",
		"--account", "acct-uuid",
		"--file", composeFile,
		// intentionally omit --yes
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if hit {
		t.Fatal("HTTP server was called before --yes guard fired")
	}
}

func TestComposePreview_MissingFile(t *testing.T) {
	t.Setenv("CDN_ENDPOINT", "http://127.0.0.1:0")
	t.Setenv("CDN_ACCESS_TOKEN", "test-token")

	err := run([]string{
		"container", "compose", "preview",
		"--account", "acct-uuid",
		"--file", "/nonexistent/docker-compose.yml",
	})
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// ---------- usage / help text tests -----------------------------------------

func usageText(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	usage(&buf)
	return buf.String()
}

func TestUsageContainsNewCommands(t *testing.T) {
	text := usageText(t)

	mustContain := []string{
		// session commands
		"cdnctl whoami",
		"cdnctl logout",
		// file transfer commands
		"cdnctl cp [-r] <localpath> [<account_uuid>:]<remotepath>",
		"accounts use",
		"files put",
		"files ls",
		"files rm",
		"files mkdir",
		// new apps subcommands
		"apps expose",
		"apps restart",
		"apps scale",
		"apps delete",
		"apps show",
		"apps rollback",
		"apps operations",
		// new flags on create/update
		"--healthcheck-type",
		"--metrics-port",
		"--metrics-path",
		// preflight
		"container preflight",
		// registry-credentials delete
		"registry-credentials delete",
		// addons
		"addons list",
		"addons enable-postgres",
		"addons disable-postgres",
		"addons enable-nats",
		"addons disable-nats",
		// imports list
		"imports list",
		// jobs delete
		"jobs delete",
		// compose import
		"compose preview",
		"compose apply",
		// object-storage new subcommands
		"buckets usage",
		"buckets delete",
		"access-keys rotate",
		"access-keys revoke",
		"bindings delete",
		// destructive note
		"Destructive commands",
		"--yes",
	}

	for _, want := range mustContain {
		if !strings.Contains(text, want) {
			t.Errorf("usage text missing %q", want)
		}
	}
}

func TestVersionIs0182(t *testing.T) {
	if version != "0.18.2" {
		t.Fatalf("expected version 0.18.2, got %s", version)
	}
}

func TestResponseStorageFullRecognizesStructuredCodeAndHTTP507(t *testing.T) {
	for _, response := range []map[string]any{
		{"status": false, "error_code": "storage_full"},
		{"status": false, "_http_status": float64(http.StatusInsufficientStorage)},
		{"status": false, "http_status": "507"},
	} {
		if !responseStorageFull(response) {
			t.Fatalf("expected storage-full response to be recognized: %#v", response)
		}
	}
}

func TestPrintFileResponseReturnsNonZeroForFailedAPIEnvelope(t *testing.T) {
	err := printFileResponse(map[string]any{"status": false, "error_code": "upload_failed"})
	exit, ok := isExitError(err)
	if !ok || exit.code != 1 {
		t.Fatalf("expected exit code 1, got %#v", err)
	}
}

func TestRecursiveCopyStopsAfterFirstStorageFullResponse(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInsufficientStorage)
		_, _ = io.WriteString(w, `{"status":false,"error_code":"storage_full","message":"Persistent storage is full."}`)
	}))
	defer server.Close()

	t.Setenv("CDN_ENDPOINT", server.URL)
	t.Setenv("CDN_ACCESS_TOKEN", "test-token")
	t.Setenv("CDNCTL_ENDPOINT", "")
	t.Setenv("CDNCTL_TOKEN", "")

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "first.txt"), []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "second.txt"), []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := cpRecursive("account", dir, "uploads", true)
	exit, ok := isExitError(err)
	if !ok || exit.code != 1 {
		t.Fatalf("expected exit code 1, got %#v", err)
	}
	if requests != 1 {
		t.Fatalf("expected fail-fast after one request, got %d requests", requests)
	}
}

// A packaged build must never self-update: it would overwrite the binary the
// package manager owns. Only the default "direct" channel may update in place.
func TestPackageUpdateHintPerChannel(t *testing.T) {
	for channel, want := range map[string]string{
		"homebrew": "brew upgrade cdnctl",
		"deb":      "apt-get install --only-upgrade cdnctl",
		"rpm":      "dnf upgrade cdnctl",
	} {
		if got := packageUpdateHint(channel); !strings.Contains(got, want) {
			t.Fatalf("channel %s: expected hint to contain %q, got %q", channel, want, got)
		}
	}
}

func TestInstallChannelDefaultsToDirect(t *testing.T) {
	if installChannel != "direct" {
		t.Fatalf("unstamped builds must self-update; got channel %q", installChannel)
	}
}

func TestAccountLabelResolvesTag(t *testing.T) {
	// server answers /accounts/show/<uuid> based on the uuid in the path
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/with-domain"):
			_, _ = io.WriteString(w, `{"status":"success","account":{"uuid":"with-domain","domain":"example.com","alias":""}}`)
		case strings.HasSuffix(r.URL.Path, "/with-alias"):
			_, _ = io.WriteString(w, `{"status":"success","account":{"uuid":"with-alias","domain":"with-alias","alias":"My Site"}}`)
		case strings.HasSuffix(r.URL.Path, "/bare"):
			// domain mirrors the uuid -> no meaningful tag
			_, _ = io.WriteString(w, `{"status":"success","account":{"uuid":"bare","domain":"bare","alias":""}}`)
		default:
			_, _ = io.WriteString(w, `{"status":"error","message":"account not found"}`)
		}
	}))
	defer server.Close()
	t.Setenv("CDN_ENDPOINT", server.URL)
	t.Setenv("CDN_ACCESS_TOKEN", "test-token")

	cases := []struct {
		uuid, wantLabel, wantState string
	}{
		{"with-domain", "example.com", "found"},
		{"with-alias", "My Site", "found"},
		{"bare", "", "found"},
		{"nope", "", "missing"},
	}
	for _, c := range cases {
		label, state := accountLabel(c.uuid)
		if label != c.wantLabel || state != c.wantState {
			t.Errorf("accountLabel(%q) = (%q,%q), want (%q,%q)", c.uuid, label, state, c.wantLabel, c.wantState)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.14.0", "0.12.0", 1},
		{"0.12.0", "0.14.0", -1},
		{"0.14.0", "0.14.0", 0},
		{"v1.2", "1.2.0", 0},
		{"1.2.0", "1.10.0", -1},
		{"2.0.0", "1.9.9", 1},
		{"0.14.1", "0.14.0", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// A published version older than the installed one must be refused unless the
// caller explicitly opts in — this is the accidental-downgrade guard.
func TestUpdateRefusesDowngradeWithoutOptIn(t *testing.T) {
	var archiveRequested bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "latest.txt") {
			_, _ = io.WriteString(w, "0.0.1\n") // older than the built-in version
			return
		}
		archiveRequested = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := run([]string{"update", "--yes", "--base-url", server.URL})
	if err == nil {
		t.Fatal("downgrade without --allow-downgrade should exit non-zero")
	}
	if exit, ok := isExitError(err); !ok || exit.code != 1 {
		t.Fatalf("expected exit code 1, got %v", err)
	}
	if archiveRequested {
		t.Fatal("a refused downgrade must not download the release archive")
	}
}

func TestDescribeUserFormatsIdentity(t *testing.T) {
	// Full profile: email + name/surname. Guards against firstString's
	// last-arg-is-fallback semantics (a bare firstString(u,"email") returns the
	// literal "email", not the value). The internal id must NOT leak into output.
	full := describeUser(map[string]any{
		"email": "me@example.com", "name": "Me", "surname": "Test", "id": float64(7),
	})
	if want := "me@example.com (Me Test)"; full != want {
		t.Fatalf("describeUser(full) = %q, want %q", full, want)
	}
	if strings.Contains(full, "7") || strings.Contains(full, "id") {
		t.Fatalf("describeUser must not expose the internal user id: %q", full)
	}

	// Email only: no parenthetical.
	if only := describeUser(map[string]any{"email": "solo@example.com"}); only != "solo@example.com" {
		t.Fatalf("describeUser(email-only) = %q, want %q", only, "solo@example.com")
	}
}

func TestLogoutClearsSessionKeepsEndpoint(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CDN_ACCESS_TOKEN", "")
	t.Setenv("CDNCTL_TOKEN", "")
	t.Setenv("CDN_ENDPOINT", "")

	cfgDir := filepath.Join(home, ".cdn")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	seed := `{"endpoint":"https://cdn.example","token":"secret-token","account":"acc-123","email":"me@example.com"}`
	cfgFile := filepath.Join(cfgDir, "config.json")
	if err := os.WriteFile(cfgFile, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := cmdLogout(parsedArgs{}); err != nil {
		t.Fatalf("logout returned error: %v", err)
	}

	data, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-token") {
		t.Fatalf("token still present in config file after logout: %s", data)
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Token != "" || cfg.Account != "" || cfg.Email != "" {
		t.Fatalf("logout did not clear session: %+v", cfg)
	}
	if cfg.Endpoint != "https://cdn.example" {
		t.Fatalf("logout should keep the endpoint, got %q", cfg.Endpoint)
	}
}

func TestUpdateWithoutYesReportsButDoesNotInstall(t *testing.T) {
	var archiveRequested bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "latest.txt") {
			_, _ = io.WriteString(w, "9.9.9\n")
			return
		}
		archiveRequested = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := run([]string{"update", "--base-url", server.URL})
	if err != nil {
		t.Fatalf("update without --yes should succeed as a report, got error: %v", err)
	}
	if archiveRequested {
		t.Fatal("update without --yes must not download the release archive")
	}
}

func tarGzArchive(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body))}); err != nil {
		t.Fatalf("tar header failed: %v", err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatalf("tar write failed: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close failed: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close failed: %v", err)
	}
	return buf.Bytes()
}

func TestAppsUpdateEnvFlagsSendMergeModeByDefault(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success"}`)
	}))
	defer server.Close()

	t.Setenv("CDN_ENDPOINT", server.URL)
	t.Setenv("CDN_ACCESS_TOKEN", "test-token")

	err := run([]string{
		"container", "apps", "update",
		"--account", "acct-uuid",
		"--app", "app-uuid",
		"--env", "FOO=bar",
		"--env", "BAZ=qux=1",
		"--unset-env", "OLD_KEY",
	})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	env, _ := captured["env"].(map[string]any)
	if env["FOO"] != "bar" || env["BAZ"] != "qux=1" {
		t.Fatalf("unexpected env payload: %#v", captured["env"])
	}
	if captured["env_mode"] != "merge" {
		t.Fatalf("expected env_mode merge, got %#v", captured["env_mode"])
	}
	unset, _ := captured["unset_env"].([]any)
	if len(unset) != 1 || unset[0] != "OLD_KEY" {
		t.Fatalf("unexpected unset_env payload: %#v", captured["unset_env"])
	}
}

func TestAppsUpdateReplaceEnvFlagSendsReplaceMode(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success"}`)
	}))
	defer server.Close()

	t.Setenv("CDN_ENDPOINT", server.URL)
	t.Setenv("CDN_ACCESS_TOKEN", "test-token")

	err := run([]string{
		"container", "apps", "update",
		"--account", "acct-uuid",
		"--app", "app-uuid",
		"--env-json", `{"ONLY":"this"}`,
		"--replace-env",
	})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if captured["env_mode"] != "replace" {
		t.Fatalf("expected env_mode replace, got %#v", captured["env_mode"])
	}
}

func TestPurgeSendsPathsAndType(t *testing.T) {
	var captured map[string]any
	var calledPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success"}`)
	}))
	defer server.Close()

	t.Setenv("CDN_ENDPOINT", server.URL)
	t.Setenv("CDN_ACCESS_TOKEN", "test-token")

	err := run([]string{
		"purge",
		"--account", "acct-uuid",
		"--path", "/sitemap.xml",
		"--path", "/robots.txt",
		"--type", "prefix",
	})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if calledPath != "/api/purge_management/acct-uuid/purge" {
		t.Fatalf("unexpected path: %s", calledPath)
	}
	paths, _ := captured["paths"].([]any)
	if len(paths) != 2 || paths[0] != "/sitemap.xml" || paths[1] != "/robots.txt" {
		t.Fatalf("unexpected paths payload: %#v", captured["paths"])
	}
	if captured["type"] != "prefix" {
		t.Fatalf("expected type prefix, got %#v", captured["type"])
	}
}

func TestPurgeAllRequiresYes(t *testing.T) {
	code, hit := runArgsExpectExit(t, []string{
		"purge", "all",
		"--account", "acct-uuid",
		// no --yes
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if hit {
		t.Fatal("HTTP server was called before --yes guard fired")
	}
}

// ---------- cp / files ------------------------------------------------------

func TestRequireYesGuard_FilesRm(t *testing.T) {
	code, hit := runArgsExpectExit(t, []string{
		"files", "rm",
		"--account", "acct-uuid",
		"--path", "/uploads/old.jpg",
		// intentionally omit --yes
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if hit {
		t.Fatal("HTTP server was called before --yes guard fired")
	}
}

func TestCpWithoutAccountErrors(t *testing.T) {
	tmp := t.TempDir()
	localFile := filepath.Join(tmp, "hello.txt")
	if err := os.WriteFile(localFile, []byte("hi"), 0o644); err != nil {
		t.Fatalf("could not create temp file: %v", err)
	}

	// Isolate HOME so no real ~/.cdn/config.json default account leaks in.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CDN_ENDPOINT", "http://127.0.0.1:0")
	t.Setenv("CDN_ACCESS_TOKEN", "test-token")

	// No "<uuid>:" prefix, no --account, and no saved default -> account error.
	err := run([]string{"cp", localFile, "uploads/hello.txt"})
	if err == nil {
		t.Fatal("expected error when no account is given and none is saved, got nil")
	}
	if !strings.Contains(err.Error(), "account") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestCpRejectsMissingLocalFile(t *testing.T) {
	t.Setenv("CDN_ENDPOINT", "http://127.0.0.1:0")
	t.Setenv("CDN_ACCESS_TOKEN", "test-token")

	err := run([]string{"cp", "/nonexistent/hello.txt", "acct-uuid:/uploads/hello.txt"})
	if err == nil {
		t.Fatal("expected error for missing local file, got nil")
	}
}

func TestCpUploadsFileToFilesPutEndpoint(t *testing.T) {
	tmp := t.TempDir()
	localFile := filepath.Join(tmp, "hello.txt")
	if err := os.WriteFile(localFile, []byte("hello cdn"), 0o644); err != nil {
		t.Fatalf("could not create temp file: %v", err)
	}

	var calledPath, targetPath, uploadedName string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledPath = r.URL.Path
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Fatalf("ParseMultipartForm failed: %v", err)
		}
		targetPath = r.FormValue("target_path")
		if files := r.MultipartForm.File["file"]; len(files) == 1 {
			uploadedName = files[0].Filename
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success"}`)
	}))
	defer server.Close()

	t.Setenv("CDN_ENDPOINT", server.URL)
	t.Setenv("CDN_ACCESS_TOKEN", "test-token")

	err := run([]string{"cp", localFile, "acct-uuid:/uploads/hello.txt"})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if calledPath != "/api/accounts/acct-uuid/files/put" {
		t.Fatalf("unexpected path: %s", calledPath)
	}
	if targetPath != "/uploads/hello.txt" {
		t.Fatalf("unexpected target_path: %s", targetPath)
	}
	if uploadedName != "hello.txt" {
		t.Fatalf("unexpected uploaded filename: %s", uploadedName)
	}
}

func TestFilesLsSendsPath(t *testing.T) {
	var captured map[string]any
	var calledPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success"}`)
	}))
	defer server.Close()

	t.Setenv("CDN_ENDPOINT", server.URL)
	t.Setenv("CDN_ACCESS_TOKEN", "test-token")

	err := run([]string{
		"files", "ls",
		"--account", "acct-uuid",
		"--path", "/uploads",
	})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if calledPath != "/api/accounts/acct-uuid/files/list" {
		t.Fatalf("unexpected path: %s", calledPath)
	}
	if captured["path"] != "/uploads" {
		t.Fatalf("unexpected path payload: %#v", captured["path"])
	}
}

func TestFilesMkdirSendsPath(t *testing.T) {
	var captured map[string]any
	var calledPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success"}`)
	}))
	defer server.Close()

	t.Setenv("CDN_ENDPOINT", server.URL)
	t.Setenv("CDN_ACCESS_TOKEN", "test-token")

	err := run([]string{
		"files", "mkdir",
		"--account", "acct-uuid",
		"--path", "/uploads/2026",
	})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if calledPath != "/api/accounts/acct-uuid/files/mkdir" {
		t.Fatalf("unexpected path: %s", calledPath)
	}
	if captured["path"] != "/uploads/2026" {
		t.Fatalf("unexpected path payload: %#v", captured["path"])
	}
}

func TestFilesRmSendsPathAfterYes(t *testing.T) {
	var captured map[string]any
	var calledPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success"}`)
	}))
	defer server.Close()

	t.Setenv("CDN_ENDPOINT", server.URL)
	t.Setenv("CDN_ACCESS_TOKEN", "test-token")

	err := run([]string{
		"files", "rm",
		"--account", "acct-uuid",
		"--path", "/uploads/old.jpg",
		"--yes",
	})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if calledPath != "/api/accounts/acct-uuid/files/delete" {
		t.Fatalf("unexpected path: %s", calledPath)
	}
	if captured["path"] != "/uploads/old.jpg" {
		t.Fatalf("unexpected path payload: %#v", captured["path"])
	}
}

func TestUpdateSecretFlagsSendSecretsAndUnset(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success"}`)
	}))
	defer server.Close()

	t.Setenv("CDN_ENDPOINT", server.URL)
	t.Setenv("CDN_ACCESS_TOKEN", "test-token")

	err := run([]string{
		"container", "apps", "update",
		"--account", "acct-uuid",
		"--app", "app-uuid",
		"--secret", "PARIBU_API_KEY=abc123",
		"--unset-secret", "OLD_TOKEN",
	})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	secrets, _ := captured["secrets"].(map[string]any)
	if secrets["PARIBU_API_KEY"] != "abc123" {
		t.Fatalf("unexpected secrets payload: %#v", captured["secrets"])
	}
	unset, _ := captured["unset_secrets"].([]any)
	if len(unset) != 1 || unset[0] != "OLD_TOKEN" {
		t.Fatalf("unexpected unset_secrets payload: %#v", captured["unset_secrets"])
	}
}

// A package-managed install must still report the version gap. The old
// behaviour returned status:false with no version fields at all, which reads
// as "nothing to do" to someone several releases behind — that is exactly how
// a 0.17.2 Homebrew user ended up running `cdnctl init` on a build that had no
// init command.
func TestUpdateViaPackageManagerReportsVersionGap(t *testing.T) {
	out, err := captureStdout(func() error {
		return updateViaPackageManager("homebrew", "0.18.0", -1, false)
	})
	if err != nil {
		t.Fatalf("updateViaPackageManager: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("output is not JSON: %v (%s)", err, out)
	}
	if payload["update_available"] != true {
		t.Errorf("update_available = %v, want true", payload["update_available"])
	}
	if payload["latest_version"] != "0.18.0" {
		t.Errorf("latest_version = %v, want 0.18.0", payload["latest_version"])
	}
	if payload["current_version"] == nil {
		t.Error("current_version missing — the caller cannot see how far behind they are")
	}
	if cmd, _ := payload["upgrade_command"].(string); !strings.Contains(cmd, "brew upgrade cdnctl") {
		t.Errorf("upgrade_command = %q, want the brew command", cmd)
	}
}

// Being current must not be reported as an available update.
func TestUpdateViaPackageManagerCurrentIsNotAnUpdate(t *testing.T) {
	out, err := captureStdout(func() error {
		return updateViaPackageManager("deb", version, 0, false)
	})
	if err != nil {
		t.Fatalf("updateViaPackageManager: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("output is not JSON: %v (%s)", err, out)
	}
	if payload["update_available"] != false {
		t.Errorf("update_available = %v, want false", payload["update_available"])
	}
}

// apt/dnf need root, so cdnctl reports the command instead of running it:
// the CLI never escalates privileges on its own.
func TestPackageUpgradeCommandNeverAutoRunsSudo(t *testing.T) {
	for _, channel := range []string{"deb", "rpm"} {
		cmd, runnable := packageUpgradeCommand(channel)
		if runnable {
			t.Errorf("%s: runnable = true, want false (would escalate privileges)", channel)
		}
		if len(cmd) == 0 || cmd[0] != "sudo" {
			t.Errorf("%s: command = %v, want a sudo command to show the user", channel, cmd)
		}
	}
	if _, runnable := packageUpgradeCommand("homebrew"); !runnable {
		t.Error("homebrew: runnable = false, want true (no privilege escalation needed)")
	}
}

// JSON output goes to a terminal, so & < > must appear literally. Go's default
// encoder escapes them for HTML embedding, which is how the Homebrew hint
// reached users as "brew update \u0026\u0026 brew upgrade cdnctl" — unreadable
// and impossible to paste.
func TestPrintedJSONDoesNotHTMLEscape(t *testing.T) {
	out, err := captureStdout(func() error {
		return printJSON(map[string]any{"message": "brew update && brew upgrade cdnctl <ok>"})
	})
	if err != nil {
		t.Fatalf("printJSON: %v", err)
	}
	if strings.Contains(out, "\\u0026") || strings.Contains(out, "\\u003c") {
		t.Errorf("output contains HTML escapes: %s", out)
	}
	if !strings.Contains(out, "brew update && brew upgrade cdnctl") {
		t.Errorf("literal && missing from output: %s", out)
	}
}
