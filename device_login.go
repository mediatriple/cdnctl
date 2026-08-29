package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"time"
)

// Device login: the CLI mints a one-time request, hands the person a browser
// URL, and waits. The browser side runs in the site's normal session world, so
// an existing login is reused with one click, and someone with no account
// registers right there — the account born in the browser comes back linked to
// this terminal. The CLI never sees a password, which is the entire point:
// `cdnctl login` used to be a password prompt in a terminal, the exact habit
// nobody should be taught.
func cmdDeviceLogin(cfg config) error {
	start, err := requestJSONPublic(cfg, http.MethodPost, "device/start", map[string]any{
		"ref":  "cdnctl",
		"need": "container-platform",
	})
	if err != nil {
		return err
	}
	deviceCode, _ := start["device_code"].(string)
	userCode, _ := start["user_code"].(string)
	verifyURL, _ := start["verification_url"].(string)
	if deviceCode == "" || verifyURL == "" {
		_ = printJSON(map[string]any{"status": false, "message": firstString(start, "message", "error", "device login unavailable")})
		return errExit(1)
	}

	fmt.Println(T("Open this address in your browser — sign in there, or register if you have no account:"))
	fmt.Println("  " + verifyURL)
	fmt.Printf(T("Code: %s (shown on the page; compare before approving)\n"), userCode)
	tryOpenBrowser(verifyURL)
	fmt.Println(T("Waiting for approval in the browser (Ctrl+C to stop)..."))

	interval := 4 * time.Second
	if seconds, ok := start["poll_interval"].(float64); ok && seconds >= 2 {
		interval = time.Duration(seconds) * time.Second
	}
	deadline := time.Now().Add(16 * time.Minute)

	for time.Now().Before(deadline) {
		time.Sleep(interval)
		poll, err := requestJSONPublic(cfg, http.MethodPost, "device/poll", map[string]any{"device_code": deviceCode})
		if err != nil {
			// Transient network trouble must not abort a flow whose other half
			// is a human mid-payment in a browser; keep polling until expiry.
			continue
		}
		switch poll["status"] {
		case "approved":
			token, _ := poll["token"].(string)
			if token == "" {
				_ = printJSON(map[string]any{"status": false, "message": "approval arrived without a token"})
				return errExit(1)
			}
			cfg.Token = token
			if email, ok := poll["email"].(string); ok {
				cfg.Email = email
			}
			if err := writeConfig(cfg); err != nil {
				return err
			}
			fmt.Println(T("✓ Logged in. Next: `cdnctl init` in your project folder."))
			return nil
		case "denied":
			fmt.Println(T("The request was denied in the browser."))
			return errExit(1)
		case "expired":
			fmt.Println(T("The link expired before approval. Run `cdnctl login` again."))
			return errExit(1)
		}
	}
	fmt.Println(T("Timed out waiting for the browser. Run `cdnctl login` again."))
	return errExit(1)
}

// tryOpenBrowser is best-effort: printing the URL is the contract, opening it
// is a courtesy. Failures stay silent — a headless box still shows the URL.
func tryOpenBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	_ = cmd.Start()
}

// deviceLoginPossible reports whether the interactive browser flow makes sense:
// a person at a terminal, no explicit credentials given.
func deviceLoginPossible(args parsedArgs) bool {
	if option(args, "email", "") != "" || option(args, "password", "") != "" {
		return false
	}
	if args.Bools["password-login"] {
		return false
	}
	return isInteractive()
}
