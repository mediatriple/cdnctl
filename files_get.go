package main

// Download side of `cdnctl cp` and `cdnctl files get`.
//
// Upload was the only direction for a long time, while the docs said cp "works
// like scp" — and scp works both ways. People reasonably tried to pull a file
// back and found no way to (numberone.com.tr, 2026-09-25). This file is the
// other half: the same account storage, read instead of written.
//
// The bytes travel base64-encoded inside JSON with their size and SHA-256, and
// nothing is written locally until both match what arrived. The panel and cdnapi
// hold the body in memory on the way, so a single file is capped at 10 MB there;
// cdnctl just reports the server's answer when a file is over it.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// maxDownloadDepth bounds recursive downloads. A directory symlink that points at
// its own ancestor would otherwise produce ever-longer paths forever.
const maxDownloadDepth = 32

var remoteAccountPrefix = regexp.MustCompile(`^[A-Za-z0-9_-]{3,}$`)

// parseRemoteSpec recognises a remote path the way scp does: "<account>:<path>",
// or ":<path>" for the saved default / --account. A colon that comes after a
// slash belongs to a local path ("./a:b"), and a one- or two-letter prefix is a
// Windows drive ("C:\\files"), not an account.
func parseRemoteSpec(s string) (account, remotePath string, ok bool) {
	i := strings.Index(s, ":")
	if i < 0 {
		return "", "", false
	}
	prefix := s[:i]
	if strings.ContainsAny(prefix, `/\`) {
		return "", "", false
	}
	if prefix != "" && !remoteAccountPrefix.MatchString(prefix) {
		return "", "", false
	}
	return prefix, s[i+1:], true
}

// localPathExists reports whether s names something on this machine (following
// symlinks is fine: all that matters is that the user meant a local file).
func localPathExists(s string) bool {
	_, err := os.Stat(s)
	return err == nil
}

// withoutDotSlash drops leading "./" segments only. strings.TrimLeft(s, "./")
// would also eat the dot of a hidden name (".htaccess" → "htaccess").
func withoutDotSlash(s string) string {
	for strings.HasPrefix(s, "./") {
		s = s[2:]
	}
	return s
}

// fetchRemoteFile asks for one file and returns its verified bytes. When the
// server declines (not found, directory, too large…) it returns nil bytes and
// the server's answer, so the caller can show it as-is.
func fetchRemoteFile(account, remotePath string) ([]byte, map[string]any, error) {
	resp, err := requestJSON(http.MethodPost, fmt.Sprintf("accounts/%s/files/get", account), map[string]any{
		"path": remotePath,
	})
	if err != nil {
		return nil, nil, err
	}
	if !responseOK(resp) {
		return nil, resp, nil
	}
	result, _ := resp["result"].(map[string]any)
	if result == nil {
		return nil, nil, fmt.Errorf("download of %s returned no file", remotePath)
	}
	if enc := strval(result["encoding"]); enc != "base64" {
		return nil, nil, fmt.Errorf("download of %s used an unsupported encoding %q; update cdnctl", remotePath, enc)
	}
	data, err := base64.StdEncoding.DecodeString(strval(result["content"]))
	if err != nil {
		return nil, nil, fmt.Errorf("download of %s arrived corrupted: %w", remotePath, err)
	}
	if err := verifyDownload(data, result["size"], strval(result["sha256"])); err != nil {
		return nil, nil, fmt.Errorf("download of %s failed verification: %w; nothing was written", remotePath, err)
	}
	return data, resp, nil
}

// verifyDownload checks the bytes against the size and SHA-256 the server sent.
func verifyDownload(data []byte, size any, wantSHA string) error {
	n, ok := size.(float64)
	if !ok || int(n) != len(data) {
		return fmt.Errorf("expected %v bytes, got %d", size, len(data))
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, wantSHA) {
		return fmt.Errorf("checksum mismatch")
	}
	return nil
}

// localTargetFor decides where a downloaded file lands: inside dst when dst is an
// existing directory or ends with a path separator, otherwise at dst itself.
func localTargetFor(dst, remotePath string) string {
	name := path.Base(strings.TrimRight(remotePath, "/"))
	if dst == "" {
		return name
	}
	if strings.HasSuffix(dst, "/") || strings.HasSuffix(dst, string(os.PathSeparator)) {
		return filepath.Join(dst, name)
	}
	if info, err := os.Stat(dst); err == nil && info.IsDir() {
		return filepath.Join(dst, name)
	}
	return dst
}

// writeDownloaded writes through a temporary file in the target directory and
// renames it into place, so an interrupted download never leaves half a file
// where a whole one used to be. The result is 0644: CreateTemp makes 0600, and a
// file nobody else can read is not what anyone downloading a site file expects.
func writeDownloaded(target string, data []byte, force bool) error {
	if info, err := os.Stat(target); err == nil {
		if info.IsDir() {
			return fmt.Errorf("%s is a directory", target)
		}
		if !force {
			return fmt.Errorf("%s already exists; pass --force to overwrite it", target)
		}
	}
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("cannot create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".cdnctl-download-*")
	if err != nil {
		return fmt.Errorf("cannot write in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("cannot write %s: %w", target, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("cannot write %s: %w", target, err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		cleanup()
		return fmt.Errorf("cannot set permissions on %s: %w", target, err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		cleanup()
		return fmt.Errorf("cannot place %s: %w", target, err)
	}
	return nil
}

// withoutContent drops the base64 body from a response before it is printed, so
// a server answer never floods the terminal with the file itself.
func withoutContent(resp map[string]any) map[string]any {
	out := make(map[string]any, len(resp))
	for k, v := range resp {
		out[k] = v
	}
	if result, ok := resp["result"].(map[string]any); ok {
		trimmed := make(map[string]any, len(result))
		for k, v := range result {
			if k != "content" {
				trimmed[k] = v
			}
		}
		out["result"] = trimmed
	}
	return out
}

// cpDownload copies one remote file to the local disk, or — with -r and a remote
// directory — every file under it, into localDst (the directory's contents, the
// same way `cdnctl cp -r ./dist assets/` uploads the contents of ./dist).
func cpDownload(account, remotePath, localDst string, recursive, force bool) error {
	if strings.TrimSpace(remotePath) == "" {
		if !recursive {
			return fmt.Errorf("source must include a remote path, e.g. %q", ":uploads/pic.jpg")
		}
		// like scp's "host:", an empty path with -r is the storage root
		remotePath = "/"
	}
	if recursive {
		// A folder comes as one tar (seconds instead of ~2.4 s per file). The
		// per-file path below stays for single files and for servers that
		// cannot send a tar yet.
		if handled, err := cpDownloadTree(account, remotePath, localDst, force); handled {
			return err
		}
	}
	data, resp, err := fetchRemoteFile(account, remotePath)
	if err != nil {
		return err
	}
	if data == nil {
		if recursive && strings.EqualFold(strval(resp["error_code"]), "is_directory") {
			return cpDownloadDir(account, remotePath, localDst, force)
		}
		return printFileResponse(withoutContent(resp))
	}
	target := localTargetFor(localDst, remotePath)
	if err := writeDownloaded(target, data, force); err != nil {
		return err
	}
	result, _ := resp["result"].(map[string]any)
	return printJSON(map[string]any{
		"status":  true,
		"message": "File downloaded.",
		"result": map[string]any{
			"path":   remotePath,
			"local":  target,
			"size":   len(data),
			"sha256": strval(result["sha256"]),
		},
	})
}

// cpDownloadDir mirrors a remote directory into localDir, file by file. Progress
// goes to stderr and a JSON summary to stdout, like the recursive upload.
func cpDownloadDir(account, remoteDir, localDir string, force bool) error {
	remoteDir = strings.TrimRight(remoteDir, "/")
	downloaded, failed, skipped := 0, 0, 0

	var walk func(rel string, depth int) error
	walk = func(rel string, depth int) error {
		if depth > maxDownloadDepth {
			failed++
			fmt.Fprintf(os.Stderr, "  FAILED    %s — deeper than %d levels (a directory symlink loop?)\n", remoteDir+"/"+rel, maxDownloadDepth)
			return nil
		}
		remote := remoteDir
		if rel != "" {
			remote = remoteDir + "/" + rel
		}
		resp, err := requestJSON(http.MethodPost, fmt.Sprintf("accounts/%s/files/list", account), map[string]any{"path": remote})
		if err != nil {
			return err
		}
		if !responseOK(resp) {
			failed++
			fmt.Fprintf(os.Stderr, "  FAILED    %s — %s\n", remote, strval(resp["message"]))
			return nil
		}
		items, isList := resp["result"].([]any)
		if !isList {
			// An answer that is not a list is not an empty folder; counting it
			// as one is how a failed listing used to end in "status": true.
			failed++
			fmt.Fprintf(os.Stderr, "  FAILED    %s — the server did not return a file list\n", remote)
			return nil
		}
		for _, raw := range items {
			item, _ := raw.(map[string]any)
			name := strval(item["name"])
			if name == "" || name == "." || name == ".." {
				continue
			}
			if strings.ContainsAny(name, `/\`) {
				// A separator in a name from the server could climb out of localDir
				// once joined on this machine; refuse it rather than write it.
				failed++
				fmt.Fprintf(os.Stderr, "  FAILED    %q — unsafe file name, not written\n", name)
				continue
			}
			childRel := name
			if rel != "" {
				childRel = rel + "/" + name
			}
			if strval(item["type"]) == "folder" {
				if isLink, _ := item["link"].(bool); isLink {
					// A symlinked folder can point back at its own parent; the
					// files it leads to are downloaded where they really live.
					skipped++
					fmt.Fprintf(os.Stderr, "  skipped   %s/ — a link to another folder, not followed\n", childRel)
					continue
				}
				if err := walk(childRel, depth+1); err != nil {
					return err
				}
				continue
			}
			data, fileResp, err := fetchRemoteFile(account, remoteDir+"/"+childRel)
			if err != nil {
				failed++
				fmt.Fprintf(os.Stderr, "  FAILED    %s — %v\n", childRel, err)
				continue
			}
			if data == nil {
				failed++
				fmt.Fprintf(os.Stderr, "  FAILED    %s — %s\n", childRel, strval(fileResp["message"]))
				continue
			}
			target := filepath.Join(localDir, filepath.FromSlash(childRel))
			if err := writeDownloaded(target, data, force); err != nil {
				failed++
				fmt.Fprintf(os.Stderr, "  FAILED    %s — %v\n", childRel, err)
				continue
			}
			downloaded++
			fmt.Fprintf(os.Stderr, "  downloaded  %s\n", childRel)
		}
		return nil
	}

	if err := walk("", 0); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr)
	summary := map[string]any{
		"status":     failed == 0,
		"downloaded": downloaded,
		"skipped":    skipped,
		"failed":     failed,
		"source":     remoteDir,
		"local":      localDir,
	}
	if err := printJSON(summary); err != nil {
		return err
	}
	if failed > 0 {
		return errExit(1)
	}
	return nil
}
