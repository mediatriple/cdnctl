package main

// Folder download as one tar stream (cdnctl cp -r <acct>:dir, cdnctl sync).
//
// File by file, every file cost one kubectl exec plus two HTTP hops — about
// 2.4 s — so a 568-file wp-content took ~23 minutes; the same folder as one
// plain tar takes seconds. The server appends a trailer after the tar:
//
//	<tar bytes><tar's stderr>\nCDNTAR-END v=1 rc=<n> bytes=<n> sha256=<hex>\n
//
// A tar cut at a member boundary is itself a valid-looking tar, so nothing is
// trusted until that trailer has been read and the byte count and SHA-256 of
// everything that arrived match it. Until then every file sits under a temp
// name next to its target; only a verified stream is renamed into place, and a
// bad one leaves the destination as it was.

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// maxTarTail bounds what may follow the tar's end-of-archive blocks: record
// padding (< 10 KiB), tar's stderr (≤ 64 KiB) and the trailer line.
const maxTarTail = 1<<20 + 64<<10

var tarTrailerLine = regexp.MustCompile(`^CDNTAR-END v=1 rc=(\d+) bytes=(\d+) sha256=([0-9a-f]{64})$`)

type tarTrailer struct {
	RC     int
	Bytes  int64
	SHA256 string
}

// pathNote is one path in a report, with why it is there.
type pathNote struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// hashCounter counts and hashes every byte handed to archive/tar.
type hashCounter struct {
	r io.Reader
	h hash.Hash
	n int64
}

func (c *hashCounter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.h.Write(p[:n])
	c.n += int64(n)
	return n, err
}

// errIncompleteDownload marks a stream that cannot be trusted as a whole.
var errIncompleteDownload = errors.New("the download was incomplete")

func incomplete(format string, args ...any) error {
	return fmt.Errorf("%w (%s); nothing was placed — run the same command again", errIncompleteDownload, fmt.Sprintf(format, args...))
}

// verifyTarTail reads what follows the tar (after Next returned io.EOF) and
// checks the trailer against everything read so far. It returns tar's stderr.
func verifyTarTail(c *hashCounter) (tarTrailer, string, error) {
	rest, err := io.ReadAll(io.LimitReader(c.r, maxTarTail+1))
	if err != nil {
		return tarTrailer{}, "", incomplete("%v", err)
	}
	if len(rest) > maxTarTail {
		return tarTrailer{}, "", incomplete("unexpected data after the archive")
	}
	if len(rest) == 0 || rest[len(rest)-1] != '\n' {
		return tarTrailer{}, "", incomplete("the end marker is missing")
	}
	body := rest[:len(rest)-1]
	nl := bytes.LastIndexByte(body, '\n')
	if nl < 0 {
		return tarTrailer{}, "", incomplete("the end marker is missing")
	}
	m := tarTrailerLine.FindSubmatch(body[nl+1:])
	if m == nil {
		return tarTrailer{}, "", incomplete("the end marker is garbled")
	}
	rc, _ := strconv.Atoi(string(m[1]))
	total, err := strconv.ParseInt(string(m[2]), 10, 64)
	if err != nil {
		return tarTrailer{}, "", incomplete("the end marker is garbled")
	}
	trailer := tarTrailer{RC: rc, Bytes: total, SHA256: string(m[3])}
	pad := total - c.n
	if pad < 0 || pad > int64(nl) {
		return trailer, "", incomplete("expected %d bytes, received %d", total, c.n+int64(nl))
	}
	c.h.Write(rest[:pad])
	if got := hex.EncodeToString(c.h.Sum(nil)); got != trailer.SHA256 {
		return trailer, "", incomplete("checksum mismatch")
	}
	return trailer, string(rest[pad:nl]), nil
}

type extractOptions struct {
	root    string
	force   bool            // replace existing files that differ
	only    map[string]bool // non-nil: accept only these names (what sync asked for)
	windows bool            // apply the Windows name rules
	// progress, when set, gets one line per placed file.
	progress io.Writer
}

type extractResult struct {
	Placed      []string
	Unchanged   int
	Bytes       int64
	Skipped     []pathNote
	Failed      []pathNote
	NotReplaced []string
	Received    map[string]bool
	Trailer     tarTrailer
	TarStderr   string
}

type pendingFile struct {
	rel, tmp, target string
	size             int64
}

// extractTar reads a tar stream with its trailer into opts.root. A non-nil
// error means the stream as a whole is not trustworthy: every temp file and
// every folder this call created is removed again. Problems with single
// entries (unsafe names, symlinks, a folder in the way) are reported in the
// result and do not stop the rest.
func extractTar(body io.Reader, opts extractOptions) (res extractResult, err error) {
	res.Received = map[string]bool{}
	var created []string
	pending := map[string]*pendingFile{}
	var order []string
	defer func() {
		if err == nil {
			return
		}
		for _, p := range pending {
			_ = os.Remove(p.tmp)
		}
		for i := len(created) - 1; i >= 0; i-- {
			_ = os.Remove(created[i]) // only empty folders go
		}
	}()

	if _, statErr := os.Lstat(opts.root); os.IsNotExist(statErr) {
		if mkErr := os.MkdirAll(opts.root, 0o755); mkErr != nil {
			return res, fmt.Errorf("cannot create %s: %w", opts.root, mkErr)
		}
		created = append(created, opts.root)
	} else if statErr != nil {
		return res, statErr
	} else if info, _ := os.Stat(opts.root); info == nil || !info.IsDir() {
		return res, fmt.Errorf("%s is not a folder", opts.root)
	}

	counter := &hashCounter{r: body, h: sha256.New()}
	tr := tar.NewReader(counter)
	for {
		hdr, nextErr := tr.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return res, incomplete("%v", nextErr)
		}
		rel := cleanTarName(hdr.Name)
		if rel == "" || hdr.Typeflag == tar.TypeXGlobalHeader {
			continue // the folder itself, or pax metadata
		}
		if nameErr := checkRelName(rel, opts.windows); nameErr != nil {
			res.Skipped = append(res.Skipped, pathNote{rel, "name: " + nameErr.Error()})
			continue
		}
		if opts.only != nil && !opts.only[rel] {
			res.Skipped = append(res.Skipped, pathNote{rel, "not requested"})
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			res.Received[rel] = true
			if dirErr := ensureLocalDirs(opts.root, rel, &created); dirErr != nil {
				res.Failed = append(res.Failed, pathNote{rel, dirErr.Error()})
			}
			continue
		case tar.TypeReg:
		case tar.TypeSymlink:
			res.Skipped = append(res.Skipped, pathNote{rel, "symlink"})
			continue
		default:
			res.Skipped = append(res.Skipped, pathNote{rel, "special"})
			continue
		}
		res.Received[rel] = true
		parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(rel)))
		if parent == "." {
			parent = ""
		}
		if dirErr := ensureLocalDirs(opts.root, parent, &created); dirErr != nil {
			res.Failed = append(res.Failed, pathNote{rel, dirErr.Error()})
			continue
		}
		target := filepath.Join(opts.root, filepath.FromSlash(rel))
		if info, statErr := os.Lstat(target); statErr == nil && info.IsDir() {
			res.Failed = append(res.Failed, pathNote{rel, "a folder is in the way"})
			continue
		}
		tmp, tmpErr := os.CreateTemp(filepath.Dir(target), ".cdnctl-*")
		if tmpErr != nil {
			res.Failed = append(res.Failed, pathNote{rel, tmpErr.Error()})
			continue
		}
		n, copyErr := io.Copy(tmp, tr)
		closeErr := tmp.Close()
		if copyErr != nil {
			_ = os.Remove(tmp.Name())
			var pathErr *os.PathError
			if errors.As(copyErr, &pathErr) {
				// writing here failed (disk full…): this file only
				res.Failed = append(res.Failed, pathNote{rel, copyErr.Error()})
				continue
			}
			return res, incomplete("%v", copyErr)
		}
		mode := os.FileMode(0o644)
		if hdr.Mode&0o111 != 0 {
			mode = 0o755
		}
		if closeErr == nil {
			closeErr = os.Chmod(tmp.Name(), mode)
		}
		if closeErr == nil {
			closeErr = os.Chtimes(tmp.Name(), hdr.ModTime, hdr.ModTime)
		}
		if closeErr != nil {
			_ = os.Remove(tmp.Name())
			res.Failed = append(res.Failed, pathNote{rel, closeErr.Error()})
			continue
		}
		if old, dup := pending[rel]; dup {
			_ = os.Remove(old.tmp) // a name archived twice: the last copy wins, as with tar
		} else {
			order = append(order, rel)
		}
		pending[rel] = &pendingFile{rel: rel, tmp: tmp.Name(), target: target, size: n}
	}

	trailer, stderr, tailErr := verifyTarTail(counter)
	res.Trailer, res.TarStderr = trailer, stderr
	if tailErr != nil {
		return res, tailErr
	}

	// Verified: now, and only now, the files take their places.
	for _, rel := range order {
		p := pending[rel]
		delete(pending, rel)
		if info, statErr := os.Lstat(p.target); statErr == nil && !opts.force {
			if info.Mode().IsRegular() && sameFileContent(p.tmp, p.target) {
				_ = os.Remove(p.tmp)
				res.Unchanged++
				continue
			}
			_ = os.Remove(p.tmp)
			res.NotReplaced = append(res.NotReplaced, rel)
			continue
		}
		if renameErr := os.Rename(p.tmp, p.target); renameErr != nil {
			_ = os.Remove(p.tmp)
			res.Failed = append(res.Failed, pathNote{rel, renameErr.Error()})
			continue
		}
		res.Placed = append(res.Placed, rel)
		res.Bytes += p.size
		if opts.progress != nil {
			fmt.Fprintf(opts.progress, "  downloaded  %s\n", rel)
		}
	}
	return res, nil
}

// sameFileContent compares two local files byte for byte.
func sameFileContent(a, b string) bool {
	ia, errA := os.Stat(a)
	ib, errB := os.Stat(b)
	if errA != nil || errB != nil || ia.Size() != ib.Size() {
		return false
	}
	ha, errA := fileSHA256(a)
	hb, errB := fileSHA256(b)
	return errA == nil && errB == nil && ha == hb
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// downloadTar asks for folder as one tar — the whole folder when files is nil,
// otherwise just those entries — and extracts it. A non-nil answer map is the
// server declining (printed as-is by the caller).
func downloadTar(account, folder string, files []string, opts extractOptions) (extractResult, map[string]any, error) {
	payload := map[string]any{"path": folder, "files": nil}
	if files != nil {
		payload["files"] = files
	}
	body, answer, err := requestStream(fmt.Sprintf("accounts/%s/files/tar", account), payload)
	if err != nil || answer != nil {
		return extractResult{}, answer, err
	}
	defer body.Close()
	res, err := extractTar(body, opts)
	return res, nil, err
}

// tarProblems turns a non-zero tar exit code and its messages into report lines.
func tarProblems(res extractResult) []pathNote {
	if res.Trailer.RC == 0 {
		return nil
	}
	reason := fmt.Sprintf("tar exit code %d", res.Trailer.RC)
	if res.Trailer.RC == 1 {
		reason += " (some files changed while they were read)"
	} else {
		reason += " (some entries could not be read)"
	}
	var out []pathNote
	for _, line := range strings.Split(strings.TrimSpace(res.TarStderr), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, pathNote{Path: "(server)", Reason: line})
		}
	}
	return append(out, pathNote{Path: "(server)", Reason: reason})
}

// cpDownloadTree is `cdnctl cp -r <acct>:dir <local>`: the folder's contents as
// one tar. It returns handled=false when the server cannot do it (no GNU tar in
// the pod, or a panel without the route) so the caller copies file by file.
func cpDownloadTree(account, remoteDir, localDir string, force bool) (handled bool, err error) {
	remoteDir = strings.TrimRight(remoteDir, "/")
	fmt.Fprintf(os.Stderr, "Downloading the contents of %s into %s as one archive…\n", displayRemote(remoteDir), localDir)
	res, answer, err := downloadTar(account, remoteDir, nil, extractOptions{
		root:     localDir,
		force:    force,
		windows:  localNameRules(),
		progress: os.Stderr,
	})
	if answer != nil {
		if responseOK(answer) {
			answer = unexpectedAnswer("an archive")
		}
		if streamUnsupported(answer) {
			fmt.Fprintln(os.Stderr, "(this server cannot send a folder as one archive yet; copying file by file)")
			return false, nil
		}
		if strval(answer["error_code"]) == "not_a_directory" {
			return false, nil // a single file: the per-file path handles it
		}
		return true, printFileResponse(answer)
	}
	if err != nil {
		return true, err
	}
	failed := append(res.Failed, tarProblems(res)...)
	for _, n := range failed {
		fmt.Fprintf(os.Stderr, "  FAILED    %s — %s\n", n.Path, n.Reason)
	}
	for _, n := range res.Skipped {
		fmt.Fprintf(os.Stderr, "  skipped   %s — %s\n", n.Path, n.Reason)
	}
	for _, rel := range res.NotReplaced {
		fmt.Fprintf(os.Stderr, "  FAILED    %s — already exists and differs; pass --force to overwrite it\n", rel)
	}
	fmt.Fprintln(os.Stderr)
	ok := len(failed) == 0 && len(res.NotReplaced) == 0
	summary := map[string]any{
		"status":     ok,
		"downloaded": len(res.Placed),
		"unchanged":  res.Unchanged,
		"skipped":    len(res.Skipped),
		"failed":     len(failed) + len(res.NotReplaced),
		"bytes":      res.Bytes,
		"source":     remoteDir,
		"local":      localDir,
	}
	if len(res.NotReplaced) > 0 {
		sort.Strings(res.NotReplaced)
		summary["not_replaced"] = res.NotReplaced
	}
	if len(failed) > 0 {
		summary["problems"] = failed
	}
	if err := printJSON(summary); err != nil {
		return true, err
	}
	if !ok {
		return true, errExit(1)
	}
	return true, nil
}

// unexpectedAnswer replaces a "successful" JSON answer where a stream was
// expected: printing it would report success for a transfer that never ran.
func unexpectedAnswer(what string) map[string]any {
	return map[string]any{"status": false, "error_code": "unexpected_answer", "message": "the server answered without " + what + "; update cdnctl (cdnctl update --check) or try again"}
}

// displayRemote renders a remote folder for messages ("" is the storage root).
func displayRemote(p string) string {
	if p == "" {
		return ":/"
	}
	return ":" + p
}
