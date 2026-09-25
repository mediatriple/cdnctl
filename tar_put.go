package main

// Folder upload as one tar (cdnctl cp -r ./dir <acct>:dir, cdnctl sync).
//
// A request body is never streamed: the edge caps bodies at 100 MB and the
// panel's Apache buffers them whole. So the tar is cut into parts of at most
// 32 MiB, each part goes through the existing, verified single-file upload
// (files/put: size and SHA-256 checked) to .cdn-upload.<session>/part-NNNNN at
// the storage root, and one tar-apply call extracts the concatenation.
//
// The tar holds only folders and regular files with modes 0644/0755. After them
// comes an optional .cdnctl-delete (what --delete removes) and, LAST,
// .cdnctl-sums: the SHA-256 of every file sent. The server refuses a tar
// without it — a stream cut at a member boundary is otherwise a valid tar —
// and places only files whose bytes on disk match their sum.

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// uploadPartSize is a variable so tests can cut parts small.
var uploadPartSize int64 = 32 << 20

const maxUploadParts = 100000

// badSumSentinel is written as the sum of a file that changed size while it
// was being archived: its bytes in the tar are padded and must not be placed,
// and a sum that can never match makes the server refuse exactly that file.
const badSumSentinel = "0000000000000000000000000000000000000000000000000000000000000000"

type uploadItem struct {
	Rel   string // slash path relative to the destination folder
	Local string // local path
	Dir   bool
}

// newUploadSession returns the 32 lowercase hex characters the server expects.
func newUploadSession() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func partTarget(session string, n int) string {
	return fmt.Sprintf(".cdn-upload.%s/part-%05d", session, n)
}

// partWriter spools the tar to a temp file and hands each full part to send,
// so memory stays bounded whatever the size of the folder.
type partWriter struct {
	spool *os.File
	n     int64
	parts int
	total int64
	h     hash.Hash
	send  func(part int, path string, size int64, sha string) error
}

func newPartWriter(send func(part int, path string, size int64, sha string) error) (*partWriter, error) {
	spool, err := os.CreateTemp("", "cdnctl-part-*")
	if err != nil {
		return nil, err
	}
	return &partWriter{spool: spool, h: sha256.New(), send: send}, nil
}

func (w *partWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		room := uploadPartSize - w.n
		chunk := p
		if int64(len(chunk)) > room {
			chunk = chunk[:room]
		}
		if _, err := w.spool.Write(chunk); err != nil {
			return written, err
		}
		w.h.Write(chunk)
		w.n += int64(len(chunk))
		w.total += int64(len(chunk))
		written += len(chunk)
		p = p[len(chunk):]
		if w.n == uploadPartSize {
			if err := w.flush(); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

func (w *partWriter) flush() error {
	if w.n == 0 {
		return nil
	}
	w.parts++
	if w.parts > maxUploadParts {
		return fmt.Errorf("the folder is too large for one upload (more than %d parts)", maxUploadParts)
	}
	if err := w.send(w.parts, w.spool.Name(), w.n, hex.EncodeToString(w.h.Sum(nil))); err != nil {
		return err
	}
	if err := w.spool.Truncate(0); err != nil {
		return err
	}
	if _, err := w.spool.Seek(0, io.SeekStart); err != nil {
		return err
	}
	w.n = 0
	w.h.Reset()
	return nil
}

// Close sends the last, partial part and removes the spool file.
func (w *partWriter) Close() error {
	err := w.flush()
	name := w.spool.Name()
	_ = w.spool.Close()
	_ = os.Remove(name)
	return err
}

// discard removes the spool file without sending anything.
func (w *partWriter) discard() {
	name := w.spool.Name()
	_ = w.spool.Close()
	_ = os.Remove(name)
}

type tarBuildResult struct {
	Files        []string   // regular files written (relative paths)
	Bytes        int64      // file bytes written
	Failed       []pathNote // files that could not be archived as they were listed
	DeleteListed bool       // .cdnctl-delete was written
}

// writeUploadTar writes items, then .cdnctl-delete (when deletes is non-empty
// and nothing failed so far), then .cdnctl-sums, to w.
func writeUploadTar(w io.Writer, items []uploadItem, deletes []string) (tarBuildResult, error) {
	var res tarBuildResult
	tw := tar.NewWriter(w)
	var sums strings.Builder
	for _, it := range items {
		if err := checkRelName(it.Rel, false); err != nil {
			res.Failed = append(res.Failed, pathNote{it.Rel, "name: " + err.Error()})
			continue
		}
		if it.Dir {
			info, err := os.Lstat(it.Local)
			if err != nil || !info.IsDir() {
				res.Failed = append(res.Failed, pathNote{it.Rel, "the folder changed while it was being read"})
				continue
			}
			if err := tw.WriteHeader(&tar.Header{
				Typeflag: tar.TypeDir,
				Name:     it.Rel + "/",
				Mode:     0o755,
				ModTime:  time.Unix(info.ModTime().Unix(), 0),
			}); err != nil {
				return res, err
			}
			continue
		}
		sum, n, failure, err := writeUploadFile(tw, it)
		if err != nil {
			return res, err
		}
		if failure != "" {
			res.Failed = append(res.Failed, pathNote{it.Rel, failure})
			if sum == "" {
				continue // nothing was written for it
			}
		}
		res.Files = append(res.Files, it.Rel)
		res.Bytes += n
		// "./": a file named "-" would otherwise make sha256sum --check read stdin
		fmt.Fprintf(&sums, "%s  ./%s\n", sum, it.Rel)
	}
	if len(deletes) > 0 && len(res.Failed) == 0 {
		var list bytes.Buffer
		for _, rel := range deletes {
			list.WriteString(rel)
			list.WriteByte(0)
		}
		if err := writeUploadMember(tw, ".cdnctl-delete", list.Bytes()); err != nil {
			return res, err
		}
		s := sha256.Sum256(list.Bytes())
		fmt.Fprintf(&sums, "%s  ./%s\n", hex.EncodeToString(s[:]), ".cdnctl-delete")
		res.DeleteListed = true
	}
	if err := writeUploadMember(tw, ".cdnctl-sums", []byte(sums.String())); err != nil {
		return res, err
	}
	return res, tw.Close()
}

func writeUploadMember(tw *tar.Writer, name string, data []byte) error {
	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(data)),
		ModTime:  time.Unix(time.Now().Unix(), 0),
	}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// writeUploadFile archives one regular file. failure is a per-file problem
// (the file vanished, turned into a link, shrank); err is a problem with the
// archive itself, which ends the upload.
func writeUploadFile(tw *tar.Writer, it uploadItem) (sum string, n int64, failure string, err error) {
	linfo, lerr := os.Lstat(it.Local)
	if lerr != nil || !linfo.Mode().IsRegular() {
		return "", 0, "the file changed while it was being read (vanished or no longer a plain file)", nil
	}
	f, oerr := os.Open(it.Local)
	if oerr != nil {
		return "", 0, oerr.Error(), nil
	}
	defer f.Close()
	info, serr := f.Stat()
	if serr != nil || !os.SameFile(linfo, info) {
		return "", 0, "the file changed while it was being read", nil
	}
	mode := int64(0o644)
	if info.Mode().Perm()&0o111 != 0 {
		mode = 0o755
	}
	size := info.Size()
	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     it.Rel,
		Mode:     mode,
		Size:     size,
		ModTime:  time.Unix(info.ModTime().Unix(), 0),
	}); err != nil {
		return "", 0, "", err
	}
	h := sha256.New()
	copied, cerr := io.CopyN(io.MultiWriter(tw, h), f, size)
	if cerr != nil && !errors.Is(cerr, io.EOF) {
		var pathErr *os.PathError
		if !errors.As(cerr, &pathErr) || pathErr.Path != f.Name() {
			return "", 0, "", cerr // the archive (spool/upload) failed
		}
	}
	if copied < size {
		// The header already promised size bytes; fill them so the archive stays
		// well-formed, and let the sentinel sum keep the server from placing it.
		if _, err := io.CopyN(tw, zeroReader{}, size-copied); err != nil {
			return "", 0, "", err
		}
		return badSumSentinel, size, "the file shrank while it was being read; not placed", nil
	}
	// Written to (or grown) during the copy: the bytes sent may be half old,
	// half new. The same sentinel keeps that mix off the server.
	if after, err := f.Stat(); err != nil || after.Size() != size || !after.ModTime().Equal(info.ModTime()) {
		return badSumSentinel, size, "the file changed while it was being read; not placed", nil
	}
	return hex.EncodeToString(h.Sum(nil)), size, "", nil
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// uploadPart sends one part with the verified single-file upload. A part can
// be 32 MiB, which a slow uplink does not move within doRequest's usual 120 s,
// so the timeout grows with the size (64 KiB/s floor). One retry covers a
// dropped connection or a gateway hiccup; the server refuses nothing twice.
func uploadPart(account, spoolPath, target string, size int64, sha string) (map[string]any, error) {
	timeout := 120*time.Second + time.Duration(size/(64<<10))*time.Second
	fields := map[string]string{"target_path": target, "overwrite": "1"}
	var resp map[string]any
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		resp, err = requestMultipartTimeout(http.MethodPost, fmt.Sprintf("accounts/%s/files/put", account), fields, "file", spoolPath, timeout)
		if err != nil {
			return nil, err
		}
		status := httpStatusOf(resp) // 0: no answer at all (connection failed)
		if responseOK(resp) || !(status == 0 || status == 502 || status == 503 || status == 504) {
			break
		}
	}
	if !responseOK(resp) {
		return resp, nil
	}
	// files/put answers with the size and SHA-256 of what it stored; a part that
	// arrived different is caught here rather than as a tar error later.
	if result, ok := resp["result"].(map[string]any); ok {
		if got := strval(result["sha256"]); got != "" && !strings.EqualFold(got, sha) {
			return map[string]any{"status": false, "error_code": "upload_mismatch", "message": fmt.Sprintf("part %s arrived with a different checksum; run the command again", target)}, nil
		}
	}
	return resp, nil
}

// errPartRefused carries the server's answer for a part it did not accept.
type errPartRefused struct{ resp map[string]any }

// A tar-apply answered "busy" is retried with the same session this many
// times, this far apart (10 minutes in all); vars so tests can shorten them.
var (
	applyBusyRetries = 30
	applyBusyWait    = 20 * time.Second
)

// discardUploadSession asks the server to remove the parts of an upload that
// will not be applied, so they do not sit in the customer's storage until the
// server's 24-hour janitor. Best effort: a failure here changes nothing else.
func discardUploadSession(account, session string) {
	_, _ = requestStreamJSON(fmt.Sprintf("accounts/%s/files/tar-apply", account), map[string]any{
		"session": session,
		"discard": true,
	})
}

func (e errPartRefused) Error() string { return "the server refused an upload part" }

type uploadOutcome struct {
	Parts        int
	TarBytes     int64
	Build        tarBuildResult
	Answer       map[string]any // tar-apply's answer
	Placed       int
	Deleted      int
	BadSum       []string
	NotPlaced    []string
	Conflicts    []string
	Truncated    bool
	OK           bool
	DeleteListed bool
}

// uploadTar archives items (+ deletes) into parts, uploads them and applies
// them to dest. A non-nil map is a refusal (a part the server did not take, or
// tar-apply declining before it ran) for the caller to print or fall back on.
func uploadTar(account, dest string, items []uploadItem, deletes []string, overwrite bool, progress io.Writer) (uploadOutcome, map[string]any, error) {
	var out uploadOutcome
	session, err := newUploadSession()
	if err != nil {
		return out, nil, err
	}
	pw, err := newPartWriter(func(part int, path string, size int64, sha string) error {
		resp, err := uploadPart(account, path, partTarget(session, part), size, sha)
		if err != nil {
			return err
		}
		if !responseOK(resp) {
			return errPartRefused{resp}
		}
		if progress != nil {
			fmt.Fprintf(progress, "  part %d uploaded (%s)\n", part, humanBytes(size))
		}
		return nil
	})
	if err != nil {
		return out, nil, err
	}
	build, err := writeUploadTar(pw, items, deletes)
	if err == nil {
		err = pw.Close()
	} else {
		pw.discard()
	}
	out.Build, out.Parts, out.TarBytes = build, pw.parts, pw.total
	out.DeleteListed = build.DeleteListed
	var refused errPartRefused
	if errors.As(err, &refused) {
		discardUploadSession(account, session)
		return out, refused.resp, nil
	}
	if err != nil {
		discardUploadSession(account, session)
		return out, nil, err
	}

	if progress != nil {
		fmt.Fprintf(progress, "Placing the upload in %s (the server unpacks and checks every file)…\n", displayRemote(dest))
	}
	apply := map[string]any{
		"path":      dest,
		"session":   session,
		"parts":     out.Parts,
		"overwrite": overwrite,
		"delete":    build.DeleteListed,
	}
	var answer map[string]any
	for attempt := 1; ; attempt++ {
		answer, err = requestStreamJSON(fmt.Sprintf("accounts/%s/files/tar-apply", account), apply)
		if err != nil {
			// The server may still be applying (it does not stop when the
			// connection drops) and removes the session itself; leave it be.
			return out, nil, err
		}
		if strval(answer["error_code"]) != "busy" || attempt > applyBusyRetries {
			break
		}
		// Another transfer holds this account's slot. The parts are already on
		// the server, so wait and apply the same session instead of re-uploading.
		fmt.Fprintf(os.Stderr, "  the server is busy with another transfer; trying again in %s (%d/%d)\n", applyBusyWait, attempt, applyBusyRetries)
		time.Sleep(applyBusyWait)
	}
	if strval(answer["error_code"]) == "busy" {
		discardUploadSession(account, session)
	}
	out.Answer = answer
	if streamUnsupported(answer) && strval(answer["error_code"]) == "" {
		// A panel without tar-apply never cleans the session up; try to.
		_, _ = requestJSON(http.MethodPost, fmt.Sprintf("accounts/%s/files/delete", account), map[string]any{"path": ".cdn-upload." + session})
	}
	result, _ := answer["result"].(map[string]any)
	out.Placed = intValue(result["placed"])
	out.Deleted = intValue(result["deleted"])
	out.BadSum = stringList(result["bad_sum"])
	out.NotPlaced = stringList(result["not_placed"])
	out.Conflicts = stringList(result["conflicts"])
	out.Truncated, _ = result["truncated_lists"].(bool)
	out.OK = responseOK(answer) && len(out.BadSum) == 0 && len(out.NotPlaced) == 0 && len(out.Conflicts) == 0
	return out, nil, nil
}

func intValue(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

func stringList(v any) []string {
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, strval(it))
	}
	return out
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// localUploadItems lists a local folder for upload: folders and regular files,
// sorted; symlinks and special files are reported as skipped, unreadable
// entries and unusable names as failed.
func localUploadItems(root string) (items []uploadItem, skipped, failed []pathNote, err error) {
	entries, walkErrs, err := walkLocal(root)
	if err != nil {
		return nil, nil, nil, err
	}
	failed = append(failed, walkErrs...)
	for _, rel := range sortedKeys(entries) {
		e := entries[rel]
		switch {
		case e.Type != 'f' && e.Type != 'd':
			skipped = append(skipped, pathNote{rel, typeWord(e.Type)})
		case hasReservedSegment(rel):
			skipped = append(skipped, pathNote{rel, "name"})
		case checkRelName(rel, false) != nil:
			failed = append(failed, pathNote{rel, "name: " + checkRelName(rel, false).Error()})
		default:
			items = append(items, uploadItem{Rel: rel, Local: filepath.Join(root, filepath.FromSlash(rel)), Dir: e.Type == 'd'})
		}
	}
	return items, skipped, failed, nil
}

// cpUploadTree is `cdnctl cp -r ./dir <acct>:dir` as one archive. handled is
// false when the server cannot apply a tar, so the caller uploads file by file.
func cpUploadTree(account, localDir, remoteBase string, force bool) (handled bool, err error) {
	remoteBase = strings.TrimRight(remoteBase, "/")
	items, skipped, failed, err := localUploadItems(localDir)
	if err != nil {
		return true, err
	}
	for _, n := range skipped {
		fmt.Fprintf(os.Stderr, "  skipped   %s — %s\n", n.Path, n.Reason)
	}
	if len(failed) > 0 {
		for _, n := range failed {
			fmt.Fprintf(os.Stderr, "  FAILED    %s — %s\n", n.Path, n.Reason)
		}
		// Refused names are refused before anything is sent.
		_ = printJSON(map[string]any{"status": false, "uploaded": 0, "failed": len(failed), "problems": failed})
		return true, errExit(1)
	}
	fmt.Fprintf(os.Stderr, "Uploading the contents of %s into %s as one archive…\n", localDir, displayRemote(remoteBase))
	out, answer, err := uploadTar(account, remoteBase, items, nil, force, os.Stderr)
	if err != nil {
		return true, err
	}
	if answer != nil {
		fmt.Fprintln(os.Stderr)
		if responseStorageFull(answer) {
			_ = printJSON(map[string]any{
				"status":     false,
				"uploaded":   0,
				"failed":     len(out.Build.Files),
				"aborted":    true,
				"error_code": "storage_full",
				"message":    "Persistent storage is full; the upload stopped before anything was placed.",
			})
			return true, errExit(1)
		}
		return true, printFileResponse(answer)
	}
	if streamUnsupported(out.Answer) {
		fmt.Fprintln(os.Stderr, "(this server cannot unpack an uploaded archive yet; uploading file by file)")
		return false, nil
	}
	return true, reportUploadOutcome(out, len(skipped), force)
}

func reportUploadOutcome(out uploadOutcome, skipped int, force bool) error {
	problems := append([]pathNote{}, out.Build.Failed...)
	for _, p := range out.BadSum {
		problems = append(problems, pathNote{p, "checksum mismatch on the server; not placed"})
	}
	for _, p := range out.NotPlaced {
		problems = append(problems, pathNote{p, "already exists; pass --force to overwrite it"})
	}
	conflict := "something else is in the way on the server"
	if !force {
		// without overwrite the apply script keeps an existing file and names it here
		conflict = "already exists on the server (kept; pass --force to overwrite it) or something else is in the way"
	}
	for _, p := range out.Conflicts {
		problems = append(problems, pathNote{p, conflict})
	}
	ok := out.OK && len(out.Build.Failed) == 0
	if !responseOK(out.Answer) && len(problems) == 0 {
		problems = append(problems, pathNote{"(server)", firstNonEmpty(strval(out.Answer["message"]), strval(out.Answer["error_code"]), strval(out.Answer["raw_body"]), "tar-apply failed")})
	}
	for _, n := range problems {
		fmt.Fprintf(os.Stderr, "  FAILED    %s — %s\n", n.Path, n.Reason)
	}
	fmt.Fprintln(os.Stderr)
	summary := map[string]any{
		"status":   ok,
		"uploaded": out.Placed,
		"failed":   len(problems),
		"skipped":  skipped,
		"bytes":    out.Build.Bytes,
		"parts":    out.Parts,
	}
	if code := strval(out.Answer["error_code"]); code != "" {
		summary["error_code"] = code
	}
	if len(problems) > 0 {
		summary["problems"] = problems
	}
	if out.Truncated {
		summary["truncated_lists"] = true
	}
	if err := printJSON(summary); err != nil {
		return err
	}
	if !ok {
		return errExit(1)
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
