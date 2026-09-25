package main

// A fake panel that implements the folder-transfer contract (tree, tar,
// tar-apply) over a real directory standing in for the account's storage, plus
// files/put for upload parts and files/get + files/list for the per-file
// fallback. Archives are real tars with the real trailer, so the client is
// tested against the bytes it will meet, and knobs break them on purpose.

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type tarServer struct {
	t    *testing.T
	root string
	srv  *httptest.Server

	mu    sync.Mutex
	calls []string // "<route> <path>"

	// knobs
	busy            bool                     // every stream route answers 429 busy
	busyApplies     int                      // the next N tar-apply calls answer 429 busy
	toolMissing     bool                     // every stream route answers tool_missing
	tarRC           int                      // exit code reported in the trailer
	tarStderr       string                   // tar's messages before the trailer
	rawTar          func() []byte            // replaces the archive (odd names)
	mutate          func(body []byte) []byte // rewrites the whole tar response
	treeRC          int                      // find exit code in the tree trailer
	applyHeartbeats int                      // spaces sent before tar-apply's JSON
	dropFromTar     map[string]bool          // requested names the "pod" leaves out
	corruptStaged   string                   // a staged file whose bytes change on "disk"

	// observed
	tarFiles     []string // "files" of the last tar request (nil = whole folder)
	tarWhole     bool
	applyReq     map[string]any
	applyMembers []string // member names of the last applied tar, in order
	parts        []string // target paths of uploaded parts
	partSizes    []int
	puts         []string // target paths of every files/put
}

func newTarServer(t *testing.T) *tarServer {
	t.Helper()
	s := &tarServer{t: t, root: t.TempDir()}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.srv.Close)
	useServer(t, s.srv.URL)
	return s
}

func (s *tarServer) callList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *tarServer) called(route string) int {
	n := 0
	for _, c := range s.callList() {
		if strings.HasPrefix(c, route+" ") {
			n++
		}
	}
	return n
}

// write puts a file into the fake storage with a fixed mtime.
func (s *tarServer) write(rel, body string, mode os.FileMode, mtime time.Time) {
	s.t.Helper()
	p := filepath.Join(s.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		s.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		s.t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		s.t.Fatal(err)
	}
	if err := os.Chtimes(p, mtime, mtime); err != nil {
		s.t.Fatal(err)
	}
}

func (s *tarServer) read(rel string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(s.root, filepath.FromSlash(rel)))
	return string(b), err == nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *tarServer) handle(w http.ResponseWriter, r *http.Request) {
	route := r.URL.Path[strings.LastIndex(r.URL.Path, "/files/")+len("/files/"):]
	var req map[string]any
	if route == "put" {
		if err := r.ParseMultipartForm(64 << 20); err != nil {
			s.t.Errorf("bad multipart: %v", err)
		}
		req = map[string]any{"path": r.FormValue("target_path")}
	} else {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	s.mu.Lock()
	s.calls = append(s.calls, route+" "+strval(req["path"]))
	s.mu.Unlock()

	switch route {
	case "tree", "tar", "tar-apply":
		if s.busy {
			writeJSON(w, 429, map[string]any{"status": false, "error_code": "busy", "message": "Another transfer is running for this account, try again in a minute."})
			return
		}
		if route == "tar-apply" && req["discard"] != true && s.busyApplies > 0 {
			s.busyApplies--
			writeJSON(w, 429, map[string]any{"status": false, "error_code": "busy", "message": "Another transfer is running for this account, try again in a minute."})
			return
		}
		if s.toolMissing {
			writeJSON(w, 501, map[string]any{"status": false, "error_code": "tool_missing", "message": "The site has no GNU tar."})
			return
		}
	}
	switch route {
	case "tree":
		s.handleTree(w, req)
	case "tar":
		s.handleTar(w, req)
	case "tar-apply":
		s.handleApply(w, req)
	case "put":
		s.handlePut(w, r)
	case "get":
		s.handleGet(w, req)
	case "list":
		s.handleList(w, req)
	default:
		s.t.Errorf("unexpected route %s", r.URL.Path)
		w.WriteHeader(404)
	}
}

func (s *tarServer) folder(req map[string]any) (string, bool) {
	p := filepath.Join(s.root, filepath.FromSlash(strings.Trim(strval(req["path"]), "/")))
	info, err := os.Stat(p)
	return p, err == nil && info.IsDir()
}

// entries lists a folder like `find . -mindepth 1 ( -name '.cdn-upload.*' -prune ) -o -print`.
func entriesOf(dir string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == dir {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".cdn-upload.") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(out)
	return out
}

func (s *tarServer) handleTree(w http.ResponseWriter, req map[string]any) {
	dir, ok := s.folder(req)
	if !ok {
		if _, err := os.Stat(dir); err == nil {
			writeJSON(w, 422, map[string]any{"status": false, "error_code": "not_a_directory", "message": "Not a folder."})
			return
		}
		writeJSON(w, 404, map[string]any{"status": false, "error_code": "file_not_found", "message": "Folder not found."})
		return
	}
	var body bytes.Buffer
	count := 0
	var files []string
	for _, rel := range entriesOf(dir) {
		fi, _ := os.Lstat(filepath.Join(dir, filepath.FromSlash(rel)))
		t := "f"
		switch {
		case fi.IsDir():
			t = "d"
		case fi.Mode()&fs.ModeSymlink != 0:
			t = "l"
		case !fi.Mode().IsRegular():
			t = "p"
		default:
			files = append(files, rel)
		}
		// %T@ carries a fraction; the client floors it
		fmt.Fprintf(&body, "E %s %d %d.%010d %s\x00", t, fi.Size(), fi.ModTime().Unix(), 123456789, rel)
		count++
	}
	if req["checksum"] == true {
		body.WriteString("SUMS\x00")
		for _, rel := range files {
			b, _ := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
			sum := sha256.Sum256(b)
			fmt.Fprintf(&body, "%s  %s\x00", hex.EncodeToString(sum[:]), rel)
		}
	}
	fmt.Fprintf(&body, "CDNTREE-END v=1 rc=%d count=%d\n", s.treeRC, count)
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(body.Bytes())
}

// buildTar archives like GNU tar: "./"-prefixed names for a whole folder, the
// listed names with --no-recursion otherwise; symlinks stored as symlinks;
// whole-second mtimes (the pod drops pax mtime); padded to a 10240-byte record.
func buildTar(dir string, list []string, drop map[string]bool) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(name, rel string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		fi, err := os.Lstat(p)
		if err != nil {
			return
		}
		hdr := &tar.Header{Name: name, Mode: int64(fi.Mode().Perm()), ModTime: time.Unix(fi.ModTime().Unix(), 0)}
		var data []byte
		switch {
		case fi.IsDir():
			hdr.Typeflag = tar.TypeDir
			if !strings.HasSuffix(hdr.Name, "/") {
				hdr.Name += "/"
			}
		case fi.Mode()&fs.ModeSymlink != 0:
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname, _ = os.Readlink(p)
		case fi.Mode().IsRegular():
			hdr.Typeflag = tar.TypeReg
			data, _ = os.ReadFile(p)
			hdr.Size = int64(len(data))
		default:
			hdr.Typeflag = tar.TypeFifo
		}
		_ = tw.WriteHeader(hdr)
		_, _ = tw.Write(data)
	}
	if list == nil {
		add("./", "")
		for _, rel := range entriesOf(dir) {
			if !drop[rel] {
				add("./"+rel, rel)
			}
		}
	} else {
		reachable := map[string]bool{}
		for _, rel := range entriesOf(dir) {
			reachable[rel] = true
		}
		sorted := append([]string(nil), list...)
		sort.Strings(sorted)
		for _, rel := range sorted {
			if reachable[rel] && !drop[rel] {
				add(rel, rel)
			}
		}
	}
	_ = tw.Close()
	return padRecord(buf.Bytes())
}

func padRecord(b []byte) []byte {
	if rem := len(b) % 10240; rem != 0 {
		b = append(b, make([]byte, 10240-rem)...)
	}
	return b
}

// withTrailer appends tar's stderr and the CDNTAR-END line for archive.
func withTrailer(archive []byte, rc int, stderr string) []byte {
	sum := sha256.Sum256(archive)
	out := append([]byte(nil), archive...)
	out = append(out, stderr...)
	return append(out, fmt.Sprintf("\nCDNTAR-END v=1 rc=%d bytes=%d sha256=%s\n", rc, len(archive), hex.EncodeToString(sum[:]))...)
}

func (s *tarServer) handleTar(w http.ResponseWriter, req map[string]any) {
	dir, ok := s.folder(req)
	if !ok {
		if _, err := os.Stat(dir); err == nil {
			writeJSON(w, 422, map[string]any{"status": false, "error_code": "not_a_directory", "message": "Not a folder."})
			return
		}
		writeJSON(w, 404, map[string]any{"status": false, "error_code": "file_not_found", "message": "Folder not found."})
		return
	}
	var list []string
	s.mu.Lock()
	if raw, isList := req["files"].([]any); isList {
		list = []string{}
		for _, f := range raw {
			list = append(list, strval(f))
		}
		s.tarFiles, s.tarWhole = list, false
	} else {
		s.tarFiles, s.tarWhole = nil, true
	}
	s.mu.Unlock()
	var archive []byte
	if s.rawTar != nil {
		archive = s.rawTar()
	} else {
		archive = buildTar(dir, list, s.dropFromTar)
	}
	body := withTrailer(archive, s.tarRC, s.tarStderr)
	if s.mutate != nil {
		body = s.mutate(body)
	}
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("X-Accel-Buffering", "no")
	_, _ = w.Write(body)
}

func (s *tarServer) handlePut(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("target_path")
	f, _, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, 422, map[string]any{"status": false, "message": "no file"})
		return
	}
	data, _ := io.ReadAll(f)
	p := filepath.Join(s.root, filepath.FromSlash(strings.TrimLeft(target, "/")))
	if _, err := os.Stat(p); err == nil && r.FormValue("overwrite") != "1" {
		writeJSON(w, 409, map[string]any{"status": false, "error_code": "file_exists", "message": "File already exists. Pass overwrite to replace it."})
		return
	}
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		writeJSON(w, 500, map[string]any{"status": false, "message": err.Error()})
		return
	}
	s.mu.Lock()
	s.puts = append(s.puts, target)
	if strings.HasPrefix(target, ".cdn-upload.") {
		s.parts = append(s.parts, target)
		s.partSizes = append(s.partSizes, len(data))
	}
	s.mu.Unlock()
	sum := sha256.Sum256(data)
	writeJSON(w, 200, map[string]any{"status": true, "message": "File uploaded successfully", "result": map[string]any{"path": target, "size": len(data), "sha256": hex.EncodeToString(sum[:])}})
}

var sessionPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// handleApply follows the pod script: parts complete, only files and folders,
// sums present and matching the staged set, per-file SHA-256, placement with
// or without overwrite, and --delete only after everything was placed.
func (s *tarServer) handleApply(w http.ResponseWriter, req map[string]any) {
	s.mu.Lock()
	s.applyReq = req
	s.mu.Unlock()
	session := strval(req["session"])
	parts := intValue(req["parts"])
	fail := func(status int, code string) {
		writeJSON(w, status, map[string]any{"status": false, "error_code": code, "message": code})
	}
	if !sessionPattern.MatchString(session) || parts < 1 || parts > 100000 {
		fail(422, "invalid_request")
		return
	}
	sess := filepath.Join(s.root, ".cdn-upload."+session)
	defer os.RemoveAll(sess)
	var all bytes.Buffer
	for i := 1; i <= parts; i++ {
		b, err := os.ReadFile(filepath.Join(sess, fmt.Sprintf("part-%05d", i)))
		if err != nil {
			fail(422, "upload_incomplete")
			return
		}
		all.Write(b)
	}
	if found, _ := os.ReadDir(sess); len(found) != parts {
		fail(422, "upload_incomplete")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	for i := 0; i < s.applyHeartbeats; i++ {
		_, _ = w.Write([]byte(" "))
		w.(http.Flusher).Flush()
	}
	answer := func(ok bool, code string, result map[string]any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": ok, "error_code": code, "message": code, "result": result})
	}

	staged := map[string]stagedMember{}
	var names []string
	tr := tar.NewReader(&all)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			answer(false, "tar_failed", nil)
			return
		}
		name := strings.TrimRight(withoutDotSlash(hdr.Name), "/")
		names = append(names, name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			staged[name] = stagedMember{dir: true}
		case tar.TypeReg:
			data, _ := io.ReadAll(tr)
			if hdr.Mode != 0o644 && hdr.Mode != 0o755 {
				s.t.Errorf("member %s has mode %o", name, hdr.Mode)
			}
			if hdr.ModTime.Nanosecond() != 0 {
				s.t.Errorf("member %s has a sub-second mtime", name)
			}
			staged[name] = stagedMember{data: data, mtime: hdr.ModTime}
		default:
			answer(false, "bad_entry_type", nil)
			return
		}
	}
	s.mu.Lock()
	s.applyMembers = names
	s.mu.Unlock()
	sums, ok := staged[".cdnctl-sums"]
	if !ok {
		answer(false, "upload_incomplete", nil)
		return
	}
	want := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(sums.data), "\n"), "\n") {
		if line == "" {
			continue
		}
		// like the real server: the client writes "./name" (a file named "-")
		want[strings.TrimPrefix(line[66:], "./")] = line[:64]
	}
	for name, m := range staged {
		if name == ".cdnctl-sums" || m.dir {
			continue
		}
		if _, listed := want[name]; !listed {
			answer(false, "manifest_mismatch", nil)
			return
		}
	}
	if len(want) != countFilesStaged(staged) {
		answer(false, "manifest_mismatch", nil)
		return
	}
	var badSum, notPlaced, conflicts []string
	dest := filepath.Join(s.root, filepath.FromSlash(strings.Trim(strval(req["path"]), "/")))
	_ = os.MkdirAll(dest, 0o755)
	var dirs []string
	for name, m := range staged {
		if m.dir {
			dirs = append(dirs, name)
		}
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		p := filepath.Join(dest, filepath.FromSlash(d))
		if fi, err := os.Lstat(p); err == nil && (!fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0) {
			conflicts = append(conflicts, d)
			continue
		}
		_ = os.MkdirAll(p, 0o755)
	}
	placed := 0
	uploaded := map[string]bool{}
	for name, m := range staged {
		if m.dir || name == ".cdnctl-sums" || name == ".cdnctl-delete" {
			continue
		}
		uploaded[name] = true
		if name == s.corruptStaged {
			m.data = append([]byte("corrupted "), m.data...)
		}
		sum := sha256.Sum256(m.data)
		if hex.EncodeToString(sum[:]) != want[name] {
			badSum = append(badSum, name)
			continue
		}
		p := filepath.Join(dest, filepath.FromSlash(name))
		if _, err := os.Lstat(p); err == nil && req["overwrite"] != true {
			conflicts = append(conflicts, name) // like the script: kept files that exist are conflicts
			continue
		}
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.Remove(p)
		if err := os.WriteFile(p, m.data, 0o644); err != nil {
			notPlaced = append(notPlaced, name)
			continue
		}
		_ = os.Chtimes(p, m.mtime, m.mtime) // GNU tar keeps the archived mtime
		placed++
	}
	deleted := 0
	if del, ok := staged[".cdnctl-delete"]; ok && req["delete"] == true && len(badSum)+len(notPlaced)+len(conflicts) == 0 {
		var delDirs []string
		for _, name := range strings.Split(strings.TrimRight(string(del.data), "\x00"), "\x00") {
			if name == "" || uploaded[name] || strings.HasPrefix(filepath.Base(name), ".cdn-upload.") {
				continue
			}
			p := filepath.Join(dest, filepath.FromSlash(name))
			fi, err := os.Lstat(p)
			if err != nil {
				continue
			}
			if fi.IsDir() {
				delDirs = append(delDirs, name)
				continue
			}
			if os.Remove(p) == nil {
				deleted++
			}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(delDirs)))
		for _, d := range delDirs {
			_ = os.Remove(filepath.Join(dest, filepath.FromSlash(d)))
		}
	}
	sort.Strings(badSum)
	sort.Strings(notPlaced)
	result := map[string]any{"placed": placed, "deleted": deleted, "bad_sum": nonNil(badSum), "not_placed": nonNil(notPlaced), "conflicts": nonNil(conflicts), "truncated_lists": false}
	ok = len(badSum)+len(notPlaced)+len(conflicts) == 0
	code := ""
	if !ok {
		code = "partially_applied"
	}
	answer(ok, code, result)
}

type stagedMember struct {
	dir   bool
	data  []byte
	mtime time.Time
}

// countFilesStaged counts staged files other than the sums member itself.
func countFilesStaged(staged map[string]stagedMember) int {
	n := 0
	for name, m := range staged {
		if !m.dir && name != ".cdnctl-sums" {
			n++
		}
	}
	return n
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *tarServer) handleGet(w http.ResponseWriter, req map[string]any) {
	p := filepath.Join(s.root, filepath.FromSlash(strings.Trim(strval(req["path"]), "/")))
	fi, err := os.Stat(p)
	if err != nil {
		writeJSON(w, 404, map[string]any{"status": false, "error_code": "file_not_found", "message": "File not found."})
		return
	}
	if fi.IsDir() {
		writeJSON(w, 422, map[string]any{"status": false, "error_code": "is_directory", "message": "That path is a directory."})
		return
	}
	data, _ := os.ReadFile(p)
	sum := sha256.Sum256(data)
	writeJSON(w, 200, map[string]any{"status": true, "result": map[string]any{
		"size": len(data), "sha256": hex.EncodeToString(sum[:]), "encoding": "base64", "content": base64.StdEncoding.EncodeToString(data),
	}})
}

func (s *tarServer) handleList(w http.ResponseWriter, req map[string]any) {
	p := filepath.Join(s.root, filepath.FromSlash(strings.Trim(strval(req["path"]), "/")))
	entries, err := os.ReadDir(p)
	if err != nil {
		writeJSON(w, 404, map[string]any{"status": false, "message": "not found"})
		return
	}
	var items []map[string]any
	for _, e := range entries {
		kind := "file"
		if e.IsDir() {
			kind = "folder"
		}
		items = append(items, map[string]any{"name": e.Name(), "type": kind, "link": e.Type()&fs.ModeSymlink != 0})
	}
	writeJSON(w, 200, map[string]any{"status": true, "result": items})
}
