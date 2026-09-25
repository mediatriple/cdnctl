package main

// The remote listing `cdnctl sync` compares against: one call for a whole
// folder, recursive, with type, size and mtime of every entry and — with
// --checksum — the SHA-256 of every regular file.
//
// Records are NUL-terminated because a site's file names may contain spaces
// and newlines. The last bytes are always
//
//	CDNTREE-END v=1 rc=<find exit code> count=<number of E records>\n
//
// so a listing cut short is recognised instead of being read as "these files
// are gone" — which, with --delete, would delete them on the other side.

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// fsEntry is one entry of a listing, local or remote. Type is the find %y
// letter: f (file), d (directory), l (symlink); anything else is special.
type fsEntry struct {
	Type  byte
	Size  int64
	Mtime int64
}

type treeListing struct {
	Entries map[string]fsEntry
	Sums    map[string]string // with checksum=true: path → sha256 hex
	RC      int               // find's exit code; non-zero = some entries were unreadable
	Missing bool              // the folder does not exist (sync reads it as empty)
}

var treeTrailerLine = regexp.MustCompile(`^CDNTREE-END v=1 rc=(\d+) count=(\d+)\n$`)

// maxTreeRecord bounds one record; PATH_MAX is 4096, so anything longer is a
// broken stream, not a file name.
const maxTreeRecord = 64 << 10

// parseTree reads a tree body up to and including its trailer.
func parseTree(r io.Reader) (treeListing, error) {
	out := treeListing{Entries: map[string]fsEntry{}, Sums: map[string]string{}}
	br := bufio.NewReaderSize(r, 64<<10)
	inSums := false
	count := 0
	for {
		rec, err := readTreeRecord(br)
		if err == io.EOF {
			m := treeTrailerLine.FindStringSubmatch(rec)
			if m == nil {
				return out, fmt.Errorf("the listing was incomplete (end marker missing); run the command again")
			}
			out.RC, _ = strconv.Atoi(m[1])
			want, _ := strconv.Atoi(m[2])
			if want != count {
				return out, fmt.Errorf("the listing was incomplete (%d of %d entries); run the command again", count, want)
			}
			return out, nil
		}
		if err != nil {
			return out, fmt.Errorf("the listing was incomplete (%v); run the command again", err)
		}
		if rec == "SUMS" && !inSums {
			inSums = true
			continue
		}
		if isKeepAlive(rec) {
			// sent every 15 s while the server hashes big files; not an entry
			continue
		}
		if inSums {
			if len(rec) < 67 || rec[64:66] != "  " || !isLowerHex(rec[:64]) {
				return out, fmt.Errorf("the listing has a malformed checksum record")
			}
			out.Sums[rec[66:]] = rec[:64]
			continue
		}
		parts := strings.SplitN(rec, " ", 5)
		if len(parts) != 5 || parts[0] != "E" || len(parts[1]) != 1 || parts[4] == "" {
			return out, fmt.Errorf("the listing has a malformed record")
		}
		size, sizeErr := strconv.ParseInt(parts[2], 10, 64)
		mtime, mtimeErr := floorSeconds(parts[3])
		if sizeErr != nil || mtimeErr != nil {
			return out, fmt.Errorf("the listing has a malformed record")
		}
		out.Entries[parts[4]] = fsEntry{Type: parts[1][0], Size: size, Mtime: mtime}
		count++
	}
}

// readTreeRecord returns one NUL-terminated record without its NUL, or, at the
// end of the stream, the unterminated remainder (the trailer) with io.EOF.
func readTreeRecord(br *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		chunk, err := br.ReadSlice(0)
		sb.Write(chunk)
		if sb.Len() > maxTreeRecord {
			return "", fmt.Errorf("record too long")
		}
		switch err {
		case nil:
			s := sb.String()
			return s[:len(s)-1], nil
		case bufio.ErrBufferFull:
			continue
		default:
			return sb.String(), err
		}
	}
}

// floorSeconds reads find's %T@ ("1727262000.1234567890") as whole seconds,
// rounding down like the local side does.
func floorSeconds(s string) (int64, error) {
	whole, frac, hasFrac := strings.Cut(s, ".")
	n, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return 0, err
	}
	if hasFrac && strings.HasPrefix(whole, "-") && strings.Trim(frac, "0") != "" {
		n--
	}
	return n, nil
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// fetchTree lists a remote folder. A missing folder is an empty listing with
// Missing set; any other refusal comes back as the server's answer.
func fetchTree(account, folder string, checksum bool) (treeListing, map[string]any, error) {
	body, answer, err := requestStream(fmt.Sprintf("accounts/%s/files/tree", account), map[string]any{
		"path":     folder,
		"checksum": checksum,
	})
	if err != nil {
		return treeListing{}, nil, err
	}
	if answer != nil {
		if responseOK(answer) {
			return treeListing{}, unexpectedAnswer("a listing"), nil
		}
		if strval(answer["error_code"]) == "file_not_found" {
			return treeListing{Entries: map[string]fsEntry{}, Sums: map[string]string{}, Missing: true}, nil, nil
		}
		return treeListing{}, answer, nil
	}
	defer body.Close()
	listing, err := parseTree(body)
	return listing, nil, err
}

// isKeepAlive recognises the padded "K    …" record the server sends while it
// hashes (the edge drops a response that stays silent for 60 s).
func isKeepAlive(rec string) bool {
	return len(rec) > 0 && rec[0] == 'K' && strings.Trim(rec[1:], " ") == ""
}
