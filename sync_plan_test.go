package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseTreeReadsOddNamesSumsAndTheTrailer(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	body := "E d 4096 1727262000.9999999999 dir with space\x00" +
		"E f 5 1727262001.5000000000 dir with space/new\nline.txt\x00" +
		"E f 0 -5.5 -leading-dash\x00" +
		"E l 7 1727262002.0000000000 link\x00" +
		"E p 0 1727262003.0000000000 fifo\x00" +
		"E f 3 1727262004.0000000000 SUMS\x00" +
		"SUMS\x00" +
		sum + "  dir with space/new\nline.txt\x00" +
		"CDNTREE-END v=1 rc=1 count=6\n"
	got, err := parseTree(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if got.RC != 1 {
		t.Errorf("rc = %d", got.RC)
	}
	want := map[string]fsEntry{
		"dir with space":               {Type: 'd', Size: 4096, Mtime: 1727262000},
		"dir with space/new\nline.txt": {Type: 'f', Size: 5, Mtime: 1727262001},
		"-leading-dash":                {Type: 'f', Size: 0, Mtime: -6},
		"link":                         {Type: 'l', Size: 7, Mtime: 1727262002},
		"fifo":                         {Type: 'p', Mtime: 1727262003},
		"SUMS":                         {Type: 'f', Size: 3, Mtime: 1727262004},
	}
	if len(got.Entries) != len(want) {
		t.Fatalf("entries: %v", got.Entries)
	}
	for k, v := range want {
		if got.Entries[k] != v {
			t.Errorf("%q = %+v, want %+v", k, got.Entries[k], v)
		}
	}
	if got.Sums["dir with space/new\nline.txt"] != sum {
		t.Errorf("sums: %v", got.Sums)
	}
}

func TestParseTreeRefusesAnIncompleteListing(t *testing.T) {
	for name, body := range map[string]string{
		"no trailer":      "E f 1 1.0 a\x00",
		"count mismatch":  "E f 1 1.0 a\x00CDNTREE-END v=1 rc=0 count=2\n",
		"cut mid-record":  "E f 1 1.0 a\x00E f 2 2.0 b",
		"garbled record":  "X f 1 1.0 a\x00CDNTREE-END v=1 rc=0 count=1\n",
		"bad sums record": "E f 1 1.0 a\x00SUMS\x00zz  a\x00CDNTREE-END v=1 rc=0 count=1\n",
	} {
		if _, err := parseTree(strings.NewReader(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func excludes(t *testing.T, patterns ...string) []excludeRule {
	t.Helper()
	var out []excludeRule
	for _, p := range patterns {
		r, err := compileExclude(p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func TestExcludeFollowsTheRsyncSubset(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		dir     bool
		want    bool
	}{
		{"*.log", "debug.log", false, true},
		{"*.log", "a/b/debug.log", false, true}, // no "/" → a name at any depth
		{"cache", "wp-content/cache", true, true},
		{"cache", "wp-content/cache/x.html", false, true}, // an excluded folder excludes its contents
		{"/cache", "cache/x", false, true},                // anchored at the root
		{"/cache", "wp-content/cache", true, false},       // … and only there
		{"cache/", "cache", true, true},                   // trailing "/" → folders only
		{"cache/", "cache", false, false},
		{"cache/", "a/cache/b.txt", false, true},
		{"uploads/*.jpg", "uploads/a.jpg", false, true},
		{"uploads/*.jpg", "x/uploads/a.jpg", false, true}, // unanchored with "/" may sit deeper
		{"uploads/*.jpg", "uploads/2024/a.jpg", false, false},
		{"uploads/**.jpg", "uploads/2024/05/a.jpg", false, true}, // "**" crosses "/"
		{"/uploads/**", "uploads/2024/a.jpg", false, true},
		{"?.txt", "a.txt", false, true},
		{"?.txt", "ab.txt", false, false},
		{"[ab].txt", "b.txt", false, true},
		{"[!ab].txt", "b.txt", false, false},
		{"*.log", "a.logx", false, false},
	}
	for _, c := range cases {
		if got := isExcluded(excludes(t, c.pattern), c.path, c.dir); got != c.want {
			t.Errorf("--exclude %q on %q (dir %v) = %v, want %v", c.pattern, c.path, c.dir, got, c.want)
		}
	}
	if _, err := compileExclude("/"); err == nil {
		t.Error("an empty pattern was accepted")
	}
}

func planFor(src, dst map[string]fsEntry, opts syncOptions) syncPlan {
	return planSync(src, dst, opts, func(side int, rel string) (string, error) {
		return "", errors.New("no sums")
	})
}

func opsOf(p syncPlan) []string {
	var out []string
	for _, op := range p.Ops {
		out = append(out, op.String())
	}
	return out
}

func TestPlanNewUpdateDeleteAndSkip(t *testing.T) {
	src := map[string]fsEntry{
		"new.txt":      {Type: 'f', Size: 3, Mtime: 100},
		"same.txt":     {Type: 'f', Size: 3, Mtime: 100},
		"bigger.txt":   {Type: 'f', Size: 9, Mtime: 100},
		"touched.txt":  {Type: 'f', Size: 3, Mtime: 200},
		"dir":          {Type: 'd'},
		"dir/in.txt":   {Type: 'f', Size: 1, Mtime: 1},
		"newdir":       {Type: 'd'},
		"link":         {Type: 'l'},
		"fifo":         {Type: 'p'},
		"bad\\name":    {Type: 'f', Size: 1},
		".cdnctl-junk": {Type: 'f', Size: 1},
	}
	dst := map[string]fsEntry{
		"same.txt":          {Type: 'f', Size: 3, Mtime: 100},
		"bigger.txt":        {Type: 'f', Size: 3, Mtime: 100},
		"touched.txt":       {Type: 'f', Size: 3, Mtime: 100},
		"dir":               {Type: 'd'},
		"dir/in.txt":        {Type: 'f', Size: 1, Mtime: 1},
		"gone.txt":          {Type: 'f', Size: 1},
		"gonedir":           {Type: 'd'},
		"gonedir/x":         {Type: 'f'},
		"dstlink":           {Type: 'l'},
		".cdn-upload.abc":   {Type: 'd'},
		".cdnctl-temp":      {Type: 'f'},
		"link/under":        {Type: 'f'}, // under a SRC symlink: left alone
		"excluded.log":      {Type: 'f'},
		"keep/excluded.log": {Type: 'f'},
	}
	opts := syncOptions{Delete: true, MaxDelete: -1, Excludes: excludes(t, "*.log")}
	plan := planFor(src, dst, opts)
	got := strings.Join(opsOf(plan), "\n")
	want := strings.Join([]string{
		"! .cdnctl-junk (name)",
		"! bad\\name (name)",
		"~ bigger.txt (size)",
		"! dstlink (symlink)",
		"! fifo (special)",
		"- gone.txt",
		"- gonedir/",
		"- gonedir/x",
		"! link (symlink)",
		"+ new.txt",
		"+ newdir/",
		"~ touched.txt (mtime)",
	}, "\n")
	if got != want {
		t.Fatalf("plan:\n%s\nwant:\n%s", got, want)
	}
	if strings.Join(plan.Transfer, ",") != "bigger.txt,new.txt,newdir,touched.txt" {
		t.Errorf("transfer = %v", plan.Transfer)
	}
	if plan.Bytes != 9+3+3 {
		t.Errorf("bytes = %d", plan.Bytes)
	}
	if len(plan.Failed) != 0 {
		t.Errorf("failed = %v", plan.Failed)
	}
	if plan.SourceCount != 7 {
		t.Errorf("source count = %d", plan.SourceCount)
	}
}

func TestPlanWithoutDeleteNeverDeletes(t *testing.T) {
	plan := planFor(map[string]fsEntry{"a": {Type: 'f'}}, map[string]fsEntry{"b": {Type: 'f'}}, syncOptions{MaxDelete: -1})
	if len(plan.Deletes) != 0 {
		t.Fatalf("deletes without --delete: %v", plan.Deletes)
	}
}

func TestModifyWindow(t *testing.T) {
	src := map[string]fsEntry{"a": {Type: 'f', Size: 1, Mtime: 102}}
	dst := map[string]fsEntry{"a": {Type: 'f', Size: 1, Mtime: 100}}
	if p := planFor(src, dst, syncOptions{MaxDelete: -1}); len(p.Transfer) != 1 {
		t.Error("a 2 s difference was ignored without --modify-window")
	}
	if p := planFor(src, dst, syncOptions{MaxDelete: -1, ModifyWindow: 2}); len(p.Transfer) != 0 {
		t.Error("--modify-window 2 did not absorb a 2 s difference")
	}
}

func TestChecksumModeComparesContentNotMtime(t *testing.T) {
	src := map[string]fsEntry{
		"same-content-new-mtime": {Type: 'f', Size: 4, Mtime: 999},
		"same-size-new-content":  {Type: 'f', Size: 4, Mtime: 100},
		"different-size":         {Type: 'f', Size: 5, Mtime: 100},
	}
	dst := map[string]fsEntry{
		"same-content-new-mtime": {Type: 'f', Size: 4, Mtime: 100},
		"same-size-new-content":  {Type: 'f', Size: 4, Mtime: 100},
		"different-size":         {Type: 'f', Size: 4, Mtime: 100},
	}
	sums := map[int]map[string]string{
		0: {"same-content-new-mtime": "aa", "same-size-new-content": "bb"},
		1: {"same-content-new-mtime": "aa", "same-size-new-content": "cc"},
	}
	var asked []string
	plan := planSync(src, dst, syncOptions{MaxDelete: -1, Checksum: true}, func(side int, rel string) (string, error) {
		asked = append(asked, rel)
		return sums[side][rel], nil
	})
	if got := strings.Join(opsOf(plan), "\n"); got != "~ different-size (size)\n~ same-size-new-content (checksum)" {
		t.Fatalf("plan:\n%s", got)
	}
	for _, rel := range asked {
		if rel == "different-size" {
			t.Error("a checksum was computed for files whose sizes already differ")
		}
	}
	failPlan := planSync(src, dst, syncOptions{MaxDelete: -1, Checksum: true}, func(int, string) (string, error) { return "", errors.New("x") })
	if len(failPlan.Failed) != 2 {
		t.Errorf("an unavailable checksum must be a failure: %v", failPlan.Failed)
	}
}

func TestTypeConflictIsAFailure(t *testing.T) {
	plan := planFor(map[string]fsEntry{"x": {Type: 'f', Size: 1}}, map[string]fsEntry{"x": {Type: 'd'}, "x/in": {Type: 'f'}}, syncOptions{Delete: true, MaxDelete: -1})
	if len(plan.Failed) != 1 || len(plan.Deletes) != 0 {
		t.Fatalf("failed %v deletes %v", plan.Failed, plan.Deletes)
	}
}

func TestDeletionSafety(t *testing.T) {
	opts := syncOptions{Delete: true, MaxDelete: -1}
	empty := planFor(map[string]fsEntry{"only-a-link": {Type: 'l'}}, map[string]fsEntry{"a": {Type: 'f'}}, opts)
	if deletionRefusal(empty, opts) == "" {
		t.Error("--delete with an empty source was not refused")
	}
	src := map[string]fsEntry{"keep": {Type: 'f'}}
	dst := map[string]fsEntry{"keep": {Type: 'f'}, "a": {Type: 'f'}, "b": {Type: 'f'}, "c": {Type: 'f'}}
	limited := syncOptions{Delete: true, MaxDelete: 2}
	if msg := deletionRefusal(planFor(src, dst, limited), limited); !strings.Contains(msg, "--max-delete 2") {
		t.Errorf("--max-delete not enforced: %q", msg)
	}
	enough := syncOptions{Delete: true, MaxDelete: 3}
	if msg := deletionRefusal(planFor(src, dst, enough), enough); msg != "" {
		t.Errorf("refused within the limit: %q", msg)
	}
	if deletionRefusal(empty, syncOptions{MaxDelete: -1}) != "" {
		t.Error("an empty source without --delete is not a problem")
	}
	if deletionSkipReason(true, 0) == "" || deletionSkipReason(false, 1) == "" || deletionSkipReason(false, 0) != "" {
		t.Error("deletion must be skipped on any listing error or failure, and only then")
	}
}

func TestPlanWithWindowsRulesSkipsUnwritableNames(t *testing.T) {
	plan := planFor(map[string]fsEntry{"CON.txt": {Type: 'f'}, "a:b": {Type: 'f'}, "ok.txt": {Type: 'f'}}, nil, syncOptions{MaxDelete: -1, Windows: true})
	if strings.Join(plan.Transfer, ",") != "ok.txt" || len(plan.Skipped) != 2 {
		t.Fatalf("transfer %v skipped %v", plan.Transfer, plan.Skipped)
	}
}

func TestCheckRelName(t *testing.T) {
	bad := []string{"", "/abs", "a/../b", "..", ".", "a//b", "a/./b", `a\b`, "a\nb", "a\rb", "tab\there", "del\x7f", "c1\u0085", "bad\xff", ".cdnctl-x", "a/.cdn-upload.1/x", "trailing/"}
	for _, name := range bad {
		if checkRelName(name, false) == nil {
			t.Errorf("%q accepted", name)
		}
	}
	good := []string{"a", "a/b.txt", "with space/ünïcödé.php", "..hidden", "a..b", ".htaccess", "CON.txt", "a:b"}
	for _, name := range good {
		if err := checkRelName(name, false); err != nil {
			t.Errorf("%q refused: %v", name, err)
		}
	}
}

// The Windows rules live in a plain function so they run on every OS.
func TestWindowsNameRules(t *testing.T) {
	bad := []string{"CON", "con.txt", "Prn.tar.gz", "AUX", "nul", "COM1", "com9.log", "LPT1", "lpt9.x", "a<b", "a>b", "a:b", `a"b`, "a|b", "a?b", "a*b", "dot.", "space "}
	for _, seg := range bad {
		if checkWindowsSegment(seg) == nil {
			t.Errorf("%q accepted on Windows", seg)
		}
	}
	good := []string{"CONSOLE.txt", "COM0", "COM10", "LPT", "auxiliary", "a.b", "file.txt", ".htaccess"}
	for _, seg := range good {
		if err := checkWindowsSegment(seg); err != nil {
			t.Errorf("%q refused on Windows: %v", seg, err)
		}
	}
	if checkRelName("dir/CON.txt", true) == nil {
		t.Error("checkRelName with windows rules accepted CON.txt")
	}
}

func TestEnsureLocalDirsRefusesASymlinkedParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := ensureLocalDirs(root, "link/sub", nil); err == nil {
		t.Fatal("a symlinked parent was followed")
	}
	if _, err := os.Stat(filepath.Join(outside, "sub")); !os.IsNotExist(err) {
		t.Fatal("a folder was created through the symlink")
	}
	if err := noSymlinkParents(root, "link/file"); err == nil {
		t.Fatal("noSymlinkParents accepted a symlinked parent")
	}
	var created []string
	if err := ensureLocalDirs(root, "a/b/c", &created); err != nil || len(created) != 3 {
		t.Fatalf("normal folders: %v %v", err, created)
	}
}

func TestParseTreeSkipsKeepAliveRecords(t *testing.T) {
	sum := strings.Repeat("cd", 32)
	body := "E f 1 1727262000.0 a.txt\x00SUMS\x00K" + strings.Repeat(" ", 8190) + "\x00" +
		"K" + strings.Repeat(" ", 8190) + "\x00" + sum + "  a.txt\x00CDNTREE-END v=1 rc=0 count=1\n"
	got, err := parseTree(strings.NewReader(body))
	if err != nil || got.Sums["a.txt"] != sum || len(got.Entries) != 1 {
		t.Fatalf("%v %+v", err, got)
	}
	// a real entry named K is not a keep-alive
	got, err = parseTree(strings.NewReader("E f 1 1.0 K\x00CDNTREE-END v=1 rc=0 count=1\n"))
	if err != nil || got.Entries["K"].Type != 'f' {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestCaseTwinsAreNotDeleted(t *testing.T) {
	src := map[string]fsEntry{"README.md": {Type: 'f', Size: 2, Mtime: 1}, "Images": {Type: 'd'}, "Images/x.png": {Type: 'f', Size: 1, Mtime: 1}}
	dst := map[string]fsEntry{"readme.md": {Type: 'f', Size: 1, Mtime: 1}, "images": {Type: 'd'}, "images/x.png": {Type: 'f', Size: 1, Mtime: 1}, "images/old.png": {Type: 'f', Size: 1, Mtime: 1}}
	plan := planFor(src, dst, syncOptions{Delete: true, MaxDelete: -1})
	protectCaseTwins(&plan, src)
	if strings.Join(plan.Deletes, ",") != "images/old.png" {
		t.Errorf("deletes = %v", plan.Deletes)
	}
	var lines []string
	for _, op := range plan.Ops {
		lines = append(lines, op.String())
	}
	if !strings.Contains(strings.Join(lines, "\n"), "! readme.md (differs from a source entry only in letter case; not deleted)") {
		t.Errorf("plan:\n%s", strings.Join(lines, "\n"))
	}
}
