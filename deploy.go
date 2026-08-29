package main

// cdnctl deploy — kaynak koddan canlıya, git'siz ve registry'siz.
//
// Akış (kb: cdnctl-init-vibe-deploy): proje dizini tar.gz'lenir → panele yüklenir →
// panel imzalı bir URL üretip aynı Kaniko/gVisor build hattını başlatır (git yolundaki
// hattın ta kendisi; tek fark init container'ın clone yerine indirmesi) → build izlenir
// → uygulama yeni imaj tag'ine çevrilir. Uygulama yoksa oluşturulur ve expose edilir.
//
// Komut agent-dostudur: --json ile her aşama makine-okur satırlar basar, hata
// mesajları bir sonraki adımı söyler, exit code'lar anlamlıdır.

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// deployExcludes: hiçbir koşulda arşive girmeyecekler. node_modules canlı bir çökme
// dersinden geliyor (lokalde derlenen native modül cluster'da ERR_DLOPEN_FAILED) —
// bağımlılıklar imaj içindeki npm install ile kurulur.
var deployExcludes = map[string]bool{
	".git": true, "node_modules": true, ".venv": true, "venv": true,
	"__pycache__": true, "dist": true, ".next": true, "vendor": true,
}

// confirmOverwrite guards a deploy that matched an existing app only by name.
// It shows what would be replaced — including whether it is currently serving
// traffic — and requires a typed yes. With no terminal to ask (an agent, CI),
// it refuses rather than assuming: --yes is how intent is stated there.
func confirmOverwrite(account, appUUID, name string) error {
	detail, _ := requestJSON(http.MethodGet,
		fmt.Sprintf("accounts/%s/platform/container/apps/%s", account, appUUID), nil)

	domain := findString(detail, "domain")
	image := findString(detail, "image")

	fmt.Fprintf(os.Stderr, T("\nThis account already has an app named \"%s\":\n"), name)
	fmt.Fprintf(os.Stderr, "  id     : %s\n", appUUID)
	if domain != "" {
		fmt.Fprintf(os.Stderr, "  adres  : https://%s\n", domain)
	}
	if image != "" {
		fmt.Fprintf(os.Stderr, "  imaj   : %s\n", image)
	}
	fmt.Fprintln(os.Stderr, T("Continuing REPLACES that app with your new image."))

	stat, err := os.Stdin.Stat()
	interactive := err == nil && (stat.Mode()&os.ModeCharDevice) != 0
	if !interactive {
		fmt.Fprintln(os.Stderr, T("Cannot ask for confirmation (no terminal). To overwrite deliberately: --yes"))
		fmt.Fprintln(os.Stderr, T("If you want a separate app: --name <other-name>"))
		return errExit(1)
	}

	fmt.Fprint(os.Stderr, T("Overwrite it? (yes/no): "))
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	if !isAffirmative(answer) {
		fmt.Fprintln(os.Stderr, T("Cancelled. For a separate app: --name <other-name>"))
		return errExit(1)
	}
	return nil
}

func makeSourceArchive(dir, dockerfile string) (string, int64, error) {
	// .dockerignore'daki düz dizin/dosya adlarını da dışla — build bağlamıyla aynı kalsın.
	extra := map[string]bool{}
	if raw, err := os.ReadFile(filepath.Join(dir, ".dockerignore")); err == nil {
		for _, l := range strings.Split(string(raw), "\n") {
			l = strings.TrimSuffix(strings.TrimSpace(l), "/")
			if l != "" && !strings.HasPrefix(l, "#") && !strings.ContainsAny(l, "*!") {
				extra[l] = true
			}
		}
	}
	// The Dockerfile is the build instruction, not build content: listing it in
	// .dockerignore (which is idiomatic — it keeps the file out of the image)
	// must never keep it out of the tarball, or the builder has nothing to
	// build and fails with "error resolving dockerfile path".
	if dockerfile == "" {
		dockerfile = "Dockerfile"
	}
	delete(extra, dockerfile)

	out, err := os.CreateTemp("", "cdnctl-source-*.tar.gz")
	if err != nil {
		return "", 0, err
	}
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)

	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		top := strings.Split(filepath.ToSlash(rel), "/")[0]
		if deployExcludes[top] || extra[top] || extra[filepath.ToSlash(rel)] {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		// Sembolik linkler arşive girmez: build bağlamında hedefleri belirsizdir ve
		// tar-slip sınıfı sürprizlerin kapısını açar.
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(rel)
		if d.IsDir() {
			header.Name += "/"
		}
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		out.Close()
		os.Remove(out.Name())
		return "", 0, err
	}
	if err := tw.Close(); err != nil {
		return "", 0, err
	}
	if err := gz.Close(); err != nil {
		return "", 0, err
	}
	stat, _ := out.Stat()
	size := stat.Size()
	out.Close()
	return out.Name(), size, nil
}

func cmdDeploy(args parsedArgs) error {
	dir := option(args, "dir", ".")
	account := requiredAccount(args)
	project := detectProject(dir)
	// Precedence: an explicit flag, then cdnctl.yaml, then detection. The
	// manifest calls itself the file "cdnctl deploy reads" and deploy did not
	// read it — so editing `name:` did nothing and the folder name silently won,
	// which is also how a rename of the folder would have created a second app.
	name := option(args, "name", "")
	if name == "" {
		name = readManifestValue(dir, "name")
	}
	if name == "" {
		name = project.Name
	}
	if port := readManifestValue(dir, "port"); port != "" && project.Port == 0 {
		fmt.Sscanf(port, "%d", &project.Port)
	}
	dockerfile := option(args, "dockerfile", "Dockerfile")

	if _, err := os.Stat(filepath.Join(dir, dockerfile)); err != nil {
		return fmt.Errorf(T("%s not found. Run `cdnctl init`: it writes a template for the project types it knows (node, python, go, php, static). For a stack it does not recognise you need to write the Dockerfile yourself"), dockerfile)
	}

	// Karne kapısı: hatalı deploy zaten çalışmayan bir site üretir; agent'lar
	// --skip-checks ile bilinçli geçebilir.
	if !args.Bools["skip-checks"] {
		findings := runChecks(dir)
		if hasErrors(findings) {
			fmt.Fprintln(os.Stderr, T("Deploy stopped: `cdnctl check` found ERRORS (run it for detail)."))
			fmt.Fprintln(os.Stderr, T("To skip deliberately: --skip-checks"))
			return errExit(1)
		}
	}

	// Resolve the target app before anything expensive happens. Asking after the
	// build wastes a minute of the user's time on a deploy they may cancel.
	appUUID := option(args, "app", "")
	matchedByName := false
	if appUUID == "" {
		appUUID = readManifestValue(dir, "app")
	}
	if appUUID == "" {
		appUUID = findAppByName(account, name)
		matchedByName = appUUID != ""
	}
	if matchedByName && !args.Bools["yes"] {
		if err := confirmOverwrite(account, appUUID, name); err != nil {
			return err
		}
	}

	fmt.Printf(T("→ archiving source (%s)\n"), name)
	archive, size, err := makeSourceArchive(dir, dockerfile)
	if err != nil {
		return err
	}
	defer os.Remove(archive)
	fmt.Printf(T("→ uploading (%.1f MB)\n"), float64(size)/1024/1024)

	up, err := requestMultipart(http.MethodPost,
		fmt.Sprintf("accounts/%s/platform/container/source/upload", account),
		nil, "source", archive)
	if err != nil {
		return err
	}
	sourceID, _ := up["source_id"].(string)
	if sourceID == "" {
		printJSONValue(up)
		return fmt.Errorf(T("upload failed"))
	}

	fmt.Println(T("→ starting build (Kaniko, isolated sandbox)"))
	start, err := requestJSON(http.MethodPost,
		fmt.Sprintf("accounts/%s/platform/container/source/build", account),
		map[string]any{"source_id": sourceID, "name": name, "dockerfile": dockerfile})
	if err != nil {
		return err
	}
	buildID, _ := start["build_id"].(string)
	image, _ := start["image"].(string)
	tag, _ := start["tag"].(string)
	if buildID == "" || image == "" {
		printJSONValue(start)
		return fmt.Errorf(T("could not start the build"))
	}

	deadline := time.Now().Add(20 * time.Minute)
	phase := ""
	for time.Now().Before(deadline) {
		st, err := requestJSON(http.MethodPost,
			fmt.Sprintf("accounts/%s/platform/container/source/build/status", account),
			map[string]any{"build_id": buildID})
		if err != nil {
			return err
		}
		phase, _ = st["phase"].(string)
		fmt.Printf("   build: %s\n", phase)
		if phase == "success" || phase == "failed" {
			break
		}
		time.Sleep(10 * time.Second)
	}
	if phase != "success" {
		fmt.Fprintln(os.Stderr, T("Build failed or timed out. Logs:"))
		logs, _ := requestJSON(http.MethodPost,
			fmt.Sprintf("accounts/%s/platform/container/source/build/logs", account),
			map[string]any{"build_id": buildID})
		printJSONValue(logs)
		return errExit(1)
	}

	// Uygulama var mı? Varsa yeni tag'e çevir, yoksa oluştur + expose et.
	fallbackDomain := ""
	if appUUID != "" {
		fmt.Printf(T("→ pointing the existing app at the new image (%s:%s)\n"), image, tag)
		if _, err := requestJSON(http.MethodPatch,
			fmt.Sprintf("accounts/%s/platform/container/apps/%s", account, appUUID),
			map[string]any{"image": image, "tag": tag}); err != nil {
			return err
		}
		// PATCH calisan uygulamayi dondurur ama DURMUS olani baslatmaz (canlida
		// olculdu) — rollout'u her durumda acikca tetikle.
		fmt.Println(T("→ triggering rollout"))
		if _, err := requestJSON(http.MethodPost,
			fmt.Sprintf("accounts/%s/platform/container/apps/%s/deploy", account, appUUID),
			map[string]any{}); err != nil {
			return err
		}
	} else {
		fmt.Println(T("→ creating the app"))
		port := project.Port
		if port == 0 {
			port = 8080
		}
		// The probe has to match what the app can answer. Asking the platform to
		// poll /health on an app with no such route gets the container killed
		// moments after it starts serving correctly — the app looks broken, the
		// logs show a clean boot followed by SIGTERM, and nothing says why.
		// A TCP probe asks the only question we can answer for sure: is the port
		// open? cdnctl check still recommends adding /health.
		healthPath := readManifestValue(dir, "healthcheck")
		healthType := "http"
		if healthPath == "" {
			if projectHasHealthRoute(dir) {
				healthPath = "/health"
			} else {
				healthType = "tcp"
				fmt.Println(T("   healthcheck: TCP (port open) — no /health route found in the code"))
			}
		}
		create, err := requestJSON(http.MethodPost,
			fmt.Sprintf("accounts/%s/platform/container/apps", account),
			map[string]any{
				"name": name, "image": image, "tag": tag,
				"port": port, "healthcheck": healthPath, "healthcheck_type": healthType,
			})
		if err != nil {
			return err
		}
		appUUID = extractAppUUID(create)
		if appUUID == "" {
			printJSONValue(create)
			return fmt.Errorf(T("could not create the app"))
		}
		// Record it: from here on this folder deploys to this app by id, so a
		// later name collision cannot silently redirect the deploy elsewhere.
		if err := setManifestValue(dir, "app", appUUID); err != nil {
			fmt.Fprintf(os.Stderr, T("warning: could not record the app id in cdnctl.yaml: %v\n"), err)
		}
		fmt.Println(T("→ assigning a subdomain"))
		exposeResp, err := requestJSON(http.MethodPost,
			fmt.Sprintf("accounts/%s/platform/container/apps/%s/expose", account, appUUID),
			map[string]any{})
		if err != nil {
			return err
		}
		if d := appDomain(exposeResp); d != "" {
			fallbackDomain = d
		}
		// create app'i "stopped" bırakır: pod'u ancak deploy başlatır. (İlk canlı
		// koşuda atlanmıştı — uygulama oluştu, expose oldu ve sonsuza dek "deploying"
		// göründü çünkü hiç pod yoktu.)
		fmt.Println(T("→ starting the first deploy"))
		if _, err := requestJSON(http.MethodPost,
			fmt.Sprintf("accounts/%s/platform/container/apps/%s/deploy", account, appUUID),
			map[string]any{}); err != nil {
			return err
		}
	}

	// Çalışır duruma gelmesini bekle ve adresi söyle.
	fmt.Println(T("→ waiting for the app to come up"))
	for i := 0; i < 30; i++ {
		show, err := requestJSON(http.MethodGet,
			fmt.Sprintf("accounts/%s/platform/container/apps/%s", account, appUUID), nil)
		if err != nil {
			return err
		}
		status := findString(show, "runtime_status")
		domain := appDomain(show)
		if domain == "" {
			// "running"a ilk gecen yoklamada show yaniti domaini henuz tasimayabiliyor
			// (temiz kabul kosusunda URL bos basildi) — expose yanitindan aldigimiz yedek.
			domain = fallbackDomain
		}
		if status == "running" && domain != "" {
			fmt.Printf(T("\n✓ LIVE: https://%s\n"), domain)
			return nil
		}
		if status == "running" {
			fmt.Println(T("\n✓ LIVE — for the address: cdnctl container apps show --app ") + appUUID)
			return nil
		}
		time.Sleep(10 * time.Second)
	}
	// Timing out is where someone most needs an answer, and "not running yet"
	// reads as patience when the truth is often a failed probe or a container
	// that exited. Show the state and the likely reason here rather than sending
	// the person to another command for a payload they then have to read.
	fmt.Println()
	if show, err := requestJSON(http.MethodGet,
		fmt.Sprintf("accounts/%s/platform/container/apps/%s", account, appUUID), nil); err == nil {
		printAppSummary(show)
	} else {
		fmt.Println(T("The app is not running yet — follow its state: cdnctl container apps show --app ") + appUUID)
	}
	return errExit(1)
}

func requiredAccount(args parsedArgs) string {
	if acct := option(args, "account", ""); acct != "" {
		return acct
	}
	cfg := readConfig()
	if cfg.Account != "" {
		fmt.Printf(T("(saved account: %s)\n"), cfg.Account)
		return cfg.Account
	}
	fmt.Fprintln(os.Stderr, "--account gerekli (ya da: cdnctl accounts use <uuid>)")
	os.Exit(2)
	return ""
}

func findAppByName(account, name string) string {
	resp, err := requestJSON(http.MethodGet,
		fmt.Sprintf("accounts/%s/platform/container/apps", account), nil)
	if err != nil {
		return ""
	}
	apps, _ := resp["apps"].([]any)
	if apps == nil {
		apps, _ = resp["data"].([]any)
	}
	for _, raw := range apps {
		app, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if n, _ := app["name"].(string); n == name {
			uuid, _ := app["uuid"].(string)
			return uuid
		}
	}
	return ""
}

func extractAppUUID(resp map[string]any) string {
	if uuid, _ := resp["uuid"].(string); uuid != "" {
		return uuid
	}
	for _, key := range []string{"app", "data", "result"} {
		if m, ok := resp[key].(map[string]any); ok {
			if uuid, _ := m["uuid"].(string); uuid != "" {
				return uuid
			}
		}
	}
	return ""
}

// findString: iç içe map'lerde ilk eşleşen anahtar değerini bulur (API yanıt
// şekilleri uca göre değişiyor; alan taşımak yerine anahtarla arıyoruz).
// appDomain digs the public address out of an app response. The API never
// returns a plain "domain" key: it reports public_subdomain plus domains /
// routed_domains lists, so a lookup for "domain" always came back empty and the
// last line of a successful deploy told people to go run another command to
// find out where their app was. That is the one line the whole flow exists to
// print.
func appDomain(payload map[string]any) string {
	if got := findString(payload, "public_subdomain"); got != "" {
		return got
	}
	for _, key := range []string{"domains", "routed_domains"} {
		if got := findFirstInList(payload, key); got != "" {
			return got
		}
	}
	return findString(payload, "domain")
}

// findFirstInList returns the first string of a named list anywhere in the tree.
func findFirstInList(node map[string]any, key string) string {
	if raw, ok := node[key].([]any); ok {
		for _, item := range raw {
			if text, ok := item.(string); ok && text != "" {
				return text
			}
		}
	}
	for _, value := range node {
		if child, ok := value.(map[string]any); ok {
			if got := findFirstInList(child, key); got != "" {
				return got
			}
		}
	}
	return ""
}

func findString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	for _, v := range m {
		if child, ok := v.(map[string]any); ok {
			if got := findString(child, key); got != "" {
				return got
			}
		}
	}
	return ""
}
