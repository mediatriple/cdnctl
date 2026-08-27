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
	name := option(args, "name", project.Name)
	dockerfile := option(args, "dockerfile", "Dockerfile")

	if _, err := os.Stat(filepath.Join(dir, dockerfile)); err != nil {
		return fmt.Errorf("%s bulunamadı. `cdnctl init` çalıştırın: tanıdığı proje tipleri (node, python, go, php, statik) için şablon yazar. Tanımadığı bir yığınsa Dockerfile'ı kendiniz yazmanız gerekir", dockerfile)
	}

	// Karne kapısı: hatalı deploy zaten çalışmayan bir site üretir; agent'lar
	// --skip-checks ile bilinçli geçebilir.
	if !args.Bools["skip-checks"] {
		findings := runChecks(dir)
		if hasErrors(findings) {
			fmt.Fprintln(os.Stderr, "Deploy durduruldu: `cdnctl check` HATA buldu (ayrıntı için çalıştırın).")
			fmt.Fprintln(os.Stderr, "Bilerek geçmek için: --skip-checks")
			return errExit(1)
		}
	}

	fmt.Printf("→ kaynak arşivleniyor (%s)\n", name)
	archive, size, err := makeSourceArchive(dir, dockerfile)
	if err != nil {
		return err
	}
	defer os.Remove(archive)
	fmt.Printf("→ yükleniyor (%.1f MB)\n", float64(size)/1024/1024)

	up, err := requestMultipart(http.MethodPost,
		fmt.Sprintf("accounts/%s/platform/container/source/upload", account),
		nil, "source", archive)
	if err != nil {
		return err
	}
	sourceID, _ := up["source_id"].(string)
	if sourceID == "" {
		printJSONValue(up)
		return fmt.Errorf("yükleme başarısız")
	}

	fmt.Println("→ build başlatılıyor (Kaniko, izole sandbox)")
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
		return fmt.Errorf("build başlatılamadı")
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
		fmt.Fprintln(os.Stderr, "Build başarısız/zaman aşımı. Loglar:")
		logs, _ := requestJSON(http.MethodPost,
			fmt.Sprintf("accounts/%s/platform/container/source/build/logs", account),
			map[string]any{"build_id": buildID})
		printJSONValue(logs)
		return errExit(1)
	}

	// Uygulama var mı? Varsa yeni tag'e çevir, yoksa oluştur + expose et.
	fallbackDomain := ""
	appUUID := option(args, "app", "")
	if appUUID == "" {
		appUUID = findAppByName(account, name)
	}
	if appUUID != "" {
		fmt.Printf("→ mevcut uygulama yeni imaja çevriliyor (%s:%s)\n", image, tag)
		if _, err := requestJSON(http.MethodPatch,
			fmt.Sprintf("accounts/%s/platform/container/apps/%s", account, appUUID),
			map[string]any{"image": image, "tag": tag}); err != nil {
			return err
		}
		// PATCH calisan uygulamayi dondurur ama DURMUS olani baslatmaz (canlida
		// olculdu) — rollout'u her durumda acikca tetikle.
		fmt.Println("→ rollout tetikleniyor")
		if _, err := requestJSON(http.MethodPost,
			fmt.Sprintf("accounts/%s/platform/container/apps/%s/deploy", account, appUUID),
			map[string]any{}); err != nil {
			return err
		}
	} else {
		fmt.Println("→ uygulama oluşturuluyor")
		port := project.Port
		if port == 0 {
			port = 8080
		}
		create, err := requestJSON(http.MethodPost,
			fmt.Sprintf("accounts/%s/platform/container/apps", account),
			map[string]any{
				"name": name, "image": image, "tag": tag,
				"port": port, "healthcheck": "/health", "healthcheck_type": "http",
			})
		if err != nil {
			return err
		}
		appUUID = extractAppUUID(create)
		if appUUID == "" {
			printJSONValue(create)
			return fmt.Errorf("uygulama oluşturulamadı")
		}
		fmt.Println("→ subdomain atanıyor")
		exposeResp, err := requestJSON(http.MethodPost,
			fmt.Sprintf("accounts/%s/platform/container/apps/%s/expose", account, appUUID),
			map[string]any{})
		if err != nil {
			return err
		}
		if d := findString(exposeResp, "domain"); d != "" {
			fallbackDomain = d
		}
		// create app'i "stopped" bırakır: pod'u ancak deploy başlatır. (İlk canlı
		// koşuda atlanmıştı — uygulama oluştu, expose oldu ve sonsuza dek "deploying"
		// göründü çünkü hiç pod yoktu.)
		fmt.Println("→ ilk deploy başlatılıyor")
		if _, err := requestJSON(http.MethodPost,
			fmt.Sprintf("accounts/%s/platform/container/apps/%s/deploy", account, appUUID),
			map[string]any{}); err != nil {
			return err
		}
	}

	// Çalışır duruma gelmesini bekle ve adresi söyle.
	fmt.Println("→ uygulamanın ayağa kalkması bekleniyor")
	for i := 0; i < 30; i++ {
		show, err := requestJSON(http.MethodGet,
			fmt.Sprintf("accounts/%s/platform/container/apps/%s", account, appUUID), nil)
		if err != nil {
			return err
		}
		status := findString(show, "runtime_status")
		domain := findString(show, "domain")
		if domain == "" {
			// "running"a ilk gecen yoklamada show yaniti domaini henuz tasimayabiliyor
			// (temiz kabul kosusunda URL bos basildi) — expose yanitindan aldigimiz yedek.
			domain = fallbackDomain
		}
		if status == "running" && domain != "" {
			fmt.Printf("\n✓ CANLI: https://%s\n", domain)
			return nil
		}
		if status == "running" {
			fmt.Println("\n✓ CANLI — adres icin: cdnctl container apps show --app " + appUUID)
			return nil
		}
		time.Sleep(10 * time.Second)
	}
	fmt.Println("Uygulama henüz running olmadı — durumu izleyin: cdnctl container apps show --app " + appUUID)
	return errExit(1)
}

func requiredAccount(args parsedArgs) string {
	if acct := option(args, "account", ""); acct != "" {
		return acct
	}
	cfg := readConfig()
	if cfg.Account != "" {
		fmt.Printf("(kayıtlı hesap: %s)\n", cfg.Account)
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
