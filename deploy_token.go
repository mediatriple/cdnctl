package main

// cdnctl deploy-token — lokal AI agent'a verilecek dar kapsamlı kimlik (Faz 3).
//
// Tasarım (kb: cdnctl-init-vibe-deploy): agent'a kullanıcının tam panel yetkisi
// verilmez — emsal, WP eklentisinin purge-only anahtarları. Bu token yalnız
// /deploy-token yüzeyini açar (kaynak yükle/build + uygulamayı canlıya alma);
// endpoint() cdnctl_ önekini görünce yönlendirmeyi şeffaf yapar.

import (
	"fmt"
	"net/http"
	"os"
)

func cmdDeployToken(args parsedArgs) error {
	action := ""
	if len(args.Positionals) >= 1 {
		action = args.Positionals[0]
	}
	account := requiredAccount(args)

	switch action {
	case "create":
		payload := map[string]any{}
		if name := option(args, "name", ""); name != "" {
			payload["name"] = name
		}
		resp, err := requestJSON(http.MethodPost,
			fmt.Sprintf("accounts/%s/platform/container/deploy-tokens", account), payload)
		if err != nil {
			return err
		}
		if token, _ := resp["token"].(string); token != "" {
			fmt.Println("Deploy token (BİR KEZ gösterilir — şimdi kaydedin):")
			fmt.Println("  " + token)
			fmt.Println()
			fmt.Println("Agent'a vermek için: cdnctl configure --endpoint " + readConfig().Endpoint + " --token " + token)
			fmt.Println("Kapsam: yalnız deploy (kaynak yükle/build + uygulama yaşam döngüsü).")
			return nil
		}
		return printJSONValue(resp)
	case "list":
		return printRequest(http.MethodGet,
			fmt.Sprintf("accounts/%s/platform/container/deploy-tokens", account), nil)
	case "revoke":
		id := option(args, "id", "")
		if id == "" {
			fmt.Fprintln(os.Stderr, "--id gerekli (cdnctl deploy-token list ile görün)")
			return errExit(2)
		}
		return printRequest(http.MethodPost,
			fmt.Sprintf("accounts/%s/platform/container/deploy-tokens/%s/revoke", account, id), map[string]any{})
	}
	fmt.Fprintln(os.Stderr, "kullanım: cdnctl deploy-token create|list|revoke")
	return errExit(2)
}
