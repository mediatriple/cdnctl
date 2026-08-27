package main

// cdnctl mcp — cdnctl'i bir MCP (Model Context Protocol) sunucusu olarak çalıştırır.
//
// Faz 3'ün özü (kb: cdnctl-init-vibe-deploy): bu ürünün asıl kullanıcısı çoğu zaman
// müşterinin yanındaki lokal AI agent. MCP, o agent'ların ortak dili — Claude Code,
// Cursor ve benzerleri bu sunucuyu bağladığında deploy/check/status birer araç olur
// ve agent uygulamayı yazdığı oturumda canlıya da alabilir.
//
// Taşıma: stdio üzerinde satır-ayrımlı JSON-RPC 2.0 (MCP stdio taşıması). stdout
// YALNIZCA protokol mesajı taşır; araçların insan-okur çıktısı yakalanıp araç
// sonucunun içine konur, tanılama stderr'e gider.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func rpcReply(w io.Writer, id json.RawMessage, result any, rerr *rpcError) {
	resp := map[string]any{"jsonrpc": "2.0", "id": id}
	if rerr != nil {
		resp["error"] = rerr
	} else {
		resp["result"] = result
	}
	data, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcp: marshal:", err)
		return
	}
	w.Write(append(data, '\n'))
}

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func objSchema(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

var mcpTools = []mcpTool{
	{
		Name:        "project_info",
		Description: "Detect the project in a directory: language, framework, port, Dockerfile/compose presence, and which AI agents are configured. Read-only, local.",
		InputSchema: objSchema(map[string]any{
			"dir": map[string]any{"type": "string", "description": "Project directory (default: current)"},
		}),
	},
	{
		Name:        "check",
		Description: "Pre-deploy report card, entirely local: localhost binds, secrets in code, SQLite-in-container, missing healthcheck, node_modules baked into the image. Fix errors before deploying.",
		InputSchema: objSchema(map[string]any{
			"dir": map[string]any{"type": "string", "description": "Project directory (default: current)"},
		}),
	},
	{
		Name:        "entitlement",
		Description: "Whether the logged-in account has a container-platform package (needed to deploy). If missing, direct the human to the returned purchase URL — payment happens in the browser on cdn.com.tr.",
		InputSchema: objSchema(map[string]any{}),
	},
	{
		Name:        "deploy",
		Description: "Deploy the project from source: archive, upload, build on the platform (Kaniko sandbox), point the app at the new image (creating and exposing it if needed) and wait until it runs. No git or registry required. Long-running (1-5 minutes).",
		InputSchema: objSchema(map[string]any{
			"dir":     map[string]any{"type": "string", "description": "Project directory (default: current)"},
			"account": map[string]any{"type": "string", "description": "Account UUID (default: the saved account)"},
			"name":    map[string]any{"type": "string", "description": "App name (default: detected project name)"},
		}),
	},
	{
		Name:        "apps_list",
		Description: "List the account's container apps with their status.",
		InputSchema: objSchema(map[string]any{
			"account": map[string]any{"type": "string", "description": "Account UUID (default: the saved account)"},
		}),
	},
	{
		Name:        "app_show",
		Description: "Full status of one container app (domain, runtime status, image).",
		InputSchema: objSchema(map[string]any{
			"account": map[string]any{"type": "string", "description": "Account UUID (default: the saved account)"},
			"app":     map[string]any{"type": "string", "description": "App UUID"},
		}, "app"),
	},
}

type mcpArgs struct {
	Dir     string `json:"dir"`
	Account string `json:"account"`
	Name    string `json:"name"`
	App     string `json:"app"`
}

// captureStdout: cmdDeploy insan-okur ilerleme basar; MCP'de stdout protokolündür.
// Aracı çalıştırırken stdout'u bir pipe'a çevirip metni sonuca gömeriz.
func captureStdout(run func() error) (string, error) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", run()
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()
	runErr := run()
	w.Close()
	os.Stdout = old
	out := <-done
	r.Close()
	return out, runErr
}

func mcpAccount(a mcpArgs) (string, *rpcError) {
	if a.Account != "" {
		return a.Account, nil
	}
	cfg := readConfig()
	if cfg.Account != "" {
		return cfg.Account, nil
	}
	return "", &rpcError{Code: -32602, Message: "account is required (or save one: cdnctl accounts use <uuid>)"}
}

func mcpCallTool(name string, a mcpArgs) (any, *rpcError) {
	dir := a.Dir
	if dir == "" {
		dir = "."
	}
	switch name {
	case "project_info":
		return map[string]any{"project": detectProject(dir), "agents": detectAgents(dir)}, nil
	case "check":
		findings := runChecks(dir)
		return map[string]any{
			"findings": findings,
			"errors":   countSeverity(findings, "error"),
			"warnings": countSeverity(findings, "warning"),
			"verdict":  map[bool]string{true: "fix errors before deploying", false: "ok to deploy"}[hasErrors(findings)],
		}, nil
	case "entitlement":
		ent := checkEntitlement()
		out := map[string]any{"entitlement": ent}
		if !ent.PlatformEnabled {
			out["purchase_url"] = buyNowURL(readConfig().Endpoint)
			out["note"] = "Payment happens in the browser on cdn.com.tr; poll this tool afterwards — it flips to enabled automatically."
		}
		return out, nil
	case "deploy":
		account, rerr := mcpAccount(a)
		if rerr != nil {
			return nil, rerr
		}
		parsed := parsedArgs{Options: map[string]string{"dir": dir, "account": account}, Bools: map[string]bool{}, Multi: map[string][]string{}}
		if a.Name != "" {
			parsed.Options["name"] = a.Name
		}
		out, err := captureStdout(func() error { return cmdDeploy(parsed) })
		result := map[string]any{"log": out, "succeeded": err == nil}
		if err != nil {
			if _, ok := isExitError(err); !ok {
				result["error"] = err.Error()
			}
		}
		return result, nil
	case "apps_list":
		account, rerr := mcpAccount(a)
		if rerr != nil {
			return nil, rerr
		}
		resp, err := requestJSON(http.MethodGet, fmt.Sprintf("accounts/%s/platform/container/apps", account), nil)
		if err != nil {
			return nil, &rpcError{Code: -32000, Message: err.Error()}
		}
		return resp, nil
	case "app_show":
		account, rerr := mcpAccount(a)
		if rerr != nil {
			return nil, rerr
		}
		if a.App == "" {
			return nil, &rpcError{Code: -32602, Message: "app (uuid) is required"}
		}
		resp, err := requestJSON(http.MethodGet, fmt.Sprintf("accounts/%s/platform/container/apps/%s", account, a.App), nil)
		if err != nil {
			return nil, &rpcError{Code: -32000, Message: err.Error()}
		}
		return resp, nil
	}
	return nil, &rpcError{Code: -32601, Message: "unknown tool: " + name}
}

func cmdMcp(_ parsedArgs) error {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	out := os.Stdout
	fmt.Fprintln(os.Stderr, "cdnctl mcp: hazır (stdio)")

	for in.Scan() {
		line := bytes.TrimSpace(in.Bytes())
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		switch req.Method {
		case "initialize":
			rpcReply(out, req.ID, map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "cdnctl", "version": version},
			}, nil)
		case "notifications/initialized", "initialized":
			// bildirim — yanıt yok
		case "ping":
			rpcReply(out, req.ID, map[string]any{}, nil)
		case "tools/list":
			rpcReply(out, req.ID, map[string]any{"tools": mcpTools}, nil)
		case "tools/call":
			var params struct {
				Name      string  `json:"name"`
				Arguments mcpArgs `json:"arguments"`
			}
			if err := json.Unmarshal(req.Params, &params); err != nil {
				rpcReply(out, req.ID, nil, &rpcError{Code: -32602, Message: "invalid params"})
				continue
			}
			result, rerr := mcpCallTool(params.Name, params.Arguments)
			if rerr != nil {
				rpcReply(out, req.ID, map[string]any{
					"content": []map[string]any{{"type": "text", "text": rerr.Message}},
					"isError": true,
				}, nil)
				continue
			}
			text, _ := marshalIndentNoHTMLEscape(result)
			rpcReply(out, req.ID, map[string]any{
				"content": []map[string]any{{"type": "text", "text": string(text)}},
			}, nil)
		default:
			if len(req.ID) > 0 {
				rpcReply(out, req.ID, nil, &rpcError{Code: -32601, Message: "method not found: " + req.Method})
			}
		}
	}
	return nil
}
