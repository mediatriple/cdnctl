package main

// The health check `cdnctl deploy` gives an app.
//
// An HTTP probe on a path the app does not serve is worse than no probe: the
// app boots, answers every real request, the probe gets 404, and Kubernetes
// kills it — over and over, with logs that show nothing but a clean start. That
// happened twice (the second time a static site app, 2026-10-24: 6 restarts, 502
// on the edge, nobody told why), both times because deploy guessed a /health
// route that was not there. So deploy only sets an HTTP probe on a path it has
// seen the code answer, or one the person named. Anything else is a question,
// and without a terminal to ask it in, a refusal that names the two flags.

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// healthChoice is the probe to send. An empty Type means "leave the app's
// probe as it is" — an existing app redeployed without a health flag.
type healthChoice struct {
	Type string // http | tcp | none
	Path string // http only
}

// addTo writes the choice into a create/update body using the field names the
// panel API validates (healthcheck_path, healthcheck_type). Deploy used to send
// "healthcheck", which the API does not read, so a path from cdnctl.yaml was
// silently replaced by the platform default.
func (h healthChoice) addTo(body map[string]any) {
	if h.Type == "" {
		return
	}
	body["healthcheck_type"] = h.Type
	if h.Type == "http" {
		body["healthcheck_path"] = h.Path
	}
}

func (h healthChoice) announce() {
	switch h.Type {
	case "http":
		fmt.Printf(T("   healthcheck: HTTP GET %s (must answer 200)\n"), h.Path)
	case "tcp":
		fmt.Println(T("   healthcheck: TCP (port open)"))
	case "none":
		fmt.Println(T("   healthcheck: none — the platform cannot tell if the app hangs; the panel shows a warning until a health endpoint is added"))
	}
}

// resolveDeployHealthcheck settles the probe before anything is uploaded.
//
// Flags win: --no-healthcheck, --healthcheck-type, --healthcheck /path. For a
// new app without flags: the path in cdnctl.yaml, then a /health route found in
// the code. With none of those, a person is asked and an agent is refused —
// guessing either way is how an app ends up restart-looping or unwatched
// without anyone having chosen it.
func resolveDeployHealthcheck(dir string, args parsedArgs, newApp, interactive bool, in io.Reader, out io.Writer) (healthChoice, error) {
	noCheck := args.Bools["no_healthcheck"]
	pathFlag, hasPath := args.Options["healthcheck"]
	typeFlag, hasType := args.Options["healthcheck_type"]
	typeFlag = strings.ToLower(strings.TrimSpace(typeFlag))

	if hasPath && !strings.HasPrefix(pathFlag, "/") {
		return healthChoice{}, errExitMessage(2, T("--healthcheck needs the path your app answers with 200, e.g. --healthcheck /health"))
	}
	if hasType && typeFlag != "http" && typeFlag != "tcp" && typeFlag != "none" {
		return healthChoice{}, errExitMessage(2, T("--healthcheck-type must be http, tcp or none"))
	}
	if noCheck && (hasPath || (hasType && typeFlag != "none")) {
		return healthChoice{}, errExitMessage(2, T("--no-healthcheck cannot be combined with --healthcheck or --healthcheck-type"))
	}

	switch {
	case noCheck:
		return healthChoice{Type: "none"}, nil
	case hasType && typeFlag == "http":
		path := pathFlag
		if path == "" {
			path = readManifestValue(dir, "healthcheck")
		}
		if path == "" {
			path = "/health"
		}
		return healthChoice{Type: "http", Path: path}, nil
	case hasType:
		return healthChoice{Type: typeFlag}, nil
	case hasPath:
		return healthChoice{Type: "http", Path: pathFlag}, nil
	case !newApp:
		return healthChoice{}, nil
	}

	if path := readManifestValue(dir, "healthcheck"); strings.HasPrefix(path, "/") {
		return healthChoice{Type: "http", Path: path}, nil
	}
	if projectHasHealthRoute(dir) {
		return healthChoice{Type: "http", Path: "/health"}, nil
	}

	if !interactive {
		// Returned, not printed: an agent (MCP, CI) reads the error, and this
		// one is the whole instruction it needs.
		return healthChoice{}, errExitMessage(1,
			T("No /health route found in the code, and there is no terminal to ask whether to deploy without a health check.")+"\n"+
				T("Choose explicitly: --healthcheck /path (a route your app answers with 200) or --no-healthcheck (deploy without a health check)."))
	}

	fmt.Fprint(out, T("No /health route found. Deploy without a health check? (yes/no): "))
	answer, _ := bufio.NewReader(in).ReadString('\n')
	if !isAffirmative(answer) {
		fmt.Fprintln(out, T("Cancelled. Add a route that answers 200 on GET /health and deploy again — or choose explicitly: --healthcheck /path or --no-healthcheck"))
		return healthChoice{}, errExit(1)
	}
	return healthChoice{Type: "none"}, nil
}
