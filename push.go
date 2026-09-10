package main

import "os"

// cmdPush is the Push CDN vocabulary for the file commands.
//
// The panel calls this storage "Push CDN" and every guide walks the reader through it
// under that name, then handed them `files put` — a different word for the thing they
// had just been taught. The guides now say `push files upload`, so this makes that real
// rather than a second implementation: it rewrites the verb and hands off.
func cmdPush(args parsedArgs) error {
	if len(args.Positionals) < 2 || args.Positionals[0] != "files" {
		usage(os.Stderr)
		return errExit(2)
	}

	verb := args.Positionals[1]
	action, ok := map[string]string{
		"upload": "put",
		"list":   "ls",
		"remove": "rm",
		"mkdir":  "mkdir",
	}[verb]
	if !ok {
		usage(os.Stderr)
		return errExit(2)
	}

	forwarded := append([]string{action}, args.Positionals[2:]...)
	return cmdFiles(parsedArgs{
		Positionals: forwarded,
		Options:     args.Options,
		Bools:       args.Bools,
		Multi:       args.Multi,
	})
}
