package main

import (
	"os"
	"strings"
)

// Only explanations are translated — never commands, flags or manifest keys.
// A message that says "run `cdnctl deploy`" keeps that command verbatim in
// every language: the words around it are for the reader, the command is for
// the shell, and translating it would produce something nobody can type.
//
// Resolution order, most specific first:
//
//	--lang on the command line
//	CDNCTL_LANG in the environment (how agents and CI pin it)
//	lang in the config file (cdnctl configure --lang tr)
//	the operating system locale (LC_ALL, LC_MESSAGES, LANG)
//	English
//
// English is the default because it is what someone lands on with no
// configuration at all, anywhere in the world; a Turkish OS gets Turkish
// without being asked.
const (
	langEN = "en"
	langTR = "tr"
)

// supportedLangs is the set a user may select. Adding a language means adding
// its code here and a third argument to the T/Tf calls — the message pairs live
// at their call sites so a translation cannot silently go missing behind a key.
var supportedLangs = map[string]bool{langEN: true, langTR: true}

// langOverride is set from --lang before any message is printed.
var langOverride string

// resolveLang returns the language user-facing text should use.
func resolveLang() string {
	if lang := normalizeLang(langOverride); lang != "" {
		return lang
	}
	if lang := normalizeLang(os.Getenv("CDNCTL_LANG")); lang != "" {
		return lang
	}
	if lang := normalizeLang(readConfig().Lang); lang != "" {
		return lang
	}
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if lang := normalizeLang(os.Getenv(key)); lang != "" {
			return lang
		}
	}
	return langEN
}

// normalizeLang accepts what people and operating systems actually write:
// "tr", "TR", "tr_TR.UTF-8", "tr-TR". Anything unrecognised returns empty so
// the next source in the chain gets its turn — an unsupported locale must not
// pin the language to a language we do not have.
func normalizeLang(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	for _, sep := range []string{".", "_", "-", "@"} {
		if idx := strings.Index(raw, sep); idx > 0 {
			raw = raw[:idx]
		}
	}
	if supportedLangs[raw] {
		return raw
	}
	return ""
}

// T picks the message for the active language.
func T(en, tr string) string {
	if resolveLang() == langTR {
		return tr
	}
	return en
}
