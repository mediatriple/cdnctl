package main

import (
	"bufio"
	"fmt"
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
	langES = "es"
	langFR = "fr"
	langRU = "ru"
	langAR = "ar"
	langFA = "fa"
)

// supportedLangs is the set a user may select. Adding a language means adding
// its code here and a third argument to the T/Tf calls — the message pairs live
// at their call sites so a translation cannot silently go missing behind a key.
var supportedLangs = map[string]bool{
	langEN: true, langTR: true, langES: true,
	langFR: true, langRU: true, langAR: true, langFA: true,
}

// catalogs holds one map per language, keyed by the English source text.
// English has no catalog: it is the key set itself, so it can never drift out
// of sync with the code.
var catalogs = map[string]map[string]string{
	langTR: messagesTR,
	langES: messagesES,
	langFR: messagesFR,
	langRU: messagesRU,
	langAR: messagesAR,
	langFA: messagesFA,
}

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

// T returns the message for the active language, keyed by the English text.
//
// English is the key set rather than a catalog, so a message that exists in the
// code always has a usable form. An untranslated key falls back to English —
// visibly imperfect, never blank or missing — and the completeness test turns
// that gap into a build failure long before a user meets it.
func T(en string) string {
	lang := resolveLang()
	if lang == langEN {
		return en
	}
	if translated, ok := catalogs[lang][en]; ok && translated != "" {
		return translated
	}
	return en
}

// maybeAskLanguageOnce offers the language choice the first time a person uses
// cdnctl from a terminal. A setting nobody knows about is a setting nobody uses,
// and the people most likely to want Turkish are the least likely to go looking
// for an English flag that would tell them it exists.
//
// It asks at most once — the answer is saved — and only when all of these hold:
// the language was not already decided (flag, environment, config), both ends of
// the terminal are real, and the command is not one whose output a machine
// parses. Getting any of that wrong turns a helpful question into a corrupted
// MCP stream or a CI job blocked forever on a prompt nobody can answer, so the
// default in every uncertain case is to stay silent and use the resolved
// language.
func maybeAskLanguageOnce(command string, args parsedArgs) {
	if langOverride != "" || os.Getenv("CDNCTL_LANG") != "" || readConfig().Lang != "" {
		return
	}
	// mcp speaks JSON-RPC on stdio and --json means a program is reading; both
	// would be broken by a question. version/help are one-shot and not worth
	// interrupting, and configure is where someone sets this deliberately.
	switch command {
	case "mcp", "version", "--version", "help", "--help", "configure":
		return
	}
	if args.Bools["json"] || os.Getenv("CI") != "" {
		return
	}
	if !isInteractive() {
		return
	}

	// The question is bilingual because at this point we do not yet know which
	// language the reader has.
	suggested := langEN
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if lang := normalizeLang(os.Getenv(key)); lang != "" {
			suggested = lang
			break
		}
	}

	// Every option is written in its own language: someone who reads only Farsi
	// should not have to recognise the English word "Persian" to find it.
	fmt.Fprintln(os.Stderr, "Dil / Language / Idioma / Langue / Язык / اللغة / زبان")
	for i, option := range languageMenu {
		fmt.Fprintf(os.Stderr, "  %d) %s\n", i+1, option.label)
	}
	fmt.Fprintf(os.Stderr, "[1-%d] (Enter = %s): ", len(languageMenu), suggested)

	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && strings.TrimSpace(answer) == "" {
		return // no answer available after all; stay with the resolved language
	}
	chosen := suggested
	reply := strings.ToLower(strings.TrimSpace(answer))
	for i, option := range languageMenu {
		if reply == fmt.Sprint(i+1) || reply == option.code {
			chosen = option.code
			break
		}
	}

	cfg := readConfig()
	cfg.Lang = chosen
	if err := writeConfig(cfg); err != nil {
		// Saving is a convenience, not a requirement: honour the choice for this
		// run rather than failing the command the person actually asked for.
		langOverride = chosen
	}
	fmt.Fprintln(os.Stderr, T("Language saved. Change it any time: cdnctl configure --lang <code>"))
	fmt.Fprintln(os.Stderr)
}

// isInteractive reports whether there is a person on both ends of this session.
func isInteractive() bool {
	for _, file := range []*os.File{os.Stdin, os.Stderr} {
		info, err := file.Stat()
		if err != nil || (info.Mode()&os.ModeCharDevice) == 0 {
			return false
		}
	}
	return true
}

// languageMenu is the first-run choice, each option labelled in its own
// language and ordered to match the site's locale list.
var languageMenu = []struct {
	code  string
	label string
}{
	{langTR, "Türkçe"},
	{langEN, "English"},
	{langES, "Español"},
	{langFR, "Français"},
	{langRU, "Русский"},
	{langAR, "العربية"},
	{langFA, "فارسی"},
}

// affirmatives are the answers that mean yes, in every language cdnctl offers
// plus English. Asking "Sobrescribir?" in Spanish while only accepting "yes"
// or "evet" turns a deliberate confirmation into a silent cancellation, so the
// whole set is accepted regardless of the display language — someone typing
// "yes" at a Turkish prompt is being just as clear as someone typing "evet".
var affirmatives = map[string]bool{
	"y": true, "yes": true,
	"e": true, "evet": true, // tr
	"s": true, "si": true, "sí": true, // es
	"o": true, "oui": true, // fr
	"d": true, "da": true, "да": true, // ru
	"n'am": true, "نعم": true, // ar
	"bale": true, "بله": true, // fa
}

// isAffirmative reports whether an answer to a yes/no prompt means yes.
func isAffirmative(answer string) bool {
	return affirmatives[strings.ToLower(strings.TrimSpace(answer))]
}
