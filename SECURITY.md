# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public GitHub issue.

- Email: **info@cdn.com.tr** (subject: `cdnctl security`)
- Or use GitHub's [private vulnerability reporting](https://github.com/mediatriple/cdnctl/security/advisories/new)

Include what you found, how to reproduce it, and the `cdnctl --version` output. We aim to
acknowledge reports within a few business days and will keep you updated on the fix.

## Scope

This repository contains the **client** CLI. It authenticates against `https://cdn.com.tr` with
the operator's own credentials and stores a token at `~/.cdn/config.json`; it embeds no secrets
and no server-side authorization logic.

Issues in the cdn.com.tr platform or API itself are also welcome at the address above — say which
component you mean.

## Supported versions

Fixes land in the latest release. Update with:

```bash
cdnctl update --yes
```

Self-update downloads from `https://cdn.com.tr/downloads/cdnctl` and verifies the archive's
SHA256 checksum before installing.
