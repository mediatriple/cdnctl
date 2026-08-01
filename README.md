# cdnctl

[![Go Reference](https://pkg.go.dev/badge/github.com/mediatriple/cdnctl.svg)](https://pkg.go.dev/github.com/mediatriple/cdnctl)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Official command-line interface for [cdn.com.tr](https://cdn.com.tr) — purge CDN cache, deploy
and manage container apps from Docker Compose, handle S3-compatible object storage, transfer
files and switch accounts, straight from your terminal or CI pipeline.

`cdnctl` is a single static binary with **no runtime dependencies** — no PHP, Node.js or Python
needed. It is written in Go using only the standard library.

> [cdn.com.tr](https://cdn.com.tr) is a Turkey-based CDN and managed hosting platform: a global
> edge network with WAF, DDoS protection and automatic SSL, plus managed WordPress/PHP hosting,
> Docker container apps and S3-compatible object storage in one panel.

---

## Install

**Homebrew** (macOS and Linux):

```bash
brew install mediatriple/tap/cdnctl
```

**Debian / Ubuntu** — signed APT repository:

```bash
curl -fsSL https://cdn.com.tr/downloads/cdn-com-tr.gpg \
  | sudo gpg --dearmor -o /usr/share/keyrings/cdn-com-tr.gpg
echo "deb [signed-by=/usr/share/keyrings/cdn-com-tr.gpg] https://cdn.com.tr/downloads/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/cdn-com-tr.list
sudo apt-get update && sudo apt-get install cdnctl
```

**RHEL / Fedora / Rocky** — signed YUM repository:

```bash
sudo tee /etc/yum.repos.d/cdn-com-tr.repo >/dev/null <<'EOF'
[cdn-com-tr]
name=cdn.com.tr
baseurl=https://cdn.com.tr/downloads/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://cdn.com.tr/downloads/cdn-com-tr.gpg
EOF
sudo dnf install cdnctl
```

Installed this way, cdnctl upgrades with your package manager (`brew upgrade cdnctl`,
`apt-get install --only-upgrade cdnctl`, `dnf upgrade cdnctl`); `cdnctl update` steps aside
rather than overwriting a file the package manager owns.

**With Go:**

```bash
go install github.com/mediatriple/cdnctl@latest
```

**Download a prebuilt binary** (linux `amd64`/`arm64`, macOS `amd64`/`arm64`, Windows `amd64`):

```bash
# see https://cdn.com.tr/downloads/cdnctl for all archives + checksums
curl -fsSLO "https://cdn.com.tr/downloads/cdnctl/cdnctl-$(curl -fsSL https://cdn.com.tr/downloads/cdnctl/latest.txt)-linux-amd64.tar.gz"
tar -xzf cdnctl-*-linux-amd64.tar.gz
sudo install cdnctl /usr/local/bin/cdnctl
```

Every archive is published with a SHA256 checksums file.

**Self-update** (verifies the SHA256 before installing):

```bash
cdnctl update --check      # is a newer version available?
cdnctl update --yes        # update in place
```

---

## Quick start

```bash
cdnctl login --email you@example.com     # prompts for the password
cdnctl accounts list                     # your CDN accounts
cdnctl accounts use <account_uuid>       # set the default account
cdnctl whoami
```

Purge the CDN cache:

```bash
cdnctl purge --account <account_uuid> --path /assets/app.css
cdnctl purge all --account <account_uuid>
```

Deploy a container app from a Docker Compose file:

```bash
cdnctl container compose preview --account <account_uuid> --file docker-compose.yml
cdnctl container compose apply   --account <account_uuid> --file docker-compose.yml
cdnctl container apps list --account <account_uuid>
cdnctl container apps logs --account <account_uuid> --app <app_uuid>
```

---

## Commands

| Group | What it does |
|---|---|
| `login` · `logout` · `whoami` · `configure` | Authentication and endpoint configuration |
| `accounts` | `list` · `use` · `current` · `clear` — switch between CDN accounts |
| `purge` | `purge` (paths) · `purge all` — invalidate edge cache |
| `container apps` | `create` · `deploy` · `list` · `show` · `status` · `logs` · `scale` · `restart` · `update` · `delete` · `expose` · `diagnose` · `wait` · `operations` |
| `container apps` (staging) | `create-preprod` · `promote` · `rollback` · `rollback-promotion` |
| `container compose` | `preview` · `apply` — deploy straight from `docker-compose.yml` |
| `container addons` | `enable-*` / `disable-*` for `redis`, `postgres`, `database`, `nats` · `list` |
| `container imports` | `database` · `files` · `list` · `cancel` — migrate an existing site in |
| `container jobs` | `create` · `list` · `run` · `delete` — scheduled (cron) HTTP jobs |
| `container registry-credentials` | `create` · `list` · `delete` — private image registries |
| `object-storage buckets` | `create` · `list` · `delete` · `usage` |
| `object-storage access-keys` | `create` · `rotate` · `revoke` — S3-compatible credentials |
| `object-storage bindings` | `create` · `delete` — attach a bucket to an app |
| `files` | `ls` · `put` · `rm` · `mkdir` — CDN file storage |
| `update` | Self-update with checksum verification |

Run `cdnctl` with no arguments for the full usage text, including every flag.

---

## Configuration

Config is stored at `~/.cdn/config.json`.

For CI and automation, use environment variables instead of an interactive login:

```bash
export CDN_ENDPOINT=https://cdn.com.tr
export CDN_ACCESS_TOKEN=...
cdnctl container apps list --account <account_uuid>
```

Other variables: `CDNCTL_BASE_URL` (mirror for self-update), `CDNCTL_BIN_DIR` (install directory).

### Example: purge the cache after a deploy

```yaml
# .github/workflows/deploy.yml
- name: Purge CDN cache
  env:
    CDN_ACCESS_TOKEN: ${{ secrets.CDN_ACCESS_TOKEN }}
  run: |
    go install github.com/mediatriple/cdnctl@latest
    cdnctl purge all --account ${{ vars.CDN_ACCOUNT_UUID }}
```

---

## Build from source

```bash
git clone https://github.com/mediatriple/cdnctl.git
cd cdnctl
go build -o cdnctl .
go test ./...
```

Requires Go 1.22+. There are no third-party dependencies.

---

## Security

`cdnctl` is a client: it authenticates against `https://cdn.com.tr` with your own credentials and
stores a token in `~/.cdn/config.json`. It contains no embedded secrets.

Found a vulnerability? Please see [SECURITY.md](SECURITY.md) — report it privately rather than
opening a public issue.

## Links

- Website — <https://cdn.com.tr>
- CLI docs & downloads — <https://cdn.com.tr/en/platform-help/tools/cdnctl>
- Help center — <https://cdn.com.tr/help>

## License

[MIT](LICENSE) © Mediatriple
