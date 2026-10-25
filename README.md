# scomp

scomp lists known vulnerabilities in the dependencies of the current Git repository and lets you browse and filter them in a TUI. It reads the repository's lockfiles with an embedded [osv-scanner](https://github.com/google/osv-scanner) and shows one row per package × vulnerability (OSV ID, with CVE IDs alongside).

## Install

```sh
go install github.com/jedipunkz/scomp@latest
```

Requires `git` and Go 1.27+ (with the default `GOTOOLCHAIN=auto`, `go install` downloads it automatically). The binary is about 70 MB because osv-scanner is linked in.

## Usage

```sh
scomp [flags] [path]
```

| Flag | Default | Description |
|---|---|---|
| `path` | `.` | Scan target. Normalized to the Git root |
| `--no-cache` | false | Do not read or write the cache |
| `--cache-ttl` | `24h` | Cache TTL |
| `--offline` | false | Use osv-scanner's offline vulnerability DB (see Privacy) |
| `--scanner` | `lib` | `lib`: embedded osv-scanner / `exec`: run `osv-scanner` v2 from `PATH` |
| `--json` | false | Print findings as JSON to stdout instead of starting the TUI |
| `--version` | | Print version |

Flags must come before `path`.

Results are cached for `--cache-ttl` (default 24h), keyed by the lockfile paths and contents, so unchanged repositories start instantly. Press `alt+r` to rescan.

### Keys

| Key | Action |
|---|---|
| Typing / `backspace` | Edit query |
| `↑` `↓` / `ctrl+p` `ctrl+n` | Move selection |
| `pgup` `pgdown` | Page through the list |
| `shift+↑` `shift+↓` / `k` `j` | Scroll the detail pane |
| mouse wheel | Scroll the detail pane |
| `alt+o` | Open `https://osv.dev/vulnerability/<ID>` in a browser |
| `alt+i` | Create a GitHub issue for the selected finding (see below) |
| `alt+s` | Cycle severity filter (all → critical → high+ → medium+) |
| `alt+e` | Cycle ecosystem filter |
| `alt+f` | Toggle showing only findings with a fixed version |
| `alt+r` | Rescan ignoring the cache |
| `esc` / `ctrl+c` | Quit |

### Query

The query is a filter expression. Field terms constrain the result and free text matches package name, ecosystem, OSV ID, CVE IDs and summary (case-insensitive substring):

```
severity:high              exact severity (also sev:)
severity:>=high            comparison: > >= < <= = and a comma list (severity:high,critical)
ecosystem:go               ecosystem substring (also eco:)
package:x/net              package name substring (also pkg:)
id:GO-2024                 OSV ID substring
cve:CVE-2023               CVE ID substring
source:go.mod              lockfile path substring
fixed:true / fixed:false   only findings with / without a fixed version
net/http                   free text: matches all of the above fields
```

Field terms and free text are ANDed. `j` / `k` scroll the detail pane instead of typing into the query.

### GitHub issues

`alt+i` on a finding searches the repository's GitHub issues for it and asks in a popup: with no existing issue, `y` creates it and `c` cancels; with one, `o` overrides it (rewrites its title and body), `d` creates a duplicate, `c` cancels.

Requires `gh` installed and authenticated (`gh auth login`) and a GitHub remote in the scan target. Created issues carry the `security` label; the label is created on demand when the repository does not have it yet (fails if the token lacks the permission). The title and body come from a template embedded in the binary ([`internal/issues/issue.tmpl`](internal/issues/issue.tmpl)); the scan target's own issue templates are not used.

## Privacy

Online scans send package names, versions and ecosystems to osv.dev, and resolve transitive dependencies of manifest files (e.g. `requirements.txt`) through deps.dev. For a private repository, this means internal package names leave your machine.

`--offline` only downloads the vulnerability databases and sends nothing. Transitive resolution is disabled in this mode, so manifest files without a lockfile report only their direct dependencies.

## Development

```sh
make build   # go build ./...
make test    # go test -race ./...
make check   # build + vet + golangci-lint + test, same as CI
```
