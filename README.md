# scomp

scomp lists known vulnerabilities in the dependencies of the current Git repository and lets you browse and filter them.

It reads the repository's lockfiles with [osv-scanner](https://github.com/google/osv-scanner), which is embedded as a library, and shows one row per package × vulnerability (OSV ID, with CVE IDs alongside). No separate osv-scanner install is needed.

See [DESIGN.md](DESIGN.md) for the design.

## Requirements

- Go 1.27 or later (to build; with the default `GOTOOLCHAIN=auto`, `go install` downloads it automatically)
- `git`
- Optional: `osv-scanner` v2 in `PATH`, only for `--scanner=exec`

The binary is about 70 MB because osv-scanner is linked in.

## Install

```sh
go install github.com/jedipunkz/scomp@latest
```

## Usage

```
scomp [flags] [path]
```

| Flag | Default | Description |
|---|---|---|
| `path` | `.` | Scan target. Normalized to the Git root |
| `--no-cache` | false | Do not read or write the cache |
| `--cache-ttl` | `24h` | Cache TTL |
| `--offline` | false | Use osv-scanner's offline vulnerability DB (see Privacy) |
| `--scanner` | `lib` | `lib`: embedded osv-scanner (v2.7.0) / `exec`: run `osv-scanner` from `PATH` |
| `--json` | false | Print findings as JSON to stdout instead of starting the TUI |
| `--version` | | Print version |

Flags must come before `path`.

### Keys

| Key | Action |
|---|---|
| Typing / `backspace` | Edit query |
| `↑` `↓` / `ctrl+p` `ctrl+n` | Move selection |
| `pgup` `pgdown` | Page through the list |
| `enter` | Show full-screen detail / go back |
| `shift+↑` `shift+↓` / `k` `j` | Scroll the detail pane |
| mouse wheel | Scroll the detail pane |
| `ctrl+o` | Open `https://osv.dev/vulnerability/<ID>` in a browser |
| `ctrl+i` | Create a GitHub issue for the selected finding (requires `gh`, see below) |
| `ctrl+s` | Cycle severity filter (all → critical → high+ → medium+) |
| `ctrl+e` | Cycle ecosystem filter |
| `ctrl+f` | Toggle showing only findings with a fixed version |
| `ctrl+r` | Rescan ignoring the cache |
| `esc` / `ctrl+c` | Quit. In the detail view, `esc` / `q` return to the list |

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

`ctrl+i` on a finding creates a GitHub issue for it with the `gh` CLI. Requirements:

- `gh` installed and authenticated (`gh auth login`)
- the scan target is a git repository with a GitHub remote

The title and body are rendered from the template embedded in the binary ([`internal/issues/issue.tmpl`](internal/issues/issue.tmpl)), not from the repository's own `.github/ISSUE_TEMPLATE`. The flow:

1. scomp searches the repository's issues (all states) for the OSV ID and package name in the title.
2. None found: `y` creates the issue, `c` cancels.
3. One or more found: `o` overrides the newest one (rewrites its title and body; a closed issue stays closed), `d` creates a duplicate, `c` cancels.

On legacy terminals `ctrl+i` arrives as `tab`; both work.

### Cache

Results are cached in `os.UserCacheDir()/scomp/` (Linux: `$XDG_CACHE_HOME` or `~/.cache`, macOS: `~/Library/Caches`), keyed by the paths and contents of the repository's lockfiles together with the scomp version, the scanner (embedded osv-scanner version or `osv-scanner` path) and `--offline`. A cached result created in the future (the system clock went back) is ignored. A cached result is used for 24 hours by default, because new vulnerabilities are published even when lockfiles do not change. Press `ctrl+r` to rescan.

## Privacy

When online, osv-scanner sends package names, versions and ecosystems to osv.dev, and resolves transitive dependencies of manifest files (e.g. `requirements.txt`, `pom.xml`) through deps.dev. For a private repository, this means internal package names leave your machine.

`--offline` runs osv-scanner with `--offline-vulnerabilities --download-offline-databases --no-resolve`: only the vulnerability databases are downloaded, and no dependency information is sent. Because transitive resolution is disabled, manifest files without a lockfile report only their direct dependencies in this mode.

## Development

```sh
go test ./...
go vet ./...
```

`testdata/osv-scanner-v2.json` is trimmed output of osv-scanner 2.7.0.

To check that `lib` and `exec` produce identical findings (needs network access and `osv-scanner` in `PATH`):

```sh
SCOMP_INTEGRATION=1 go test -run TestLibMatchesExec ./internal/scanner/
```
