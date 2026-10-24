# scomp

scomp lists known vulnerabilities in the dependencies of the current Git repository and lets you browse them with an fzf-style fuzzy finder.

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
| `shift+↑` `shift+↓` | Scroll preview |
| `ctrl+o` | Open `https://osv.dev/vulnerability/<ID>` in a browser |
| `ctrl+s` | Cycle severity filter (all → critical → high+ → medium+) |
| `ctrl+e` | Cycle ecosystem filter |
| `ctrl+f` | Toggle showing only findings with a fixed version |
| `ctrl+r` | Rescan ignoring the cache |
| `esc` / `ctrl+c` | Quit |

The query matches package name, ecosystem, OSV ID, CVE IDs and summary.

### Cache

Results are cached in `os.UserCacheDir()/scomp/` (Linux: `$XDG_CACHE_HOME` or `~/.cache`, macOS: `~/Library/Caches`), keyed by the paths and contents of the repository's lockfiles. A cached result is used for 24 hours by default, because new vulnerabilities are published even when lockfiles do not change. Press `ctrl+r` to rescan.

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
