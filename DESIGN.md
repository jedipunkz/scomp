# scomp design

## 1. Overview

scomp is a TUI tool that fetches known vulnerabilities in the packages that the Git repository in the current directory depends on, and lets the user filter and browse them.

The name comes from the Star Wars scomp link (the connector R2-D2 plugs into terminals to read data). It maps to the action of reading the repository's lockfiles.

## 2. Goals and non-goals

### Goals

- Show only vulnerabilities relevant to your own repository (not a browser for all CVEs)
- Support lockfiles for many languages (without writing per-language parsers ourselves)
- Filter with query terms (`severity:high`, `ecosystem:go`, `fixed:true`) and case-insensitive free text across package name, vulnerability ID, CVE ID, and summary
- Make startup-to-list fast (show from cache immediately if lockfiles have not changed)

### Non-goals

- Automatic dependency updates / fixes (the domain of `osv-scanner fix`)
- Container image scanning
- SBOM generation / output
- Reachability analysis (govulncheck integration is a future consideration, see §16)

## 3. Terminology

| Term | Meaning |
|---|---|
| OSV | Open Source Vulnerabilities. The vulnerability DB and schema provided by osv.dev |
| OSV ID | A vulnerability ID on OSV, such as `GHSA-` / `GO-` / `PYSEC-` / `RUSTSEC-`. CVE IDs are stored in aliases |
| Finding | A pair of "1 package × 1 vulnerability". Corresponds to one row in the TUI |
| Root | The repository's top-level directory obtained via `git rev-parse --show-toplevel` |

## 4. Architecture

```
┌────────────┐   ┌──────────────┐   ┌───────────────┐
│ cmd (main) │──▶│ repo         │──▶│ cache         │
│ parse flags│   │ detect root  │   │ lockfile hash │
└────────────┘   │ list lockfiles│  │ hit → return  │
                 └──────────────┘   └──────┬────────┘
                                           │ miss
                                           ▼
                                    ┌───────────────┐
                                    │ scanner       │
                                    │ (interface)   │
                                    │  ├ exec impl  │ exec osv-scanner
                                    │  └ lib  impl  │ import osv-scanner/v2
                                    └──────┬────────┘
                                           ▼
                                    ┌───────────────┐
                                    │ model         │
                                    │ []Finding     │
                                    └──────┬────────┘
                                           ▼
                                    ┌───────────────┐
                                    │ tui           │
                                    │ Bubble Tea v2 │
                                    │ + query filter│
                                    └───────────────┘
```

## 5. Dependencies

| Purpose | Module | Notes |
|---|---|---|
| TUI framework | `charm.land/bubbletea/v2` | v2 moved its import path to a vanity domain. `View()` returns `tea.View` |
| UI components | `charm.land/bubbles/v2` | Uses `textinput`, `viewport`, `spinner`, `help` |
| Styling | `charm.land/lipgloss/v2` | |
| Vulnerability scanning (lib impl) | `github.com/google/osv-scanner/v2/pkg/osvscanner` | v2.7.0. Requires Go 1.27. `DoScan(ScannerActions)` takes no context |
| Opening a browser | Standard library + OS-specific command | macOS `open`, Linux `xdg-open` |

External commands (exec impl only): `osv-scanner` (v2), `git`.

## 6. Processing flow

1. Parse flags.
2. Get the root via `git rev-parse --show-toplevel`. If outside Git, use the current directory as the root and print a one-line warning.
3. List lockfiles under the root (walk using the target file names in §9; exclude `.git/`, `node_modules/`, `vendor/`).
4. Compute SHA-256 from the paths and contents of the listed lockfiles and use it as the cache key.
5. If the cache exists, the key matches, and it is within TTL, read `[]Finding` from the cache.
6. Otherwise, start the TUI first showing "scanning", and run the scanner as a background `tea.Cmd`.
7. On scan completion, receive `scanDoneMsg`, update the list, and write the cache.
8. Handle user actions (search, filtering, detail view).

Even when shown from the cache, `ctrl+r` rescans.

## 7. Scanner layer

### 7.1 Interface

```go
type Scanner interface {
    Scan(ctx context.Context, root string) ([]model.Finding, error)
}
```

The TUI and cache depend only on `[]model.Finding`. Swapping the exec and lib implementations requires no TUI changes.

### 7.2 exec implementation (M1)

```
osv-scanner scan source -r <root> --format json
```

- Convert the stdout JSON into `model.Finding`.
- Exit code handling (to verify: confirm the exact v2 definitions during implementation):

| Exit code | Assumed meaning | scomp handling |
|---|---|---|
| 0 | No vulnerabilities | Success. Show an empty list |
| 1 | Vulnerabilities found | Success. Parse stdout |
| 128 | No packages found | Success. Show "no lockfiles" |
| Other | Error | Show the error including stderr |

- If `osv-scanner` is not on PATH, print install instructions (`go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`) and exit.

Reason for implementing exec first: it is the smallest amount of code, and it automatically follows osv-scanner's addition of new lockfile support.

### 7.3 lib implementation (M5)

- Call `osvscanner.DoScan` directly. Enables single-binary distribution.
- Migration condition: once the TUI is complete with the exec implementation and the v2 library API stability is confirmed.
- Switch with the flag `--scanner=exec|lib`. lib is the default (users no longer need to install osv-scanner).
- `ScannerActions` mirrors what `osv-scanner scan source -r <root>` builds from its default flags (plugins `lockfile`, `sbom`, `directory`; call analysis `go` only). `--offline` sets `CompareOffline`, `DownloadDatabases` and `TransitiveScanning.Disabled`, matching the exec arguments.
- The result is marshaled to JSON and passed to the same parser as exec, so both produce identical findings. `TestLibMatchesExec` (run with `SCOMP_INTEGRATION=1`) checks this.
- `DoScan` takes no context: it runs in a goroutine, and on cancel its result is dropped.
- osvscanner logs through a process-global logger. It is redirected with `osvscanner.SetLogger` into a buffer (shown as the error details on failure) so it does not corrupt the TUI, and scans are serialized.
- Binary size is about 70 MB.

## 8. Data model

```go
package model

type Severity int

const (
    SeverityUnknown Severity = iota
    SeverityLow
    SeverityMedium
    SeverityHigh
    SeverityCritical
)

type Package struct {
    Name      string // e.g. golang.org/x/net
    Version   string // e.g. v0.17.0
    Ecosystem string // e.g. Go, npm, PyPI
    Source    string // lockfile path relative to the root, e.g. go.mod
}

type Finding struct {
    ID            string    // OSV ID, e.g. GO-2024-2687
    Aliases       []string  // alternate IDs such as CVE / GHSA
    CVEs          []string  // entries from Aliases starting with CVE-
    Summary       string
    Details       string    // Markdown
    Severity      Severity
    CVSSScore     float64   // 0 if unknown
    Package       Package
    FixedVersions []string  // empty if no fixed version
    References    []string  // URLs
    Published     time.Time
    Modified      time.Time
}
```

### Determining severity

1. Use the max severity included in the osv-scanner JSON (to verify: field name).
2. If absent, derive from the CVSS v3 score: ≥ 9.0 Critical / ≥ 7.0 High / ≥ 4.0 Medium / > 0 Low / otherwise Unknown.

### Why the display is not limited to CVEs

Some OSV advisories have no CVE ID (e.g. only `GO-`). Limiting to CVEs would miss them, so the row unit is the OSV ID, and CVE IDs are shown as a column.

## 9. Cache

| Item | Value |
|---|---|
| Location | `os.UserCacheDir()/scomp/<first 16 hex chars of SHA-256 of root path>.json` |
| Key | SHA-256 of the lockfile set (paths + contents) |
| TTL | 24 hours (configurable with `--cache-ttl`). A TTL is needed because new vulnerabilities are added to the DB even when lockfiles are unchanged |
| Invalidation | `--no-cache` skips both reads and writes. `ctrl+r` rescans and overwrites |
| Write method | Write to a temp file and replace with `os.Rename` (to avoid leaving a corrupt file on interruption) |
| Permissions | Directory 0700, file 0600 |

Target file names for lockfile listing (initial values; finalize during implementation by cross-checking osv-scanner's supported list, to verify):

| Ecosystem | Files |
|---|---|
| Go | `go.mod` |
| npm / pnpm / yarn | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` |
| Python | `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock` |
| Rust | `Cargo.lock` |
| Ruby | `Gemfile.lock` |
| PHP | `composer.lock` |
| Java | `pom.xml`, `gradle.lockfile` |
| .NET | `packages.lock.json` |

Listing is used only for cache key computation. The actual dependency extraction is done by the scanner (osv-scanner).

## 10. TUI

### 10.1 Layout

```
┌ scomp ─ github.com/jedipunkz/foo ─ 12 findings (C:1 H:4 M:5 L:2) ─ cached 3h ago ┐
│ > severity:>=high eco:go█                                        sev:all eco:all │
├──────────────────────────────────────────────────────────────────────────────────┤
│ ▶ CRIT  golang.org/x/net   v0.17.0  GO-2024-2687  HTTP/2 CONTINUATION flood      │
│   HIGH  golang.org/x/net   v0.17.0  GO-2025-1234  HTTP/2 rapid reset             │
│   HIGH  golang.org/x/net   v0.17.0  GO-2025-5678  ...                            │
│   ...                                                                            │
├──────────────────────────────────────────────────────────────────────────────────┤
│ GO-2024-2687                                                                     │
│ CVE-2023-45288                                                                   │
│                                                                                  │
│ Package : golang.org/x/net v0.17.0                                               │
│ Source  : go.mod                                                                 │
│ Fixed   : v0.23.0                                                                │
│ HTTP/2 CONTINUATION flood in net/http ...                                        │
├──────────────────────────────────────────────────────────────────────────────────┤
│ ↑↓ move  enter detail  ctrl+o open  ctrl+s severity  ctrl+e ecosystem  ctrl+r rescan  esc quit │
└──────────────────────────────────────────────────────────────────────────────────┘
```

- Top: search input (`bubbles/textinput`), styled prompt and cursor. Focus is on the input from startup, and typed characters always go into the query.
- Above: Finding list. Free-text matches are highlighted. The selected row is highlighted with the gruvbox `bg1` background across its full width.
- Below: detail pane of the selected Finding (`bubbles/viewport`), about 55% of the body height. Scrolled with `shift+↑` `shift+↓` `j` `k` and the mouse wheel.
- The list and detail panes have title bars (`Findings n/m`, `Detail`) rendered with lipgloss; the help bar uses `bubbles/help` with gruvbox styles.
- `enter` toggles a full-screen detail view. On very short terminals where the list would drop below 3 rows, the pane is hidden and `enter` is the only way to see the detail.

### 10.2 Key bindings

| Key | Action |
|---|---|
| Typing / `backspace` | Edit query |
| `↑` `↓` / `ctrl+p` `ctrl+n` | Move selection |
| `pgup` `pgdown` | Page through the list |
| `enter` | Show full-screen detail / go back |
| `shift+↑` `shift+↓` / `k` `j` | Scroll the detail pane |
| `ctrl+o` | Open `https://osv.dev/vulnerability/<ID>` in a browser |
| `ctrl+s` | Cycle severity filter (all → critical → high+ → medium+) |
| `ctrl+e` | Cycle ecosystem filter (all → detected ecosystems in order) |
| `ctrl+f` | Toggle showing only findings with a fixed version |
| `ctrl+r` | Rescan ignoring the cache |
| `esc` / `ctrl+c` | Quit. In the detail view, `esc` / `q` return to the list |

Why `q` does not quit: typed characters always go into the query by design. Exceptions: `j` / `k` are reserved for scrolling the detail pane and never reach the query; in the detail view, `q` returns to the list.

### 10.3 Query filtering

The search target string for each Finding is precomputed by joining the following with spaces:

```
<Package.Name> <Package.Ecosystem> <ID> <CVEs...> <Summary>
```

The query is a filter expression parsed into terms:

| Term | Matches |
|---|---|
| `severity:<op><name>[,<name>...]` (also `sev:`) | Severity. `<op>` is one of `=`, `>=`, `>`, `<=`, `<` (default `=`); `<name>` is `critical` / `high` / `medium` (`moderate`) / `low` / `unknown`. Values in one term are ORed |
| `ecosystem:<sub>` (also `eco:`) | Case-insensitive substring of the ecosystem |
| `package:<sub>` (also `pkg:`) | Case-insensitive substring of the package name |
| `id:<sub>` | Case-insensitive substring of the OSV ID |
| `cve:<sub>` | Case-insensitive substring of any CVE ID |
| `source:<sub>` | Case-insensitive substring of the lockfile path |
| `fixed:true` / `fixed:false` | Findings with / without a fixed version |
| `<text>` (free text) | Case-insensitive substring of the search key |

- All terms are ANDed. An unknown key or unparsable value falls back to free text.
- Empty query: sort by severity desc → package name asc → ID asc. Results always keep this order (no relevance scoring).
- Filtering order: apply the key-binding filters (`ctrl+s` `ctrl+e` `ctrl+f`) first, then the query terms.
- Expected volume: a few hundred findings or fewer per repository (assumption). Recomputing everything on each keystroke is enough, so no index is built. If input lag appears above 1000 items, add a debounce (50ms).

### 10.4 Status display

| State | Display |
|---|---|
| Scanning | Spinner and "scanning…" in the header. If a cache exists, the list stays visible |
| 0 vulnerabilities | "No known vulnerabilities" in the center |
| No lockfiles | "No supported lockfiles found" and the list of target file names in the center |
| Error | Error details at the bottom. The list (from cache) stays visible |

## 11. CLI

```
scomp [flags] [path]
```

| Flag | Default | Description |
|---|---|---|
| `path` | `.` | Scan target. Normalized to the Git root |
| `--no-cache` | false | Do not read or write the cache |
| `--cache-ttl` | `24h` | Cache TTL |
| `--offline` | false | Use osv-scanner's offline DB (does not send dependency info externally) |
| `--scanner` | `lib` | `lib` / `exec` |
| `--json` | false | Do not start the TUI; print `[]Finding` as JSON to stdout (for tests / pipes) |
| `--version` | | Print version |

## 12. Directory layout

```
.
├── main.go                  # flag parsing and wiring of layers only
├── internal/
│   ├── repo/                # root detection, lockfile listing
│   ├── cache/               # key computation, read/write
│   ├── scanner/
│   │   ├── scanner.go       # interface
│   │   ├── exec.go          # osv-scanner exec implementation
│   │   ├── exec_parse.go    # JSON → model.Finding
│   │   └── lib.go           # library implementation (M5, default)
│   ├── model/               # Finding, Package, Severity
│   └── tui/
│       ├── model.go         # tea.Model
│       ├── update.go
│       ├── view.go
│       ├── search.go        # query parsing + filtering
│       └── styles.go
├── testdata/                # sample osv-scanner JSON output
├── DESIGN.md
└── README.md
```

## 13. Error handling

- On scan failure, show the error in the TUI, and keep showing cached content if available. Never silently show an empty list.
- Keep the full osv-scanner stderr so it can be viewed in the detail view.
- On cache corruption (JSON decode failure), print a warning, delete the cache, and rescan.

## 14. Security and privacy

- When online, osv-scanner sends package names, versions, and ecosystems (and in some cases file hashes) to osv.dev. For private repositories, internal package names leave the network. Document this in the README and point to `--offline` as the workaround.
- The exec implementation passes arguments as an array to `exec.CommandContext`. No shell is involved.
- Show the scanner in the header: the embedded osv-scanner version for lib, or the path resolved by `exec.LookPath` for exec (so the user notices if an unintended binary runs).
- Treat vulnerability Details as externally sourced strings and strip terminal control sequences before display.
- No credentials are handled.

## 15. Testing strategy

| Target | Method |
|---|---|
| `scanner/exec_parse.go` | Table-driven tests using JSON in `testdata/` as input |
| `cache` | Key computation, expiry, and corruption behavior using `t.TempDir()` |
| `tui/search.go` | Table-driven tests for filters and sort order |
| `tui` overall | Pass `tea.Msg` directly to `Update` and verify state transitions |
| Integration | Check `--json` output against a small sample repository (use `--offline` in CI; to verify: time to fetch the offline DB in CI) |

## 16. Milestones

| # | Scope | Estimate | Done when |
|---|---|---|---|
| M1 | model + exec impl + `--json` | 2 hours | `scomp --json` prints Findings as JSON |
| M2 | TUI list + query filter + detail pane | 4 hours | Typing a query in `scomp` narrows the list |
| M3 | Cache | 2 hours | Second launch shows results without scanning |
| M4 | Filters, `ctrl+o`, status display | 2 hours | All keys in §10.2 work |
| M5 | lib impl | 1 day | `--scanner=lib` prints the same JSON as M1 |
| M6 | GoReleaser / Homebrew tap | 2 hours | Installable via `brew install` |

Future considerations (after M6):

- Filter syntax inside the query (e.g. `sev:high eco:go net/http`)
- Reachability display via Go govulncheck integration
- Prioritization with CISA KEV / EPSS
- Cross-view of multiple worktrees

## 17. Open items (to verify)

| Item | How to confirm |
|---|---|
| osv-scanner v2 JSON structure and the max-severity field name | Run `--format json` against a real repository |
| osv-scanner v2 exit code definitions | Check official docs and source |
| Stability of the osv-scanner v2 library API | Check `v2/pkg/osvscanner` on `pkg.go.dev` and the CHANGELOG |
| Query performance | Measure filtering on 1000 findings per keystroke |
| Finalizing lockfile target file names | Cross-check against osv-scanner's supported lockfiles list |
