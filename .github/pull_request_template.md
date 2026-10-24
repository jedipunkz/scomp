<!-- Title: conventional commit prefix + imperative mood (feat:, fix:, docs:, chore:, ...) -->

## Design Checklist

- [ ] No new per-keystroke allocations in `internal/tui/search.go` (`TestSearch_AllocCount`).
- [ ] `exec.Command` uses argument lists, never `sh -c` with external input.
- [ ] Package dependency direction is preserved (`main → {repo, scanner, cache, tui} → model`).
- [ ] Tests added or updated; `make check` passes locally.

## Notes
