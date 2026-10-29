// Package scanner finds known vulnerabilities in a repository's dependencies.
package scanner

import (
	"context"

	"github.com/jedipunkz/scomp/internal/model"
)

type Scanner interface {
	Scan(ctx context.Context, root string) ([]model.Finding, error)
}

// excludeTestdata skips directories named testdata at any depth. They hold
// test fixtures (Go never builds them), often pinned to vulnerable versions
// on purpose. osv-scanner resolves a plain dir name against the working
// directory, so a regex on the root-relative path is used instead.
const excludeTestdata = "r:(^|/)testdata$"
