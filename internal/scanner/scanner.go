// Package scanner finds known vulnerabilities in a repository's dependencies.
package scanner

import (
	"context"
	"errors"

	"github.com/jedipunkz/scomp/internal/model"
)

type Scanner interface {
	Scan(ctx context.Context, root string) ([]model.Finding, error)
}

// ErrNoPackages means the scanner found no supported lockfiles or packages.
var ErrNoPackages = errors.New("no supported lockfiles found")
