// Package scanner finds known vulnerabilities in a repository's dependencies.
package scanner

import (
	"context"

	"github.com/jedipunkz/scomp/internal/model"
)

type Scanner interface {
	Scan(ctx context.Context, root string) ([]model.Finding, error)
}
