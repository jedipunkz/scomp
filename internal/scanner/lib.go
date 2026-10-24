package scanner

import (
	"context"
	"errors"

	"github.com/jedipunkz/scomp/internal/model"
)

// ErrLibNotImplemented is returned by Lib until milestone M5 is done.
var ErrLibNotImplemented = errors.New("--scanner=lib is not implemented yet; use --scanner=exec")

// Lib will call osv-scanner/v2/pkg/osvscanner directly (milestone M5).
type Lib struct{}

func (Lib) Scan(context.Context, string) ([]model.Finding, error) {
	return nil, ErrLibNotImplemented
}
