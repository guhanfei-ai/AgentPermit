// Package migrations exposes the SQL migration files embedded at build time.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
