// Package migrations embeds SQL migration files for use in tests and tooling.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
