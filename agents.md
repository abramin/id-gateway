AGENTS.md
Dev environment tips

Use go mod tidy after adding or removing imports to keep modules clean.

Run go work use ./... if you're working with a multi-module workspace.

Use make dev (or whatever wrapper you add) to start the server with live reload via air or fresh.

To navigate quickly, use grep -R "<symbol>" ./internal or go to definition in your editor.

Keep tools updated: go install golang.org/x/tools/...@latest, go install github.com/cosmtrek/air@latest.

Code style tips

Handlers should stay thin: decode input → call service → encode output.

Services contain business logic; do not put logic in HTTP handlers.

Stores use small interfaces and return typed errors.

Prefer returning structs, not pointers, unless mutation or nil has meaning.

One package per responsibility: http, domain, storage, registry, vc, audit.

Testing instructions

Run go test ./... from the repo root before every commit.

To run only one package: go test ./internal/<package>.

To run a single test: go test -run "<TestName>" ./internal/<package>.

Use table tests for variants; use BDD-style naming for behaviours.

Add tests whenever you touch a service or data structure.

Avoid sleeps in tests; use fake clocks or deterministic inputs.

Use t.Helper() in shared test functions.

Linting & formatting

Always run go fmt ./... before committing.

Use golangci-lint run if you add a linter config (recommended).

Fix import ordering with goimports -w . if needed.

PR instructions

Title format: [go] <summary>

Must pass: go fmt, go vet, go test ./....

Keep diffs small and scoped to one logical change.

Include tests for new behaviour; update tests if behaviour changes.

Avoid mixing refactors with feature changes.
