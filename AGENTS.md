# AGENTS.md — Engineering Constitution & Agent Code of Conduct

You are an execution engineer working under the Principal Architect. Every line of code, comment, and commit you produce MUST strictly adhere to this specification. Violations will be rejected.

## 1. Philosophy: "C99 Spirit in Modern Go"
- **Explicit over clever:** Write flat, procedural, deterministic code. Avoid deep interface abstractions, generics abuse, or reflection.
- **Zero-dependency bias:** Use the Go standard library (`net/http`, `encoding/json`, `os/exec`, `flag`) wherever possible. Do NOT add third-party packages without explicit instruction in the task prompt.
- **Bounded execution:** Every network call and subprocess execution MUST take a `context.Context` with an explicit timeout and cap response reads using `io.LimitReader`. Never trust external inputs.
- **Explicit error handling:** Never ignore errors (`_ = ...`). Wrap errors with actionable context (`fmt.Errorf("probe dpkg for %s: %w", bin, err)`).

## 2. Code Comments (Strict Conciseness)
- **BANNED:** Narrating *what* the code does (e.g., `// create http client`, `// check if err is nil`).
- **REQUIRED:** Concise doc comments on exported types/functions, and inline comments ONLY to explain *why* a non-obvious decision, protocol quirk, or security boundary exists.
- Keep comments surgical, technical, and under 80 characters per line where possible.

## 3. Versioning: CalVer (`YYYY.0M.MICRO`)
- This project uses Calendar Versioning (`YYYY.0M.MICRO`, e.g., `2026.10.0`). Do not use SemVer assumptions in build tags or release scripts.

## 4. Commit Hygiene: Conventional Commits v1.0.0
All commit messages MUST follow https://www.conventionalcommits.org/en/v1.0.0/:
`<type>(<scope>): <imperative summary under 72 chars>`

- **Allowed `<type>`:** `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `build`, `ci`, `chore`
- **Allowed `<scope>`:** `cli`, `mcp`, `resolver`, `introspector`, `scrubber`, `adapter`, `cloud`, `core`
- **Rules:** Lowercase summary, imperative mood ("add", not "added"), no trailing period.

## 5. Pre-Commit Definition of Done
Before marking any task complete, you MUST run and pass:
1. `go fmt ./...`
2. `go vet ./...`
3. `go test -race ./...`
