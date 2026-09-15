# Commit Guard

A GitHub Action that scans commits and pull requests for:

- 🔑 **Leaked secrets** (API keys, tokens, credentials) — via [gitleaks](https://github.com/gitleaks/gitleaks)
- 📦 **Vulnerable dependencies** — via [osv-scanner](https://github.com/google/osv-scanner)
- ⚠️ **Unsafe code patterns** (SQL injection, unsafe eval, weak crypto, etc.) — via [semgrep](https://semgrep.dev/)

Findings are posted as a PR comment and job summary, each with a suggested fix.

## Quick start

Add `.github/workflows/commit-guard.yml` to your repo — see
[`.github/workflows/example-usage.yml`](.github/workflows/example-usage.yml) for the full
version with the required setup steps (installing gitleaks/osv-scanner/semgrep).

## Inputs

| Input                  | Default        | Description                                          |
|-------------------------|----------------|-------------------------------------------------------|
| `github-token`           | `github.token` | Token used to post PR comments                       |
| `fail-on`                | `high`         | Minimum severity that fails the check: `high`\|`medium`\|`low`\|`none` |
| `enable-secrets-scan`    | `true`         | Toggle the secrets scanner                           |
| `enable-deps-scan`       | `true`         | Toggle the dependency scanner                        |
| `enable-pattern-scan`    | `true`         | Toggle the code pattern scanner                      |
| `comment-on-pr`          | `true`         | Post findings as a PR comment                        |

## Outputs

- `findings-count` — total findings across all scanners
- `high-severity-count` — count of high-severity findings

## Project layout

```
action.yml                    # Action metadata (inputs/outputs, entrypoint)
src/
  index.ts                    # Orchestrates scanners → fixes → report → PR comment
  types.ts                    # Shared Finding / FixSuggestion types
  scanners/
    secrets.ts                 # gitleaks wrapper
    deps.ts                     # osv-scanner wrapper
    patterns.ts                 # semgrep wrapper
  fixes/
    templates.ts                # Rule-based fix suggestions (no external calls)
    llm-fallback.ts              # Optional: Claude API fallback for novel findings
  report.ts                     # Markdown formatter for PR comment / job summary
.github/workflows/
  example-usage.yml              # Sample consumer workflow
```

## Development

```bash
npm install
npm run build   # bundles src/ → dist/index.js via @vercel/ncc, what the Action actually runs
npm test
```

Because GitHub Actions run the *bundled* `dist/index.js`, you must run `npm run build`
and commit the `dist/` folder (or build it in CI) before tagging a release.

## Design notes / next steps

- **Secrets scanner never surfaces raw matched text** — only file, line, and rule ID —
  so a leaked secret is never re-leaked into a PR comment.
- Fix suggestions are template-based by default (fast, free, deterministic). The
  `llm-fallback.ts` module is wired but not called by default — enable it in `index.ts`
  if you want more specific fixes for findings the templates only handle generically,
  and pass an `ANTHROPIC_API_KEY` as a workflow secret.
- Currently scans the whole working tree for deps/patterns and the push/PR commit range
  for secrets. For very large monorepos you may want to scope `osv-scanner`/`semgrep` to
  changed paths only — that's a good next optimization.
- No tests included yet in this scaffold — recommend adding fixture-based tests per
  scanner (feed a canned gitleaks/osv/semgrep JSON report in, assert the parsed `Finding[]`).
