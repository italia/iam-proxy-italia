# Contributing to IAM Proxy Italia

Thank you for your interest in contributing.

## Documentation

When updating or adding documentation:

- **Internal links**: Verify that links to other docs (e.g. `docs/setup.md`, `docs/TROUBLESHOOTING.md`) point to existing files and that anchor fragments (e.g. `#configuration-by-environment-variables`) match the target headings (GitHub-style anchors are lowercase with hyphens).
- **Index**: When adding new files under `docs/`, add them to [docs/README.md](docs/README.md).
- **Versions**: When mentioning Python, SATOSA, or other dependency versions, prefer referencing [pyproject.toml](pyproject.toml) (`requires-python`, `dependencies`, `[project.optional-dependencies]`) to avoid drift.
- **Code blocks**: Use explicit language in fenced blocks (e.g. ` ```bash `, ` ```yaml `) for syntax highlighting and accessibility.

Before a release, a quick checklist: internal links verified, docs index up to date, version references consistent with pyproject.toml.

## CI

- Markdown link check runs on `README*.md` and `docs/*.md` (see [.github/workflows/docs-link-check.yml](.github/workflows/docs-link-check.yml)). Fix or exclude any reported broken links.
