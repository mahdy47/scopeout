# Changelog

All notable changes to `scopeout` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-08-30

### Added

- Read-only **web dashboard** (`scopeout.web` + Vercel serverless `api/index.py`)
  exposing the engagement state over a clean HTTP API:
  overview summary, hosts, services, leads, coverage, observations, report,
  and credentials (always redacted).
- **Report builder** (`build_report`) rendering a professional Markdown
  engagement report per host → service → observations → findings, with
  timestamps and evidence preserved.
- **Credential correlation** — suggests which existing credentials to try
  against unresolved open leads.
- **Methodology seeds** for common services (SSH, HTTP, SMB, MySQL) to bootstrap
  coverage from standard checklists.
- `docs/USAGE.md` — a beginner-friendly, full engagement walkthrough.
- `v2.0.0` git tag marking this release.

### Changed

- Refactored core into `core/` (importer, model, planner, presets, render,
  report, state) with the CLI as a thin adapter.
- Core/CLI logic remains **stdlib-only** (Python + SQLite); FastAPI/uvicorn are
  used only by the web layer.

### Security

- Web layer and reports apply **credential redaction** — raw credential values
  are never returned or written.
- The web layer is **read-only** and performs no shell / scan / auth execution.

### Fixed

- Import now rejects seed files whose content is a remote URL.
- Removed an unused variable shadowing the built-in `state` module during import.
- Dropped an invalid runtime entry from `vercel.json` and removed rewrites so the
  Vercel FastAPI preset routes original paths.
- Declared FastAPI/uvicorn as direct dependencies so the Vercel runtime installs them.
- Kept `vercel/.env` files out of git.
- Added Python 3.13 to the CI matrix and a `ruff check .` lint gate.
