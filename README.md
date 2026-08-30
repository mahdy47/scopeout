# scopeout

[![tests](https://github.com/mahdy47/scopeout/actions/workflows/tests.yml/badge.svg)](https://github.com/mahdy47/scopeout/actions/workflows/tests.yml)

**Engagement-state engine for penetration testing.**

`scopeout` is a purely organizational, decision-support tool that keeps the
state of your thinking during a pentest. It imports your recon, owns a live
model of **Asset → Service → Lead → Result → Coverage**, and tells you **what
to test next** — so you never repeat work, never miss a test, and don't have to
re-read scattered notes to remember where you left off two hours ago.

It does **not** execute attacks and does **not** depend on an LLM. It is a
local, deterministic planning and coverage tracker built in Python + SQLite.

---

## The problem it solves

During an engagement you have to decide, host-by-host:

> "What should I test next, and what have I already covered?"

The common workflow is: save an nmap scan, then cross-reference
HackTricks/checklists by hand, keep credentials/leads/hypotheses as mental +
note-app entries, and on report day re-read everything to rebuild the timeline.
`scopeout` replaces that loop with a live, per-asset investigation state and a
prioritized **NEXT LEADS** board.

```text
Nmap
   ↓
scopeout
   ↓                    ┌─────────────────────────────┐
   leads (decision)     │       10.10.10.25           │
   status (state)       │  22 SSH · 80 HTTP · 445 SMB │
   coverage (tested?)   └─────────────────────────────┘
```

---

## Installation

Requires Python 3.10+.

```bash
# from the project root
pip install -e .

# or run without installing
python -m scopeout --help
```

---

## Commands

| Command | Purpose |
| --- | --- |
| `scopeout import <nmap.xml>` | ingest an nmap `-oX` scan |
| `scopeout leads` | prioritized NEXT LEADS board |
| `scopeout coverage [host]` | coverage board per service |
| `scopeout done <host:port> <lead_id> [outcome] [evidence]` | close a lead + record result |
| `scopeout note <host:port> "text"` | add a note to a service |
| `scopeout obs <host:port> "text"` | add an observation to a service |
| `scopeout status [host]` | investigation tree for a host (or all) |
| `scopeout report [--output FILE]` | generate a Markdown engagement report |
| `scopeout creds` | credential-reuse suggestions (decision support) |
| `scopeout auth add <host:port> <user> <cred> [origin]` | record a credential |
| `scopeout auth list [host:port]` | list recorded credentials |

Global options: `--db PATH` (default `./scopeout.db`) and `--ascii` (force
ASCII glyphs instead of `✓`/`✗`; auto-detected on non-UTF-8 terminals).

---

## Example usage

### 1. Import a scan

```bash
$ scopeout import scans/nmap.xml
imported 2 assets, 5 services (seeded 13 coverage items, 6 leads)
  10.10.10.25        3 service(s)
  10.10.10.30        2 service(s)
```

Importing seeds each known service (SMB/HTTP/SSH) with a small methodology
coverage list and initial open leads, so the state is immediately usable.

### 2. Decision support — what to do next

```bash
$ scopeout leads
NEXT LEADS

[still has open leads]
  1. 10.10.10.25:22   SSH investigation   Reason: service still has open leads
  2. 10.10.10.25:80   Web investigation   Reason: service still has open leads
  3. 10.10.10.30:445  SMB enumeration     Reason: service still has open leads

[closed without a recorded result]
  4. 10.10.10.30:22   SSH investigation   Reason: no result recorded
```

Each service appears once, with a single dominant reason (`open-leads` /
`no-result` / `discovered-not-covered`) — clean, not a noisy checklist.

### 3. Focus on one host

```bash
$ scopeout status 10.10.10.25
10.10.10.25
===========
hostname: ws01.lab.local
os: Linux 4.15 - 5.8 (91%)

SMB enumeration :445
├── Leads
│   └── [DONE] 4 - Test SMB null session
│       └── result: guest login accepted
└── Coverage
    ✓ Null session test
    ✓ SMB signing check
    ✗ Share enumeration

Web investigation :80
├── Observations
│   ├── Apache detected
│   └── Interesting endpoint at /admin
└── Leads
    ├── [OPEN] 2 - Enumerate web application
    └── [OPEN] 3 - Check interesting paths
```

The tree surfaces lead **ids**, observations, and per-activity coverage, so
after hours away you can see exactly where a host was left.

### 4. Record state as you work

```bash
$ scopeout done 10.10.10.25:445 4 "guest login accepted" "smbclient -L //10.10.10.25"
lead 4 marked DONE: guest login accepted

$ scopeout obs 10.10.10.25:80 "Apache detected"
$ scopeout note 10.10.10.25:80 "Interesting endpoint at /admin"
```

### 5. Coverage board

```bash
$ scopeout coverage
10.10.10.25
-----------
  :22 (ssh)         0/2 covered
    [ ] Auth methods review
    [ ] Version / weak ciphers check
  :80 (http)        0/3 covered
    [ ] Fingerprint / headers
    [ ] Interesting paths / robots.txt
    [ ] Virtual host enumeration
  :445 (netbios-ssn) 1/3 covered
    [x] Null session test
    [x] SMB signing check
    [ ] Share enumeration
```

On torrents that support UTF-8 the marks render as `✓`/`✗`; otherwise they
automatically fall back to `[x]`/`[ ]` (or use `--ascii`).

---

## v2: Report builder & credential correlation

### 6. Generate an engagement report

`scopeout report` collects every recorded observation and result, keeps
timestamps and chronological order, and renders a clean professional Markdown
report organized by host → service → observations → findings. Evidence is
attached to every finding; nothing is invented.

```bash
$ scopeout report --output report.md        # write to a file
$ scopeout report                           # or print to stdout
```

```markdown
# Engagement Report

**Scope summary:** 2 host(s) in scope.

## Timeline
| Time | Host | Service | Event |
| --- | --- | --- | --- |
| 2026-08-30 17:33:41 | 10.10.10.25 | netbios-ssn :445 | [result] Test SMB null session: guest login accepted |

## 10.10.10.25
- **Hostname:** ws01.lab.local
- **OS:** Linux 4.15 - 5.8 (91%)

### SMB enumeration :445
#### Findings
##### Test SMB null session
**Status:** DONE
**Finding:** guest login accepted
**Observed:** ...
**Evidence:**
```text
smbclient -L //10.10.10.25
```
```

### 7. Credential correlation (decision support only)

Record where a credential was observed/tested:

```bash
$ scopeout auth add 10.10.10.25:445 "guest" "(blank password)" "smbclient -L"
recorded credential for guest (id 1) on 10.10.10.25:445

$ scopeout auth list
credentials (all services):
  [1] guest @ service 3 (id)  origin: smbclient -L
```

`scopeout creds` then suggests related services where the credential *might*
be reused — purely informational, never automated:

```bash
$ scopeout creds
CREDENTIAL REUSE (suggestions only - no automated checks)

Credential observed/tested on 10.10.10.25:445 (user: guest, service: netbios-ssn)
Potential related services:
- 10.10.10.30:445 (microsoft-ds)

Reason: the same service type exists on other discovered hosts.
```

> **Safety:** `scopeout` records relationships and surfaces suggestions only.
> It performs **no** automatic login, spraying, brute forcing, or any
> authentication attempt. Credentials shown in the generated report are
> redacted by default.

### v2 workflow at a glance

```
import scan → work through leads → done/obs/note/cover
        → auth add (record creds) → creds (reuse suggestions)
        → report --output report.md (hand-off to full reporting)
```

---

## Default methodology seeds

Each preset is intentionally small so it stays a decision support tool:

- **SMB (445)** — null session test, signing check, share enumeration
- **HTTP/HTTPS (80/443)** — fingerprint/headers, interesting paths, vhosts
  (+ TLS cert review for HTTPS)
- **SSH (22)** — version/weak ciphers, auth methods

Services with no preset are still tracked and show up as
`discovered-not-covered` until you investigate them.

---

## Development

```bash
# CLI-only test/development dependencies
pip install -e ".[dev]"

# Everything above PLUS the web/API layer (FastAPI, uvicorn)
pip install -e ".[dev,web]"

python -m pytest -q
```

## Web interface (read-only dashboard)

`scopeout` ships a **read-only** web dashboard and HTTP API that reuse the
same core engine as the CLI. The CLI remains fully functional and unchanged;
the web layer only adds request/response adapters around `scopeout.core`.

### Run locally

```bash
pip install -e ".[dev,web]"
python -m uvicorn api.index:app --reload
# open http://127.0.0.1:8000
```

### API endpoints (all read-only)

| Endpoint | Description |
| --- | --- |
| `GET /` | Dashboard (HTML) |
| `GET /api/health` | Service health + mode |
| `GET /api/hosts` | Hosts in scope (ip, hostname, OS, service count) |
| `GET /api/services` | Discovered services (`?asset_id=` filters by host) |
| `GET /api/leads` | Leads with host:port, status, reason, evidence |
| `GET /api/coverage` | Coverage items + tested/pending state |
| `GET /api/observations` | Observations / recon notes |
| `GET /api/credentials` | Credential **usernames only** — values always redacted |
| `GET /api/report` | The existing Markdown engagement report |
| `GET /api/summary` | Dashboard totals (hosts, leads, coverage progress) |

All endpoints map 1:1 onto core functions (`Store.list_*`, `planner.next_leads`,
`report.build_report`). No business logic is duplicated in the web layer.

### Persistence model — read-only snapshot

scopeout's core uses a local SQLite `Store`. Vercel serverless filesystems are
**ephemeral and non-persistent**, so a writable local SQLite file cannot persist
between invocations in production.

The web interface therefore serves a **read-only snapshot** seeded once from a
real dataset (`examples/sample.xml`) through the **same core importer** the CLI
uses. It is explicitly **not** a persistent, write-capable service:

- There are **no write/mutation endpoints** (no POST/PUT/DELETE).
- Nothing is written to the ephemeral filesystem, so nothing is silently lost.
- Credential values are redacted everywhere (matching the CLI report).

A write-persistent deployment would require an external database (e.g.
Vercel/Neon Postgres or Turso/libSQL) behind a `Store`-compatible adapter, plus
a `DATABASE_URL`-style secret. That is intentionally out of scope for this
read-only milestone.

### Deploy to Vercel

The repo already contains the required Vercel configuration (`api/index.py`,
`vercel.json`, `requirements.txt`, `.gitignore` ignores `.vercel/` and `.env`).

1. Push this branch/commit to GitHub.
2. In Vercel, **Import Project** → select `mahdy47/scopeout` (Framework Preset:
   *Other*). The Python function at `api/index.py` is auto-detected.
3. No secret env vars are required for the read-only snapshot. If you later add
   an external DB, add it as a Vercel Environment Variable (never commit it).

Alternatively, from a machine with Vercel auth:

```bash
vercel                      # link project
vercel --prod               # production deploy
```

## License

MIT
