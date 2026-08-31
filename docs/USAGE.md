# Using ScopeOut — a practical getting-started guide

This guide walks a new operator through the full, real workflow of using
`scopeout` during an **authorized** penetration test or a dedicated lab box you
own or have written permission to target.

ScopeOut is a **local, deterministic planning and coverage tracker** (Python +
SQLite). It imports the output of your recon tools, keeps a live model of
**Asset → Service → Lead → Result → Coverage**, and tells you **what to test
next**. It does **not** execute attacks and does not run an LLM.

> **Authorization.** Only ever run the tools shown below against systems you are
> explicitly authorized to test. This guide uses fictional lab IPs such as
> `192.168.56.10`; replace them with your own authorized targets or the
> placeholders `<TARGET>` / `<PORT>`.

---

## Table of contents

1. [Installation](#1-installation)
2. [Start an engagement](#2-start-an-engagement)
3. [Import Nmap results](#3-import-nmap-results)
4. [Understand leads](#4-understand-leads)
5. [Perform investigation outside ScopeOut](#5-perform-investigation-outside-scopeout)
6. [Record observations / evidence](#6-record-observations--evidence)
7. [Coverage](#7-coverage)
8. [Credential correlation](#8-credential-correlation)
9. [Planning / next steps](#9-planning--next-steps)
10. [Reporting](#10-reporting)
11. [Web dashboard](#11-web-dashboard)
12. [Complete example workflow](#12-complete-example-workflow)
13. [Troubleshooting](#13-troubleshooting)
14. [Command reference](#14-command-reference)

---

## 1. Installation

### Requirements

* **Python 3.10 or newer** (`requires-python = ">=3.10"`).
* An [Nmap](https://nmap.org/) binary to create scan XML (the only scan format
  ScopeOut imports). You can also start from an existing `-oX` file.

### Create a virtual environment and install ScopeOut

Clone the repository, then create and activate a virtual environment:

```bash
git clone <your-scopeout-repo-url>
cd scopeout

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate

# Windows (PowerShell)
# python -m venv .venv
# .\.venv\Scripts\Activate.ps1
```

Install ScopeOut in editable mode with the CLI + test dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

### Verify the CLI

```bash
scopeout --help
```

You should see the command list (import, leads, coverage, done, note, obs,
status, report, creds, auth). If `scopeout` is not on your `PATH`, you can run
the same CLI without installing an entry point:

```bash
python -m scopeout --help
```

Both forms are equivalent. This guide uses the `scopeout` form.

---

## 2. Start an engagement

ScopeOut is an **organizational / decision-support** tool. Knowing what it is
NOT is as important as knowing what it is.

**What ScopeOut does:**
* Imports and organizes your reconnaissance results (currently Nmap `-oX` XML).
* Tracks hosts (assets), services, leads, observations, coverage, and findings.
* Presents a prioritized "what should I test next" board.
* Generates a professional Markdown report from what you recorded.

**What ScopeOut does NOT do:**
* Nmap, Gobuster, and your other tools perform the actual reconnaissance. ScopeOut
  only imports and organizes their output.
* It does not run scans, start brute force, spray passwords, execute exploits, or
  authenticate anywhere.
* It does not replace your reconnaissance tooling — it replaces the "which host do
  I tackle next / what did I already cover" notebook loop.

Think of the pipeline this way:

```text
Nmap / Gobuster / curl / ...   (your tools: do the actual testing)
           |
           v
     ScopeOut                   (imports, tracks, plans, reports)
```

Create a fresh database (the default is `./scopeout.db` in your current
directory) simply by running the first command that reads or writes it. There
is no separate "new engagement" command — a new empty database is a new
engagement.

```bash
scopeout status            # empty store -> prints nothing yet; creates scopeout.db
```

---

## 3. Import Nmap results

Run Nmap with XML output, then import the file:

```bash
nmap -sV -oX scan.xml <AUTHORIZED_TARGET>
scopeout import scan.xml
```

`-oX` writes XML, which is the format ScopeOut understands. Example output:

```text
imported 2 assets, 5 services (seeded 13 coverage items, 6 leads)
  10.10.10.25        3 service(s)
  10.10.10.30        2 service(s)
```

**What ScopeOut creates from the import:**

* one **asset (host)** per alive host (IP, hostname, OS);
* one **service** per open TCP port;
* a small, per-service **coverage** checklist based on the service type
  (SMB/HTTP/SSH presets);
* initial **leads** — investigation tasks it thinks are worth checking.

Freshly imported known services (SMB/HTTP/SSH) are seeded with methodology
coverage and open leads, so the state is immediately usable. Unknown service
types are still tracked and flagged as `discovered-not-covered`.

**Inspect the state:**

```bash
scopeout status                 # investigation tree for every host
scopeout status 192.168.56.10   # investigation tree for one host
scopeout coverage               # coverage board for all hosts
scopeout leads                  # what you should look at next
```

---

## 4. Understand leads

A **lead** is a suggested investigation task attached to a service. ScopeOut
creates leads so you have a concrete checklist per service and can record the
outcome of each one. A `status` view can look like this:

```text
192.168.100.7
=============
Web investigation :5357
├── Leads
│   ├── [OPEN] 1 - Enumerate web application
│   └── [OPEN] 2 - Check interesting paths
└── Coverage
    ✗ Fingerprint / headers
    ✗ Interesting paths / robots.txt
    ✗ Virtual host enumeration
```

Here:

* `[OPEN]` means the lead is **still to be investigated**. A lead marked
  `[DONE]` has been worked and its outcome recorded with `scopeout done`; a
  `[BLOCK]` lead is one you flagged as blocked.
* A lead **represents a task you should verify manually** (e.g. "Enumerate web
  application").
* ScopeOut creates leads because it recognizes a service type and knows which
  checks are usually relevant.
* Leads are **investigation tasks**, not automatically executed exploits — and
  not findings. Nothing is executed on your behalf. You investigate, then record
  the outcome.

---

## 5. Perform investigation outside ScopeOut

For each open lead, use the appropriate **authorized tool** yourself. For
example, for a web service identified by a lead on `<TARGET>:<PORT>`:

```bash
# Grab headers to fingerprint the service
curl -I http://<TARGET>:<PORT>

# Enumerate interesting paths/directories
gobuster dir -u http://<TARGET>:<PORT> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Replace `<TARGET>` / `<PORT>` with your real authorized target and port. The
point is: **you do the investigation with your normal tools**. Then you bring the
findings back into ScopeOut so the state and the final report stay complete.

---

## 6. Record observations / evidence

ScopeOut provides two ways to attach free text to a service: `note` and `obs`.
They behave identically on disk (both store an Observation); use whichever reads
better to you. Record what you actually saw during your authorized testing.

```bash
scopeout obs  192.168.56.10:80  "Apache httpd 2.4.41 (Ubuntu)"
scopeout note 192.168.56.10:80  "Interesting endpoint discovered at /admin"
```

When you finish investigating a lead, close it and record the outcome and the
evidence that supports it:

```bash
scopeout done 192.168.56.10:445 4 "guest login accepted" "smbclient -L //192.168.56.10 -U guest"
```

`done` takes `<host:port> <lead_id> [outcome] [evidence]`. The `lead_id` is the
number shown by `scopeout status` (e.g. the `4` in `[OPEN] 4 - Test SMB null
session`). The outcome defaults to `checked, see evidence` if you omit it. The
evidence is the command or output that supports the finding, and it is preserved
verbatim in the report.

> **Never record an assumption as a finding.** If you did not observe it, either
> record it as a note/hypothesis (`note`) or leave the lead open. Only close a
> lead as `DONE` with an outcome you can support with evidence you collected.

---

## 7. Coverage

The coverage board shows, per service, the methodology checklist items and
whether each has been tested (`✓`/`[x]`) or not (`✗`/`[ ]`):

```bash
scopeout coverage
```

```text
[still has open leads]
192.168.100.7
-------------
  :5357 (http) 0/3 covered
    ✗ Fingerprint / headers
    ✗ Interesting paths / robots.txt
    ✗ Virtual host enumeration
```

**What the marks mean:**

* `✗` (or `[ ]` with `--ascii`, or when your terminal cannot render UTF-8) — this
  methodology item is **pending**, not yet tested.
* `✓` (or `[x]`) — this item has been marked **tested**.

The marks are auto-detected from your terminal; use `--ascii` to force the
ASCII forms.

ScopeOut tracks a coverage item's tested state in its `Coverage` record
(the `set_coverage` library operation). The CLI exposes the **board for viewing**
(`scopeout coverage [host]`) and drives engagement state through the workflow
commands above (`import`, `done`, `obs`, `note`, `status`). There is no separate
CLI flag to flip a coverage checkbox; the way you advance coverage is to work the
leads for a service and record the results with `scopeout done` — the picture you
see in both `coverage` and `status` reflects the recorded state. A service whose
coverage is complete and whose leads are resolved drops off the "next leads" board.

---

## 8. Credential correlation

Credential handling is **decision support only**. Record where you observed (or
successfully tested) a credential:

```bash
scopeout auth add 192.168.56.10:445 "guest" "(blank password)" "smbclient -L"
```

```text
recorded credential for guest (id 1) on 192.168.56.10:445
```

List what is recorded:

```bash
scopeout auth list                # all recorded credentials
scopeout auth list 192.168.56.10:445   # credentials for one service
```

And see reuse suggestions:

```bash
scopeout creds
```

**What this feature is — and is not:**

* It **records credentials discovered by the operator** and where they were tested.
* It does **not** authenticate to any service.
* It does **not** perform password spraying.
* It does **not** brute force.
* It does **not** automatically test credentials.
* `scopeout creds` returns purely informational suggestions ("the same service
  type exists on another host") — you decide whether to try anything, with your
  own tools, under your authorization, on your own time.
* **Credential values are redacted** in the generated report and in the web
  output — only the username and origin are shown.

If no credentials are recorded, `scopeout creds` reports:
`No credential-reuse candidates found. Record credentials with scopeout auth add to surface related services.`

---

## 9. Planning / next steps

The planner is the "what should I investigate next" brain. It produces one
entry per service with a single, dominant reason, ordered by priority:

```bash
scopeout leads
```

```text
[still has open leads]
  1. 192.168.56.10:80   Web investigation   Reason: service still has open leads
  2. 192.168.56.10:445  SMB enumeration     Reason: service still has open leads

[closed without a recorded result]
  3. 192.168.56.10:22   SSH investigation   Reason: no result recorded

[discovered but not covered]
  4. 192.168.56.10:3306 Database             Reason: discovered but not covered
```

Priorities: **open leads** (work in progress) come first, then services
**closed without a recorded result**, then services **discovered but not
covered**. Each service appears at most once, so the board stays clean rather
than a noisy checklist. When a service has no open leads, a recorded result, and
full coverage, it drops off the board; an empty board means you are fully
covered.

---

## 10. Reporting

Generate the engagement report:

```bash
scopeout report                    # print Markdown to stdout
scopeout report --output report.md # write to a file
# alias: scopeout report -o report.md
```

The report is organized **host → service → observations → findings**, plus a
global chronological timeline:

```text
Host
 └── Service
      ├── Observations
      └── Findings
```

* **Timeline** — a chronological table of every observation and result across the
  engagement, so you get an audit trail of *when* things were recorded.
* **Observations** — each with its timestamp.
* **Findings** — each closed (non-open) lead's recorded result, with the finding
  outcome, when it was observed, and the supporting **evidence** command/output
  preserved verbatim.
* **Credentials** — rendered as a table where the credential column always shows
  `*redacted*`; only username and origin are shown.

If there is no data yet, the report notes: *No engagement data has been captured
yet. Import a scan and record results to build a report.* Nothing is invented —
the report only reflects what you recorded.

---

## 11. Web dashboard

There is a deployed, **read-only** companion dashboard:

```text
https://scopeout-virid.vercel.app
```

Important properties of the current deployment:

* **Read-only** — there are no write/mutation endpoints (no POST/PUT/DELETE).
* **Snapshot-based** — it serves a one-time snapshot seeded from the repository's
  `examples/sample.xml` through the same core importer the CLI uses. It is
  **not** a persistent engagement database.
* **Intended for visualization / demo** — it reuses the same core engine as the
  CLI to visualize the model, not to manage real engagements.
* **Credentials are redacted** there, matching the CLI report behavior.

To run the dashboard locally:

```bash
python -m pip install -e ".[dev,web]"
python -m uvicorn api.index:app --reload
# open http://127.0.0.1:8000
```

> The **local CLI remains the primary way to manage an engagement.** The web
> dashboard is a visualization of a snapshot — it will not reflect the contents
> of your local `scopeout.db`, and it is not where you record findings.

---

## 12. Complete example workflow

A full end-to-end pass against a **fictional lab target** (`192.168.56.10`):

```text
Nmap
  ↓
scan.xml
  ↓
scopeout import
  ↓
inspect hosts/services
  ↓
review leads
  ↓
perform authorized investigation
  ↓
record observations/evidence
  ↓
update coverage
  ↓
review planner
  ↓
generate report
```

```bash
# 1. Recon with your own tool
nmap -sV -oX scan.xml 192.168.56.10

# 2. Import
scopeout import scan.xml

# 3. Inspect
scopeout status
scopeout coverage

# 4. Review leads
scopeout leads

# 5. Investigate (your tooling, authorized target)
curl -I http://192.168.56.10:80
gobuster dir -u http://192.168.56.10:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# 6. Record observations / evidence
scopeout obs  192.168.56.10:80 "Apache httpd exposes a directory listing at /files"
scopeout done 192.168.56.10:80 2 "interesting paths enumerated" "gobuster dir -u ... -w ..."

# 7. Coverage picture now reflects tested items
scopeout coverage

# 8. Planner shows what is left
scopeout leads

# 9. Report
scopeout report --output report.md
```

Always substitute `192.168.56.10`, the ports, and the lead ids with your own
authorized environment and the actual ids shown by `scopeout status`. **Do not
test systems you are not authorized to target.**

---

## 13. Troubleshooting

**`scopeout: command not found`**
The package entry point is not on your `PATH`. Either activate your virtual
environment (which creates `scopeout` as a script) or run `python -m scopeout`
instead.

**`scopeout: no such file: <path>``**
`scopeout import` could not find the XML file. Check the path: it is relative to
your current directory.

**Incorrect XML path / "no such file"**
Make sure the argument points at the actual `-oX` XML output, e.g.
`scopeout import scans/nmap.xml`. Rerun Nmap with `-oX` if you only saved text
output (`-oN`) — only the XML form is imported.

**Virtual environment not activated**
You still see your system Python or the install did not take effect. Activate
the venv first (`source .venv/bin/activate` or
`.\.venv\Scripts\Activate.ps1`), then reinstall: `python -m pip install -e ".[dev]"`.

**Vercel dashboard showing snapshot data**
That is expected. The deployed dashboard serves a fixed snapshot from
`examples/sample.xml`; it is read-only and does not reflect your local database.
Use the local CLI (`scopeout`) to manage a real engagement.

**Empty engagement / database**
`scopeout status`, `scopeout leads`, `scopeout coverage`, or the report show no
data. You have not imported a scan yet (or you pointed at a different `--db` and
the database is empty). Run `scopeout import <your.xml>` first. If you are not
on the expected database, pass `--db <path>` to select the one you want.

**`[-] no asset with ip ...` (or similar)**
You referenced a host or `host:port` that is not in the store — usually a typo,
or the scan for that host was not imported. Confirm the IP with `scopeout status`.

---

## 14. Command reference

Every command below exists in `scopeout/cli.py`; examples match the implemented
behavior.

| Command | Purpose | Example |
| --- | --- | --- |
| `import <nmap.xml>` | Ingest an Nmap `-oX` scan | `scopeout import scan.xml` |
| `leads` | Prioritized "what next" board | `scopeout leads` |
| `coverage [host]` | Coverage board per service (view) | `scopeout coverage 192.168.56.10` |
| `done <host:port> <lead_id> [outcome] [evidence]` | Close a lead + record result | `scopeout done 192.168.56.10:445 4 "guest login accepted" "smbclient -L"` |
| `obs <host:port> "text"` | Add an observation to a service | `scopeout obs 192.168.56.10:80 "Apache 2.4.41"` |
| `note <host:port> "text"` | Add a note to a service | `scopeout note 192.168.56.10:80 "endpoint /admin"` |
| `status [host]` | Investigation tree (host or all) | `scopeout status 192.168.56.10` |
| `report [--output FILE]` | Generate Markdown report (`-o` alias) | `scopeout report --output report.md` |
| `creds` | Credential-reuse suggestions (info only) | `scopeout creds` |
| `auth add <host:port> <user> <cred> [origin]` | Record a credential | `scopeout auth add 192.168.56.10:445 guest "(blank)" "smbclient -L"` |
| `auth list [host:port]` | List recorded credentials | `scopeout auth list 192.168.56.10:445` |

**Global options** (place before the subcommand):

* `--db PATH` — SQLite database file (default `./scopeout.db`).
* `--ascii` — force ASCII glyphs (`[x]`/`[ ]`) instead of `✓`/`✗`.

Example:

```bash
scopeout --db engagements/lab-a.db --ascii status
```

**CLI-only notes:**

* There is no separate "new engagement" command — a new empty database is a new
  engagement.
* `coverage` is a display command; advance coverage by working leads and
  recording results with `done`.
* Credentials are **never** returned in full by the report/web output — only
  username and origin (report shows `*redacted*`).

That's everything you need to import a scan, work through leads, record findings,
and hand off a clean report.
