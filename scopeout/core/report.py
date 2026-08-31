"""Markdown report builder (v2).

`build_report(store)` collects every recorded Observation and Result (with the
lead context that produced each Result) and renders a clean, professional
Markdown report organized by host -> service -> observations -> findings, with
timestamps preserved and evidence referenced. It never invents findings or
evidence; it only reflects what is stored.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .model import LeadStatus, Store
from .planner import _service_display


def _fmt_ts(ts: str | None) -> str:
    """Return a human-friendly timestamp or 'n/a'."""
    if not ts:
        return "n/a"
    return str(ts).replace("T", " ")[:19]


def _md_single_line(text: str) -> str:
    """Collapse whitespace/newlines so a value renders on one line.

    Used for bullet and inline contexts where a raw newline would break the
    Markdown structure (observations, finding outcomes, table cells).
    """
    return " ".join(str(text).split())


def _md_table_cell(text: str) -> str:
    """Make a value safe to embed in a Markdown table cell.

    Escapes the pipe character (which would otherwise split the cell) and
    collapses newlines so the row stays on a single physical line.
    """
    return _md_single_line(text).replace("|", r"\|")


def build_report(store: Store) -> str:
    """Generate the full Markdown report as a string."""
    assets = store.list_assets()
    out: list[str] = []

    out.append("# Engagement Report")
    out.append("")
    out.append(f"_Generated on {datetime.now(tz=timezone.utc).date().isoformat()}_")
    out.append("")
    out.append(f"**Scope summary:** {len(assets)} host(s) in scope.")
    out.append("")

    if not assets:
        out.append("No engagement data has been captured yet. Import a scan "
                   "and record results to build a report.")
        return "\n".join(out)

    # ---- global chronological timeline -----------------------------------
    timeline = _build_timeline(store, assets)
    if timeline:
        out.append("## Timeline")
        out.append("")
        out.append("Chronological record of observations and results across "
                   "the engagement.")
        out.append("")
        out.append("| Time | Host | Service | Event |")
        out.append("| --- | --- | --- | --- |")
        for event in timeline:
            ts = _fmt_ts(event["ts"])
            out.append(
                f"| {ts} | {_md_table_cell(event['ip'])} | "
                f"{_md_table_cell(event['service'])} | "
                f"{_md_table_cell(event['text'])} |"
            )
        out.append("")

    # ---- per-host detail -------------------------------------------------
    for asset in assets:
        out.extend(_render_host(store, asset))

    return "\n".join(out)


def _build_timeline(store: Store, assets) -> list[dict]:
    """Collect observations + results into a global chronological list."""
    events = []
    for asset in assets:
        for svc in store.list_services(int(asset.id)):
            svc_label = f"{svc.name or 'unknown'} :{svc.port}"
            for obs in store.list_observations(int(svc.id)):
                events.append({
                    "ts": obs.created_at or "",
                    "ip": asset.ip,
                    "service": svc_label,
                    "text": obs.text,
                })
            for lead in store.list_leads(int(svc.id)):
                for res in store.list_results(int(lead.id)):
                    # Only surface results that made it into the report as
                    # findings; keep the event concise here.
                    events.append({
                        "ts": res.created_at or "",
                        "ip": asset.ip,
                        "service": svc_label,
                        "text": f"[result] {lead.title}: {res.outcome}",
                    })
    events.sort(key=lambda e: e["ts"])
    return events


def _render_host(store: Store, asset) -> list[str]:
    out = [
        f"## {asset.ip}",
        "",
    ]
    if asset.hostname:
        out.append(f"- **Hostname:** {_md_single_line(asset.hostname)}")
    if asset.os:
        out.append(f"- **OS:** {_md_single_line(asset.os)}")
    out.append("")

    services = store.list_services(int(asset.id))
    if not services:
        out.append("_No services recorded for this host._")
        out.append("")
        return out

    for svc in services:
        out.append(
            f"### {_md_single_line(_service_display(svc.name))} :{svc.port}"
        )
        out.append("")
        if svc.version:
            out.append(f"- **Version:** {_md_single_line(svc.version)}")
        if svc.banner:
            out.append(f"- **Banner:** {_md_single_line(svc.banner)}")
        out.append("")

        # Observations
        observations = store.list_observations(int(svc.id))
        if observations:
            out.append("#### Observations")
            out.append("")
            for obs in observations:
                out.append(
                    f"- ({_fmt_ts(obs.created_at)}) "
                    f"{_md_single_line(obs.text)}"
                )
            out.append("")

        # Findings: results on DONE/BLOCKED leads, with evidence
        findings = _collect_findings(store, int(svc.id))
        if findings:
            out.append("#### Findings")
            out.append("")
            for f in findings:
                out.append(f"##### {_md_single_line(f['title'])}")
                out.append("")
                out.append(f"**Status:** {_md_single_line(f['status'])}")
                out.append("")
                out.append(f"**Finding:** {_md_single_line(f['outcome'])}")
                out.append("")
                if f["observed_at"]:
                    out.append(f"**Observed:** {_fmt_ts(f['observed_at'])}")
                    out.append("")
                if f["evidence"]:
                    out.append("**Evidence:**")
                    out.append("")
                    out.append("```text")
                    out.append(f["evidence"])
                    out.append("```")
                    out.append("")

        # Credentials observed/tested on this service
        credentials = store.list_credentials(int(svc.id))
        if credentials:
            out.append("#### Credentials")
            out.append("")
            out.append("| Username | Credential | Origin |")
            out.append("| --- | --- | --- |")
            for cred in credentials:
                # keep raw credential out of the report body in case it is
                # sensitive; render only username + origin reference.
                marker = f"`{_md_table_cell(cred.username)}`"
                origin = _md_table_cell(cred.origin) if cred.origin else "observed here"
                out.append(f"| {marker} | *redacted* | {origin} |")
            out.append("")

    return out


def _collect_findings(store: Store, service_id: int) -> list[dict]:
    """Return report findings (results on non-OPEN leads) in chronological order."""
    findings = []
    for lead in store.list_leads(service_id):
        if lead.status == LeadStatus.OPEN:
            continue  # open leads are not findings yet
        for res in store.list_results(int(lead.id)):
            findings.append({
                "title": lead.title,
                "status": lead.status.value,
                "outcome": res.outcome,
                "evidence": res.evidence,
                "observed_at": res.created_at or "",
            })
    findings.sort(key=lambda f: f["observed_at"])
    return findings
