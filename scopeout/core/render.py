"""Rendering for the CLI (M3/M4).

- render_leads(): the NEXT LEADS board, one prioritized entry per service.
- render_status(): the per-host investigation tree
  (Observations / Leads / Coverage).

Glyph handling (M4): the status tree normally uses Unicode box-drawing and
check/cross marks (✓/✗). On terminals that don't render/can't encode UTF-8, an
ASCII fallback is available (ASCII_MARKS). The CLI decides which set to use via
auto-detection or an explicit --ascii flag.
"""

from __future__ import annotations

import shutil
import sys
from typing import Optional

from .model import LeadStatus, Store

# Board grouping / order for reasons (visual order, not priority math).
_REASON_GROUP_LABEL = {
    "open-leads": "still has open leads",
    "no-result": "closed without a recorded result",
    "discovered-not-covered": "discovered but not covered",
}

# --- glyph sets --------------------------------------------------------------

UNICODE_MARKS = {
    "done": "✓",
    "notdone": "✗",
    "branch": "├──",
    "branch_leaf": "│   ",
    "leaf": "└──",
    "last": "    ",
    "vcross": "│   ",
}

ASCII_MARKS = {
    "done": "[x]",
    "notdone": "[ ]",
    "branch": "+--",
    "branch_leaf": "|   ",
    "leaf": "`--",
    "last": "    ",
    "vcross": "|   ",
}


def supports_unicode() -> bool:
    """Best-effort check whether the current terminal renders UTF-8 marks.

    Returns False on Windows consoles (cp1252 default) or when stdout encoding
    cannot represent the check/cross glyphs.
    """
    try:
        enc = (sys.stdout.encoding or "").lower()
        if enc and "utf" in enc:
            return True
        # Ask the codec directly whether it can encode the marks.
        _ = "✓✗".encode(sys.stdout.encoding or "ascii")
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def _svc_display(name: str) -> str:
    from .planner import _service_display

    return _service_display(name)


# --- leads board -------------------------------------------------------------


def render_leads(leads, show_reason_detail: bool = False) -> str:
    """Render the NEXT LEADS board from a list of NextLead objects."""
    if not leads:
        return "No open next leads - engagement state is fully covered."

    lines = ["NEXT LEADS", ""]

    # group by reason for a clean, non-noisy layout
    from collections import OrderedDict

    groups: "OrderedDict[str, list]" = OrderedDict()
    for n in leads:
        groups.setdefault(n.reason_key, []).append(n)

    counter = 1
    for reason_key, group in groups.items():
        header = _REASON_GROUP_LABEL.get(reason_key, reason_key)
        lines.append(f"[{header}]")
        for n in group:
            detail = f"  ({n.detail})" if show_reason_detail and n.detail else ""
            lines.append(
                f"  {counter}. {n.ip}:{n.port}  {n.display}"
                f"   Reason: {n.reason_label}{detail}"
            )
            counter += 1
        lines.append("")

    return "\n".join(lines).rstrip()


# --- status tree -------------------------------------------------------------


def render_status(store: Store, asset, marks: Optional[dict] = None) -> str:
    """Render the investigation tree for one asset (host).

    `marks` selects the glyph set; defaults to UNICODE_MARKS (callers that need
    portability should pass ASCII_MARKS or a mixed set).
    """
    marks = marks or UNICODE_MARKS
    done = marks["done"]
    notdone = marks["notdone"]
    branch = marks["branch"]
    bl = marks["branch_leaf"]
    leaf = marks["leaf"]
    last = marks["last"]
    vcross = marks["vcross"]

    lines = [f"{asset.ip}", "=" * len(asset.ip)]
    if asset.hostname:
        lines.append(f"hostname: {asset.hostname}")
    if asset.os:
        lines.append(f"os: {asset.os}")
    lines.append("")

    services = store.list_services(int(asset.id))
    for idx, svc in enumerate(services):
        is_last = idx == len(services) - 1
        root = leaf if is_last else branch
        lines.append(f"{root} {_svc_display(svc.name)} :{svc.port}")

        # Observations (recon findings / notes)
        observations = store.list_observations(int(svc.id))
        if observations:
            lines.append(f"{bl} Observations")
            n = len(observations)
            for j, o in enumerate(observations):
                if j == n - 1:
                    lines.append(f"{bl}{leaf} {o.text}")
                else:
                    lines.append(f"{bl}{branch} {o.text}")

        # Leads
        leads = store.list_leads(int(svc.id))
        if leads:
            lines.append(f"{bl} Leads")
            done_results = {}
            for l in leads:
                if l.status == LeadStatus.DONE:
                    res = store.list_results(int(l.id))
                    done_results[int(l.id)] = res[-1].outcome if res else None
            n = len(leads)
            for j, l in enumerate(leads):
                marker = {
                    LeadStatus.OPEN: "[OPEN]",
                    LeadStatus.DONE: "[DONE]",
                    LeadStatus.BLOCKED: "[BLOCK]",
                }[l.status]
                line = f"{bl}{leaf if j == n - 1 else branch} {marker} {l.id} - {l.title}"
                lines.append(line)
                has_result = l.status == LeadStatus.DONE and done_results.get(int(l.id))
                if has_result:
                    lines.append(
                        f"{bl}{last if j == n - 1 else vcross}{leaf}"
                        f" result: {done_results[int(l.id)]}"
                    )

        # Coverage
        coverage = store.list_coverage(int(svc.id))
        if coverage:
            lines.append(f"{bl} Coverage")
            for c in coverage:
                mark = done if c.tested else notdone
                lines.append(f"{bl}{last}{mark} {c.activity}")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_credential_suggestions(suggestions) -> str:
    """Render credential-reuse suggestions for the CLI (decision support only)."""
    if not suggestions:
        return ("No credential-reuse candidates found. Record credentials with "
                "`scopeout auth add` to surface related services.")

    from collections import OrderedDict

    lines = ["CREDENTIAL REUSE (suggestions only - no automated checks)", ""]

    groups: "OrderedDict[str, list]" = OrderedDict()
    for s in suggestions:
        key = (s.origin_ip, s.origin_port, s.username)
        groups.setdefault(key, []).append(s)

    for (ip, port, username), group in groups.items():
        head = group[0]
        lines.append(
            f"Credential observed/tested on {ip}:{port}"
            f" (user: {username}, service: {head.origin_service})"
        )
        lines.append("Potential related services:")
        for s in group:
            lines.append(f"- {s.related_ip}:{s.related_port} ({s.related_service})")
        lines.append("")
        lines.append("Reason: the same service type exists on other discovered hosts.")
        lines.append("")

    return "\n".join(lines).rstrip()
