"""Methodology presets used to seed initial coverage items and open leads.

Each preset is bound to a set of service *names* (as reported by nmap). The
presets are intentionally SMALL (a few activities) so scopeout stays a
decision-support tool rather than ballooning back into a static checklist.

A preset defines:
  - `coverage`: activities that SHOULD be tested for that service (each gets a
    Coverage item, seeded as not-yet-tested=False).
  - `auto_leads`: optional Open leads pre-created when the service is first
    seen. These mirror the strongest "first thing to check" for a service.

The seed content is what M3's planner reads to distinguish
"discovered but not covered" from "covered".
"""

from __future__ import annotations

from typing import Optional

from .model import Store

# service-name -> preset
PRESETS: dict[str, dict] = {
    "netbios-ssn": {
        "coverage": [
            "Null session test",
            "SMB signing check",
            "Share enumeration",
        ],
        "auto_leads": [
            ("Test SMB null session", "service discovered, first auth surface"),
        ],
    },
    "microsoft-ds": {  # Samba/CIFS on 445
        "coverage": [
            "Null session test",
            "SMB signing check",
            "Share enumeration",
        ],
        "auto_leads": [
            ("Test SMB null session", "service discovered, first auth surface"),
        ],
    },
    "smb": {
        "coverage": [
            "Null session test",
            "SMB signing check",
            "Share enumeration",
        ],
        "auto_leads": [
            ("Test SMB null session", "service discovered, first auth surface"),
        ],
    },
    "http": {
        "coverage": [
            "Fingerprint / headers",
            "Interesting paths / robots.txt",
            "Virtual host enumeration",
        ],
        "auto_leads": [
            ("Enumerate web application", "HTTP service discovered"),
            ("Check interesting paths", "robots.txt and common dirs"),
        ],
    },
    "https": {
        "coverage": [
            "Fingerprint / headers",
            "Interesting paths / robots.txt",
            "Virtual host enumeration",
            "TLS certificate review",
        ],
        "auto_leads": [
            ("Enumerate web application", "HTTPS service discovered"),
            ("Check interesting paths", "robots.txt and common dirs"),
        ],
    },
    "ssh": {
        "coverage": [
            "Version / weak ciphers check",
            "Auth methods review",
        ],
        "auto_leads": [
            ("Assess SSH auth methods", "SSH service discovered"),
        ],
    },
}

# service names that have no methodology seed (we leave them empty)
_SEEN_NO_PRESET = set()


def preset_for(service_name: str) -> Optional[dict]:
    """Return the preset dict for a service name, or None."""
    key = service_name.lower().strip()
    if not key:
        return None
    return PRESETS.get(key)


def seed_service(store: Store, service_id: int, service_name: str) -> dict:
    """Apply the preset for a service: seed coverage items + auto leads.

    Idempotent: existing coverage/leads for that service are left untouched,
    so re-running on an already-seeded service never duplicates.

    Returns a summary dict:
        {"coverage": [...names seeded...], "leads": [...titles seeded...]}
    """
    preset = preset_for(service_name)
    if preset is None:
        return {"coverage": [], "leads": []}

    seeded_coverage = []
    existing_activities = {c.activity for c in store.list_coverage(service_id)}
    for activity in preset["coverage"]:
        if activity not in existing_activities:
            store.set_coverage(service_id, activity, tested=False)
            seeded_coverage.append(activity)

    seeded_leads = []
    existing_titles = {l.title for l in store.list_leads(service_id)}
    for title, reason in preset["auto_leads"]:
        if title not in existing_titles:
            store.add_lead(service_id, title, reason=reason)
            seeded_leads.append(title)

    return {"coverage": seeded_coverage, "leads": seeded_leads}


def seed_all(store: Store) -> dict:
    """Apply presets to every service currently in the store.

    Returns a summary across all assets:
        {
          "seeded": {"coverage": n, "leads": n},
          "services_with_preset": {...service_name: count...},
        }
    """
    total_cov = 0
    total_leads = 0
    by_name: dict[str, int] = {}
    for service in store.list_services():
        res = seed_service(store, int(service.id), service.name or "")
        total_cov += len(res["coverage"])
        total_leads += len(res["leads"])
        name = (service.name or "").strip() or "unknown"
        by_name[name] = by_name.get(name, 0) + 1
    return {
        "seeded": {"coverage": total_cov, "leads": total_leads},
        "services_with_preset": by_name,
    }
