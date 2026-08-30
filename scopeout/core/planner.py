"""Decision-support planner (M3).

Scans the engagement state in the store and produces a prioritized, non-noisy
list of NEXT LEADS, each with a single dominant reason drawn from three states:

  - OPEN_LEADS             service has at least one OPEN lead (active work)
  - DONE_NO_RESULT         a lead was closed DONE but has no Result recorded
  - DISCOVERED_NOT_COVERED service was discovered but has no coverage items

Each service appears AT MOST ONCE with its dominant reason, so the output stays
clean (no repeated/competing reasons for the same service).

Priorities (display order):
    1. OPEN_LEADS            (most actionable - active pending work)
    2. DONE_NO_RESULT        (data-integrity gap: closed work, missing evidence)
    3. DISCOVERED_NOT_COVERED(service never touched)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .model import LeadStatus, Store

# ---------------------------------------------------------------------------
# Reason model
# ---------------------------------------------------------------------------


class Reason(tuple):
    """A reason is (priority, key, label, detail)."""

    OPEN_LEADS = (0, "open-leads", "service still has open leads", "")
    DONE_NO_RESULT = (1, "no-result", "no result recorded", "")
    DISCOVERED_NOT_COVERED = (2, "discovered-not-covered", "discovered but not covered", "")


@dataclass
class NextLead:
    ip: str
    port: int
    proto: str
    service_name: str
    display: str
    reason_key: str
    reason_label: str
    detail: str = ""
    # sort keys for stable ordering
    priority: int = 0

    @property
    def priority_rank(self) -> int:
        of = {
            "open-leads": 0,
            "no-result": 1,
            "discovered-not-covered": 2,
        }
        return of.get(self.reason_key, 9)

    def sort_key(self):
        return (self.priority_rank, self.ip, self.port)


# Mapping service name -> friendly display used in the board.
_DISPLAY: dict[str, str] = {
    "netbios-ssn": "SMB enumeration",
    "microsoft-ds": "SMB enumeration",
    "smb": "SMB enumeration",
    "http": "Web investigation",
    "https": "Web investigation",
    "ssh": "SSH investigation",
    "ftp": "FTP investigation",
    "mysql": "Database investigation",
    "postgresql": "Database investigation",
    "ms-sql-s": "Database investigation",
    "rdp": "RDP investigation",
    "winrm": "WinRM investigation",
    "ldap": "LDAP investigation",
    "dns": "DNS investigation",
    "nfs": "NFS/network mount investigation",
    "snmp": "SNMP investigation",
}


def _service_display(name: str) -> str:
    key = (name or "").lower().strip()
    if key in _DISPLAY:
        return _DISPLAY[key]
    if key:
        return f"{name.strip()} investigation"
    return "Unidentified service"


def _dominant_reason(store: Store, service) -> Optional[Reason]:
    """Return the single dominant reason for a service, or None if it needs none.

    Priority: OPEN_LEADS > DONE_NO_RESULT > DISCOVERED_NOT_COVERED.
    """
    leads = store.list_leads(int(service.id))

    has_open = any(l.status == LeadStatus.OPEN for l in leads)
    if has_open:
        n = sum(1 for l in leads if l.status == LeadStatus.OPEN)
        r = Reason.OPEN_LEADS
        return r + (f"{n} open lead{'s' if n != 1 else ''}",)

    # any DONE lead without a recorded Result?
    for l in leads:
        if l.status == LeadStatus.DONE and not store.list_results(int(l.id)):
            r = Reason.DONE_NO_RESULT
            return r + ("closed lead missing evidence",)

    # no coverage items at all -> never touched
    if not store.list_coverage(int(service.id)):
        r = Reason.DISCOVERED_NOT_COVERED
        return r + ("no methodology coverage applied",)

    return None


def next_leads(store: Store) -> list[NextLead]:
    """Compute the prioritized NEXT LEADS board."""
    results: list[NextLead] = []
    for asset in store.list_assets():
        for service in store.list_services(int(asset.id)):
            reason = _dominant_reason(store, service)
            if reason is None:
                continue
            display = _service_display(service.name)
            results.append(
                NextLead(
                    ip=asset.ip,
                    port=int(service.port),
                    proto=service.proto or "tcp",
                    service_name=service.name or "",
                    display=display,
                    reason_key=reason[1],
                    reason_label=reason[2],
                    detail=reason[3],
                    priority=reason[0],
                )
            )
    results.sort(key=lambda r: r.sort_key())
    return results


# ---------------------------------------------------------------------------
# Credential reuse (v2) - decision support only.
# ---------------------------------------------------------------------------


@dataclass
class CredentialSuggestion:
    """A human-reviewable credential-reuse suggestion.

    Carries the credential reference, where it was observed/tested, and the
    related hosts/services it *could* be tried against. This is purely
    informational - scopeout NEVER attempts login with these.
    """

    username: str
    origin_ip: str
    origin_port: int
    origin_service: str
    related_ip: str
    related_port: int
    related_service: str
    reason: str

    def sort_key(self):
        return (self.origin_ip, self.origin_port, self.related_ip, self.related_port)


def _service_name_family(name: str) -> str:
    """Group service names that share the same methodology family."""
    key = (name or "").lower().strip()
    if key in ("netbios-ssn", "microsoft-ds", "smb", "smb2"):
        return "smb"
    if key in ("http", "https", "http-alt"):
        return "http"
    return key


def credential_suggestions(store: Store) -> list[CredentialSuggestion]:
    """Find potential credential-reuse targets across discovered services.

    For each stored credential, locate OTHER discovered services that are
    related (same service family) and suggest them as relevant places the
    credential might be reused. The originating service is excluded.

    Safety: this only builds a suggestion list. It performs no authentication,
    no spray, no brute force, and no automatic checks.
    """
    # Index discovered services by their methodology family.
    family_map: dict[str, list] = {}
    for asset in store.list_assets():
        for svc in store.list_services(int(asset.id)):
            family = _service_name_family(svc.name)
            family_map.setdefault(family, []).append((asset, svc))

    suggestions: list[CredentialSuggestion] = []
    for asset in store.list_assets():
        for svc in store.list_services(int(asset.id)):
            creds = store.list_credentials(int(svc.id))
            if not creds:
                continue
            origin_family = _service_name_family(svc.name)
            related = family_map.get(origin_family, [])
            for cred in creds:
                for rel_asset, rel_svc in related:
                    if int(rel_svc.id) == int(svc.id):
                        continue  # don't suggest the credential's own service
                    suggestion = CredentialSuggestion(
                        username=cred.username,
                        origin_ip=asset.ip,
                        origin_port=int(svc.port),
                        origin_service=svc.name or "unknown",
                        related_ip=rel_asset.ip,
                        related_port=int(rel_svc.port),
                        related_service=rel_svc.name or "unknown",
                        reason=(
                            f"credential observed/tested on {asset.ip}:{svc.port}; "
                            f"related {origin_family.upper()} service exists on "
                            f"{rel_asset.ip}:{rel_svc.port}"
                        ),
                    )
                    suggestions.append(suggestion)

    suggestions.sort(key=lambda s: s.sort_key())
    return suggestions
