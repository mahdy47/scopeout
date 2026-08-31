"""State commands.

High-level operations that update investigation state and power the future
CLI (M4) and the coverage/notes views:
  - done:   close a lead (by its id) and record a Result.
  - note:   add a free-text note to a service.
  - obs:    add an Observation to a service (recon finding, e.g. "Apache").
  - cover:  mark a coverage item as tested / not tested.
  - addlead: create a new open lead by hand (useful later for the planner).
"""

from __future__ import annotations

from .model import LeadStatus, Store


class ScopeoutError(Exception):
    """Raised on user-facing errors (bad ids, unknown entities, etc.)."""


# -- resolution helpers ------------------------------------------------------


def _require_asset(store: Store, spec: str) -> int:
    """Resolve an asset spec: an integer id, or an IP literal."""
    spec = spec.strip()
    if spec.isdigit():
        aid = int(spec)
        if store.get_asset(aid) is not None:
            return aid
        raise ScopeoutError(f"no asset with id {aid}")
    asset = next((a for a in store.list_assets() if a.ip == spec), None)
    if asset is None:
        raise ScopeoutError(f"no asset with ip {spec!r}")
    return int(asset.id)


def _resolve_service(store: Store, service_spec: str) -> int:
    """Resolve a service spec of the form ``asset:port`` (e.g. '10.0.0.1:22')."""
    if ":" not in service_spec:
        raise ScopeoutError(
            f"service spec must be '<asset>:<port>', got {service_spec!r}"
        )
    asset_part, port_part = service_spec.rsplit(":", 1)
    try:
        port = int(port_part)
    except ValueError:
        raise ScopeoutError(f"invalid port: {port_part!r}")
    aid = _require_asset(store, asset_part)
    for s in store.list_services(aid):
        if s.port == port:
            return int(s.id)
    raise ScopeoutError(
        f"no open service on {asset_part} port {port} (import a scan first)"
    )


def _require_lead(store: Store, lead_id: int) -> None:
    lead = next(
        (l for l in store.list_leads() if l.id == lead_id), None
    )
    if lead is None:
        raise ScopeoutError(f"no lead with id {lead_id}")


# -- commands ----------------------------------------------------------------


def done(store: Store, lead_id: int, outcome: str, evidence: str = "") -> dict:
    """Close an open lead and record its Result."""
    _require_lead(store, lead_id)
    store.set_lead_status(lead_id, LeadStatus.DONE)
    store.add_result(lead_id, outcome, evidence)
    return {"lead_id": lead_id, "status": "DONE", "outcome": outcome}


def block(store: Store, lead_id: int) -> dict:
    """Mark a lead BLOCKED (e.g. checked, no finding, deferred)."""
    _require_lead(store, lead_id)
    store.set_lead_status(lead_id, LeadStatus.BLOCKED)
    return {"lead_id": lead_id, "status": "BLOCKED"}


def add_lead(store: Store, service_spec: str, title: str,
             reason: str = "") -> dict:
    """Add a new open lead to a service by hand."""
    sid = _resolve_service(store, service_spec)
    lid = store.add_lead(sid, title, reason=reason)
    return {"service_id": sid, "lead_id": lid, "title": title, "status": "OPEN"}


def note(store: Store, service_spec: str, text: str) -> dict:
    """Add a free-text note to a service (stored as an Observation)."""
    sid = _resolve_service(store, service_spec)
    oid = store.add_observation(sid, text)
    return {"service_id": sid, "observation_id": oid, "text": text}


def obs(store: Store, service_spec: str, text: str) -> dict:
    """Add an Observation (recon finding) to a service."""
    return note(store, service_spec, text)


def cover(store: Store, service_spec: str, activity: str,
          tested: bool = True) -> dict:
    """Mark a coverage item for a service as tested (or not)."""
    sid = _resolve_service(store, service_spec)
    store.set_coverage(sid, activity, tested=tested)
    return {"service_id": sid, "activity": activity, "tested": bool(tested)}


def auth_add(store: Store, service_spec: str, username: str,
             credential: str, origin: str = "") -> dict:
    """Record a credential (or credential reference) against a service.

    This only records where a credential was observed or tested. It never
    attempts authentication or reuse - the planner only surfaces suggestions.
    """
    sid = _resolve_service(store, service_spec)
    cid = store.add_credential(sid, username, credential, origin=origin)
    return {"service_id": sid, "credential_id": cid,
            "username": username, "credential": credential}
