"""Read-only HTTP API + dashboard for scopeout.

The routes are read-oriented adapters over the existing ``scopeout.core``
engine. Business logic (planning, report building, credential suggestions) is
NOT reimplemented here - the handlers call the same core functions the CLI
uses and only shape the results as JSON.

Security model
--------------
  * read-only: there are no write/mutation endpoints exposed.
  * no shell / pentest / brute-force / auth / exploit execution anywhere in
    this layer (the core never performs any of those either).
  * raw credential values are never returned; they are always redacted.

Persistence
-----------
The app is built on a read-only in-memory snapshot sourced through the core
importer (see ``scopeout.web.seed``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from scopeout.core.model import LeadStatus
from scopeout.core.planner import next_leads
from scopeout.core.report import build_report

from .seed import create_store

STATIC_INDEX = Path(__file__).resolve().parent / "static" / "index.html"

# ---------------------------------------------------------------------------
# Response models (typed, thin)
# ---------------------------------------------------------------------------


class Health(BaseModel):
    status: str
    mode: str
    service: str


class Host(BaseModel):
    id: int
    ip: str
    hostname: Optional[str]
    os: Optional[str]
    service_count: int
    created_at: str


class Service(BaseModel):
    id: int
    host: str
    host_id: int
    port: int
    proto: str
    name: str
    version: Optional[str]
    banner: Optional[str]


class Lead(BaseModel):
    id: int
    host: str
    port: int
    title: str
    status: str
    reason: str
    evidence: str
    created_at: str
    closed_at: Optional[str]


class Coverage(BaseModel):
    id: int
    host: str
    port: int
    service: str
    activity: str
    tested: bool


class Observation(BaseModel):
    id: int
    host: str
    port: int
    text: str
    created_at: str


class Credential(BaseModel):
    id: int
    host: str
    port: int
    username: str
    credential: str  # always "redacted" over the API
    origin: str
    created_at: str


class Report(BaseModel):
    report: str
    format: str = "markdown"


class Summary(BaseModel):
    total_hosts: int
    total_services: int
    open_leads: int
    completed_leads: int
    coverage_tested: int
    coverage_total: int
    observations: int
    next_leads: int


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app(seed_path: Optional[str] = None,
               store: Optional[Store] = None) -> FastAPI:
    _app = FastAPI(
        title="ScopeOut Web",
        description="Read-only web interface for the ScopeOut engagement-state engine.",
        version="2.0.0",
    )

    # Build the read-only in-memory store at creation. It is immutable and
    # needs no explicit lifecycle cleanup. A caller may inject a fully-built
    # Store (e.g. in tests) via ``store``; otherwise one is created from the
    # read-only seed snapshot.
    if store is None:
        store = create_store(seed_path)

    # -- dashboard ---------------------------------------------------------
    @_app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def dashboard() -> str:
        try:
            return STATIC_INDEX.read_text(encoding="utf-8")
        except OSError:
            return (
                "<!doctype html><html><body><h1>ScopeOut Web</h1>"
                "<p>Dashboard asset missing.</p></body></html>"
            )

    # -- API ---------------------------------------------------------------
    @_app.get("/api/health", response_model=Health)
    def health() -> Health:
        return Health(status="ok", mode="read-only-snapshot", service="scopeout")

    @_app.get("/api/hosts", response_model=list[Host])
    def hosts() -> list[Host]:
        out = []
        for asset in store.list_assets():
            out.append(
                Host(
                    id=int(asset.id),
                    ip=asset.ip,
                    hostname=asset.hostname,
                    os=asset.os,
                    service_count=len(store.list_services(int(asset.id))),
                    created_at=asset.created_at or "",
                )
            )
        return out

    @_app.get("/api/services", response_model=list[Service])
    def services(asset_id: Optional[int] = None) -> list[Service]:
        out = []
        for asset in store.list_assets():
            if asset_id is not None and int(asset.id) != asset_id:
                continue
            for svc in store.list_services(int(asset.id)):
                out.append(
                    Service(
                        id=int(svc.id),
                        host=asset.ip,
                        host_id=int(asset.id),
                        port=int(svc.port),
                        proto=svc.proto or "tcp",
                        name=svc.name or "",
                        version=svc.version,
                        banner=svc.banner,
                    )
                )
        return out

    @_app.get("/api/leads", response_model=list[Lead])
    def leads() -> list[Lead]:
        out = []
        for asset in store.list_assets():
            for svc in store.list_services(int(asset.id)):
                for lead in store.list_leads(int(svc.id)):
                    results = store.list_results(int(lead.id))
                    evidence = results[-1].evidence if results else ""
                    out.append(
                        Lead(
                            id=int(lead.id),
                            host=asset.ip,
                            port=int(svc.port),
                            title=lead.title,
                            status=lead.status.value,
                            reason=lead.reason or "",
                            evidence=evidence,
                            created_at=lead.created_at or "",
                            closed_at=lead.closed_at,
                        )
                    )
        return out

    @_app.get("/api/coverage", response_model=list[Coverage])
    def coverage() -> list[Coverage]:
        out = []
        for asset in store.list_assets():
            for svc in store.list_services(int(asset.id)):
                for item in store.list_coverage(int(svc.id)):
                    out.append(
                        Coverage(
                            id=int(item.id),
                            host=asset.ip,
                            port=int(svc.port),
                            service=svc.name or "unknown",
                            activity=item.activity,
                            tested=bool(item.tested),
                        )
                    )
        return out

    @_app.get("/api/observations", response_model=list[Observation])
    def observations() -> list[Observation]:
        out = []
        for asset in store.list_assets():
            for svc in store.list_services(int(asset.id)):
                for obs in store.list_observations(int(svc.id)):
                    out.append(
                        Observation(
                            id=int(obs.id),
                            host=asset.ip,
                            port=int(svc.port),
                            text=obs.text,
                            created_at=obs.created_at or "",
                        )
                    )
        return out

    @_app.get("/api/credentials", response_model=list[Credential])
    def credentials() -> list[Credential]:
        out = []
        for asset in store.list_assets():
            for svc in store.list_services(int(asset.id)):
                for cred in store.list_credentials(int(svc.id)):
                    out.append(
                        Credential(
                            id=int(cred.id),
                            host=asset.ip,
                            port=int(svc.port),
                            username=cred.username,
                            credential="redacted",
                            origin=cred.origin or "",
                            created_at=cred.created_at or "",
                        )
                    )
        return out

    @_app.get("/api/report", response_model=Report)
    def report() -> Report:
        return Report(report=build_report(store), format="markdown")

    @_app.get("/api/summary", response_model=Summary)
    def summary() -> Summary:
        assets = store.list_assets()
        services = [s for a in assets for s in store.list_services(int(a.id))]
        leads = [l for a in assets for s in store.list_services(int(a.id))
                 for l in store.list_leads(int(s.id))]
        coverage = [c for a in assets for s in store.list_services(int(a.id))
                    for c in store.list_coverage(int(s.id))]
        observations = [o for a in assets for s in store.list_services(int(a.id))
                        for o in store.list_observations(int(s.id))]
        return Summary(
            total_hosts=len(assets),
            total_services=len(services),
            open_leads=sum(1 for l in leads if l.status == LeadStatus.OPEN),
            completed_leads=sum(1 for l in leads if l.status == LeadStatus.DONE),
            coverage_tested=sum(1 for c in coverage if c.tested),
            coverage_total=len(coverage),
            observations=len(observations),
            next_leads=len(next_leads(store)),
        )

    return _app


app = create_app()
