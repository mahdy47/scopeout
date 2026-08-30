"""Tests for the read-only web/API layer.

These exercises re-use the real scopeout.core engine through the FastAPI app.
Where a test needs a deterministic database (including credentials for the
redaction check) it builds a real core Store and injects it via
``create_app(store=...)`` - no core logic is duplicated or mocked away.
"""

import pytest

fastapi = pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from scopeout.core.importer import import_nmap_file
from scopeout.core.model import Store
from scopeout.core.state import auth_add, done
from scopeout.web.app import create_app

SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun version="7.94" xmloutputversion="1.04">
<host><status state="up"/>
<address addr="10.1.1.5" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="445"><state state="open"/><service name="netbios-ssn"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
</ports>
</host>
</nmaprun>
"""


def _seeded_store(tmp_path) -> Store:
    store = Store(":memory:")
    xml_path = tmp_path / "web.xml"
    xml_path.write_text(SAMPLE, encoding="utf-8")
    import_nmap_file(store, xml_path)
    return store


@pytest.fixture
def client(tmp_path):
    store = _seeded_store(tmp_path)
    app = create_app(store=store)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def empty_client():
    app = create_app(seed_path=":")  # explicit empty snapshot
    with TestClient(app) as c:
        yield c


# -- health ----------------------------------------------------------------


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["mode"] == "read-only-snapshot"
    assert body["service"] == "scopeout"


# -- hosts ----------------------------------------------------------------


def test_hosts(client):
    r = client.get("/api/hosts")
    assert r.status_code == 200
    hosts = r.json()
    assert len(hosts) == 1
    assert hosts[0]["ip"] == "10.1.1.5"
    assert hosts[0]["service_count"] == 2
    assert hosts[0]["os"] is None


# -- services -------------------------------------------------------------


def test_services(client):
    r = client.get("/api/services")
    assert r.status_code == 200
    svcs = r.json()
    assert len(svcs) == 2
    ports = {s["port"] for s in svcs}
    assert ports == {445, 80}
    assert all(s["host"] == "10.1.1.5" for s in svcs)


# -- leads ----------------------------------------------------------------


def test_leads(client):
    r = client.get("/api/leads")
    assert r.status_code == 200
    leads = r.json()
    # SMB preset auto-seeds 1 lead; HTTP auto-seeds 2.
    assert len(leads) == 3
    assert all(l["status"] == "OPEN" for l in leads)
    assert all(l["host"] == "10.1.1.5" for l in leads)


def test_leads_evidence_and_redaction(tmp_path):
    store = _seeded_store(tmp_path)
    asset = next(a for a in store.list_assets() if a.ip == "10.1.1.5")
    svc445 = next(s for s in store.list_services(asset.id) if s.port == 445)
    lead = store.list_leads(svc445.id)[0]
    done(store, lead.id, "guest login accepted", evidence="smbclient -L //10.1.1.5")
    auth_add(store, "10.1.1.5:445", "guest", "(blank password)", origin="smbclient -L")
    app = create_app(store=store)
    with TestClient(app) as c:
        leads = c.get("/api/leads").json()
        lead_row = next(l for l in leads if l["title"] == lead.title)
        assert lead_row["status"] == "DONE"
        assert lead_row["evidence"] == "smbclient -L //10.1.1.5"


# -- coverage -------------------------------------------------------------


def test_coverage(client):
    r = client.get("/api/coverage")
    assert r.status_code == 200
    cov = r.json()
    assert len(cov) == 6  # 3 SMB + 3 HTTP
    assert all(c["tested"] is False for c in cov)
    assert all(c["host"] == "10.1.1.5" for c in cov)


# -- observations ---------------------------------------------------------


def test_observations(client):
    r = client.get("/api/observations")
    assert r.status_code == 200
    assert r.json() == []  # none recorded yet


# -- report ---------------------------------------------------------------


def test_report(client):
    r = client.get("/api/report")
    assert r.status_code == 200
    body = r.json()
    assert body["format"] == "markdown"
    assert body["report"].startswith("# Engagement Report")
    assert "10.1.1.5" in body["report"]


# -- summary --------------------------------------------------------------


def test_summary(client):
    r = client.get("/api/summary")
    assert r.status_code == 200
    s = r.json()
    assert s["total_hosts"] == 1
    assert s["total_services"] == 2
    assert s["open_leads"] == 3
    assert s["completed_leads"] == 0
    assert s["coverage_total"] == 6
    assert s["coverage_tested"] == 0
    assert s["observations"] == 0
    assert s["next_leads"] == 2  # both services have open leads


# -- empty database -------------------------------------------------------


def test_empty_database(empty_client):
    assert empty_client.get("/api/health").status_code == 200
    assert empty_client.get("/api/hosts").json() == []
    assert empty_client.get("/api/services").json() == []
    assert empty_client.get("/api/leads").json() == []
    assert empty_client.get("/api/coverage").json() == []
    assert empty_client.get("/api/report").json()["report"].startswith("# Engagement Report")
    summary = empty_client.get("/api/summary").json()
    assert summary["total_hosts"] == 0
    assert summary["coverage_total"] == 0
    assert summary["next_leads"] == 0


# -- credential redaction -------------------------------------------------


def test_credentials_redacted(tmp_path):
    store = _seeded_store(tmp_path)
    auth_add(store, "10.1.1.5:445", "guest", "SuperSecret!",
             origin="smbclient -L //10.1.1.5")
    app = create_app(store=store)
    with TestClient(app) as c:
        creds = c.get("/api/credentials").json()
        assert len(creds) == 1
        row = creds[0]
        assert row["username"] == "guest"
        # Redaction is the core security guarantee.
        assert row["credential"] == "redacted"
        assert "SuperSecret!" not in str(creds)
        assert row["origin"] == "smbclient -L //10.1.1.5"


def test_credentials_not_exposed_via_report(tmp_path):
    store = _seeded_store(tmp_path)
    auth_add(store, "10.1.1.5:445", "guest", "SuperSecret!",
             origin="observed")
    app = create_app(store=store)
    with TestClient(app) as c:
        report = c.get("/api/report").json()["report"]
        assert "SuperSecret!" not in report
        assert "*redacted*" in report  # core already redacts in the report


# -- malformed requests / error handling ---------------------------------


def test_malformed_query_param_rejected(client):
    # FastAPI validates int query params and returns 422 on bad types.
    assert client.get("/api/services?asset_id=abc").status_code == 422


def test_services_filter_by_asset(client):
    asset = client.get("/api/hosts").json()[0]
    filtered = client.get(f"/api/services?asset_id={asset['id']}").json()
    assert len(filtered) == 2
    # An asset id that does not exist filters everything out (empty).
    assert client.get("/api/services?asset_id=999999").json() == []


def test_unknown_route_404(client):
    assert client.get("/api/nope").status_code == 404


def test_dashboard_served(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "ScopeOut" in r.text
