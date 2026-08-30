"""Tests for the core data model + SQLite store (M1)."""

import pytest

from scopeout.core.model import Store, Asset, Service, LeadStatus


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


def test_upsert_asset_creates_and_dedups(store):
    a1 = store.upsert_asset("10.0.0.1", hostname="ws1.lab", os="Linux")
    a2 = store.upsert_asset("10.0.0.1")
    assert a1 == a2
    assert len(store.list_assets()) == 1


def test_upsert_asset_updates_hostname_and_os(store):
    store.upsert_asset("10.0.0.1", hostname="ws1", os="Linux")
    aid = store.upsert_asset("10.0.0.1", hostname="ws1.lab", os="Windows")
    asset = store.get_asset(aid)
    assert asset.hostname == "ws1.lab"
    assert asset.os == "Windows"


def test_service_lifecycle(store):
    aid = store.upsert_asset("10.0.0.1")
    sid = store.upsert_service(aid, 22, name="ssh", version="OpenSSH 8.2p1")
    services = store.list_services(aid)
    assert len(services) == 1
    assert services[0].name == "ssh"
    assert services[0].version == "OpenSSH 8.2p1"
    # dedup same (asset, port, proto)
    sid2 = store.upsert_service(aid, 22, name="ssh")
    assert sid == sid2
    assert len(store.list_services(aid)) == 1


def test_observation(store):
    aid = store.upsert_asset("10.0.0.1")
    sid = store.upsert_service(aid, 80)
    store.add_observation(sid, "Apache detected")
    obs = store.list_observations(sid)
    assert len(obs) == 1
    assert obs[0].text == "Apache detected"


def test_lead_lifecycle(store):
    aid = store.upsert_asset("10.0.0.1")
    sid = store.upsert_service(aid, 445)
    lid = store.add_lead(sid, "Test null session", reason="discovered but not covered")
    leads = store.list_leads(sid)
    assert len(leads) == 1
    assert leads[0].status == LeadStatus.OPEN
    assert leads[0].reason == "discovered but not covered"

    store.set_lead_status(lid, LeadStatus.DONE)
    done = store.list_leads(sid, status=LeadStatus.DONE)
    assert len(done) == 1
    assert done[0].closed_at is not None
    open_leads = store.list_leads(sid, status=LeadStatus.OPEN)
    assert open_leads == []


def test_result_on_lead(store):
    aid = store.upsert_asset("10.0.0.1")
    sid = store.upsert_service(aid, 445)
    lid = store.add_lead(sid, "Test null session")
    store.add_result(lid, "guest login accepted", evidence="smbclient -L //10.0.0.1")
    results = store.list_results(lid)
    assert len(results) == 1
    assert results[0].outcome == "guest login accepted"


def test_coverage(store):
    aid = store.upsert_asset("10.0.0.1")
    sid = store.upsert_service(aid, 445)
    store.set_coverage(sid, "Share enumeration", False)
    store.set_coverage(sid, "Signing check", True)
    cov = store.list_coverage(sid)
    mapping = {c.activity: c.tested for c in cov}
    assert mapping["Share enumeration"] is False
    assert mapping["Signing check"] is True
    # updating existing
    store.set_coverage(sid, "Share enumeration", True)
    cov2 = store.list_coverage(sid)
    assert len(cov2) == 2
    assert {c.activity: c.tested for c in cov2}["Share enumeration"] is True


def test_cascade_delete_asset(store):
    aid = store.upsert_asset("10.0.0.1")
    sid = store.upsert_service(aid, 80)
    store.add_observation(sid, "x")
    store.add_lead(sid, "y")
    store.conn.execute("DELETE FROM assets WHERE id = ?", (aid,))
    store.conn.commit()
    assert store.list_services(aid) == []
