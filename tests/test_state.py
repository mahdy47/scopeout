"""Tests for state commands: done / note / obs / cover / add_lead (M2)."""

import pytest

from scopeout.core.importer import import_nmap_file
from scopeout.core.model import LeadStatus, Store
from scopeout.core.state import (
    ScopeoutError,
    add_lead,
    block,
    cover,
    done,
    note,
    obs,
)

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


@pytest.fixture
def store(tmp_path):
    s = Store(":memory:")
    xml_path = tmp_path / "s.xml"
    xml_path.write_text(SAMPLE, encoding="utf-8")
    import_nmap_file(s, xml_path)
    yield s
    s.close()


def _first_lead(store, port):
    asset = next(a for a in store.list_assets() if a.ip == "10.1.1.5")
    svc = next(s for s in store.list_services(asset.id) if s.port == port)
    return store.list_leads(svc.id)[0]


def test_done_closes_lead_and_records_result(store):
    lead = _first_lead(store, 445)
    res = done(store, lead.id, "guest login accepted",
               evidence="smbclient -L //10.1.1.5")
    assert res["status"] == "DONE"

    remaining = store.list_leads(lead.service_id, status=LeadStatus.OPEN)
    assert all(l.id != lead.id for l in remaining)
    results = store.list_results(lead.id)
    assert len(results) == 1
    assert results[0].outcome == "guest login accepted"
    assert results[0].evidence == "smbclient -L //10.1.1.5"


def test_block_changes_status(store):
    lead = _first_lead(store, 80)
    block(store, lead.id)
    assert store.list_leads(lead.service_id, status=LeadStatus.BLOCKED)[0].id == lead.id


def test_done_unknown_lead_raises(store):
    with pytest.raises(ScopeoutError):
        done(store, 99999, "x")


def test_note_adds_observation(store):
    note(store, "10.1.1.5:80", "Apache main page at /")
    asset = next(a for a in store.list_assets() if a.ip == "10.1.1.5")
    svc = next(s for s in store.list_services(asset.id) if s.port == 80)
    obs_list = store.list_observations(svc.id)
    assert any(o.text == "Apache main page at /" for o in obs_list)


def test_obs_alias(store):
    obs(store, "10.1.1.5:80", "Apache detected")
    asset = next(a for a in store.list_assets() if a.ip == "10.1.1.5")
    svc = next(s for s in store.list_services(asset.id) if s.port == 80)
    assert store.list_observations(svc.id)[0].text == "Apache detected"


def test_cover_marks_tested(store):
    asset = next(a for a in store.list_assets() if a.ip == "10.1.1.5")
    svc = next(s for s in store.list_services(asset.id) if s.port == 445)
    cover(store, "10.1.1.5:445", "Null session test", tested=True)
    mapping = {c.activity: c.tested for c in store.list_coverage(svc.id)}
    assert mapping["Null session test"] is True
    assert mapping["SMB signing check"] is False


def test_cover_creates_new_item(store):
    # marking a coverage item that wasn't seeded creates it as tested
    cover(store, "10.1.1.5:80", "Custom check", tested=True)
    asset = next(a for a in store.list_assets() if a.ip == "10.1.1.5")
    svc = next(s for s in store.list_services(asset.id) if s.port == 80)
    mapping = {c.activity: c.tested for c in store.list_coverage(svc.id)}
    assert mapping["Custom check"] is True


def test_add_lead(store):
    res = add_lead(store, "10.1.1.5:445", "Try SMBv1 fallback", reason="manual")
    assert res["status"] == "OPEN"
    asset = next(a for a in store.list_assets() if a.ip == "10.1.1.5")
    svc = next(s for s in store.list_services(asset.id) if s.port == 445)
    titles = [l.title for l in store.list_leads(svc.id)]
    assert "Try SMBv1 fallback" in titles


def test_service_spec_errors(store):
    with pytest.raises(ScopeoutError):
        note(store, "not-a-spec", "x")          # no colon
    with pytest.raises(ScopeoutError):
        note(store, "10.1.1.5:99999", "x")       # port not open
    with pytest.raises(ScopeoutError):
        note(store, "192.0.2.1:80", "x")         # unknown ip
    with pytest.raises(ScopeoutError):
        note(store, "10.1.1.5:notapnum", "x")    # bad port
