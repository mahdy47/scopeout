"""Tests for rendering (M3): next-leads board + per-host status tree."""

import pytest

from scopeout.core.model import Store, LeadStatus
from scopeout.core.importer import import_nmap_file
from scopeout.core.planner import next_leads
from scopeout.core.render import render_leads, render_status
from scopeout.core import state

BASE = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun version="7.94" xmloutputversion="1.04">
<host><status state="up"/>
<address addr="10.1.1.5" addrtype="ipv4"/>
<hostnames><hostname name="ws5.lab" type="PTR"/></hostnames>
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
    p = tmp_path / "s.xml"
    p.write_text(BASE, encoding="utf-8")
    import_nmap_file(s, p)
    yield s
    s.close()


def _svc(store, port):
    asset = next(a for a in store.list_assets() if a.ip == "10.1.1.5")
    return next(s for s in store.list_services(asset.id) if s.port == port)


def test_render_leads_empty():
    assert "fully covered" in render_leads([])


def test_render_leads_board(store):
    tabs = next_leads(store)
    out = render_leads(tabs)
    assert "NEXT LEADS" in out
    assert "445" in out
    assert "SMB enumeration" in out
    assert "Reason:" in out


def test_render_leads_header_order(store):
    # verify group headers appear (open-leads, and no discovered group here)
    tabs = next_leads(store)
    out = render_leads(tabs)
    assert "still has open leads" in out


def test_render_status_shows_seed(store, tmp_path):
    out = render_status(store, next(a for a in store.list_assets()))
    assert "10.1.1.5" in out
    assert "ws5.lab" in out
    assert "[OPEN]" in out            # auto-seeded open lead
    assert "SMB enumeration :445" in out
    assert "✗ Null session test" in out


def test_render_status_shows_result(store):
    smb = _svc(store, 445)
    lead = next(l for l in store.list_leads(int(smb.id)) if l.status == LeadStatus.OPEN)
    state.done(store, int(lead.id), "guest login accepted", "smbclient -L")
    out = render_status(store, next(a for a in store.list_assets()))
    assert "[DONE]" in out
    assert "guest login accepted" in out


def test_render_status_shows_observation_and_note(store):
    state.obs(store, "10.1.1.5:80", "Apache detected")
    state.note(store, "10.1.1.5:80", "interesting endpoint at /admin")
    out = render_status(store, next(a for a in store.list_assets()))
    assert "Apache detected" in out
    assert "interesting endpoint at /admin" in out
