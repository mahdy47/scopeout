"""Tests for the planner (M3) - the three decision states + ordering."""


from scopeout.core import state
from scopeout.core.importer import import_nmap_file
from scopeout.core.model import LeadStatus, Store
from scopeout.core.planner import next_leads

BASE = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun version="7.94" xmloutputversion="1.04">
<host><status state="up"/>
<address addr="10.1.1.5" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="445"><state state="open"/><service name="netbios-ssn"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="3306"><state state="open"/><service name="mysql"/></port>
</ports>
</host>
</nmaprun>
"""


def _make_store(tmp_path, xml=BASE):
    s = Store(":memory:")
    p = tmp_path / "s.xml"
    p.write_text(xml, encoding="utf-8")
    import_nmap_file(s, p)
    return s


def _svc(store, port):
    asset = next(a for a in store.list_assets() if a.ip == "10.1.1.5")
    return next(s for s in store.list_services(asset.id) if s.port == port)


def _reason_keys(leads):
    return [(n.reason_key, n.display) for n in leads]


# ---------------------------------------------------------------------------
# State 1: discovered-but-not-covered (mysql has no preset -> no coverage)
# ---------------------------------------------------------------------------


def test_discovered_not_covered(tmp_path):
    store = _make_store(tmp_path)
    tabs = next_leads(store)
    # mysql (3306) has no coverage -> discovered-but-not-covered
    keys = _reason_keys(tabs)
    assert any(k == "discovered-not-covered" and "Database" in d for k, d in keys)


# ---------------------------------------------------------------------------
# State 2: open-leads (freshly imported smb/http have open auto-leads)
# ---------------------------------------------------------------------------


def test_open_leads_reason(tmp_path):
    store = _make_store(tmp_path)
    tabs = next_leads(store)
    assert {n.reason_key for n in tabs} == {
        "open-leads", "discovered-not-covered",
    }
    # smb + http should be open-leads
    open_leads_ports = {
        n.port for n in tabs if n.reason_key == "open-leads"
    }
    assert 445 in open_leads_ports
    assert 80 in open_leads_ports


# ---------------------------------------------------------------------------
# State 3: no-result (DONE lead closed through command without a Result)
# ---------------------------------------------------------------------------


def test_done_no_result(tmp_path):
    store = _make_store(tmp_path)
    # find a SMB open lead and close it with DONE but NO result recorded
    smb = _svc(store, 445)
    lead = next(l for l in store.list_leads(int(smb.id))
                if l.status == LeadStatus.OPEN)
    # 'block' sets DONE? No - block sets BLOCKED. Simulate a DONE-no-result by
    # setting the status directly (done() records a Result; use store API).
    store.set_lead_status(int(lead.id), LeadStatus.DONE)

    tabs = next_leads(store)
    no_result = [
        n for n in tabs if n.reason_key == "no-result" and n.port == 445
    ]
    assert no_result, "expected 445 flagged as no-result"
    assert no_result[0].reason_label == "no result recorded"


def test_done_with_result_is_not_no_result(tmp_path):
    store = _make_store(tmp_path)
    smb = _svc(store, 445)
    lead = next(l for l in store.list_leads(int(smb.id))
                if l.status == LeadStatus.OPEN)
    state.done(store, int(lead.id), "guest login accepted", "smbclient -L")

    tabs = next_leads(store)
    assert not any(
        n.reason_key == "no-result" and n.port == 445 for n in tabs
    )


# ---------------------------------------------------------------------------
# Ordering: open-leads before no-result before discovered-not-covered
# ---------------------------------------------------------------------------


def test_priority_ordering(tmp_path):
    store = _make_store(tmp_path)
    # make the SMB service a no-result (close its lead DONE); mysql stays
    # discovered-not-covered; http stays open-leads.
    smb = _svc(store, 445)
    lead = next(l for l in store.list_leads(int(smb.id))
                if l.status == LeadStatus.OPEN)
    store.set_lead_status(int(lead.id), LeadStatus.DONE)

    tabs = next_leads(store)
    # expected order by priority: open-leads (http:80), no-result (445), discovered-not-covered (3306)
    ranks = [n.priority_rank for n in tabs]
    assert ranks == sorted(ranks)
    assert tabs[0].reason_key == "open-leads"      # http 80
    assert tabs[1].reason_key == "no-result"       # smb 445
    assert tabs[2].reason_key == "discovered-not-covered"  # mysql 3306


# ---------------------------------------------------------------------------
# Non-noisy: each service appears at most once
# ---------------------------------------------------------------------------


def test_each_service_once(tmp_path):
    store = _make_store(tmp_path)
    tabs = next_leads(store)
    seen = set()
    for n in tabs:
        key = (n.ip, n.port)
        assert key not in seen, f"duplicate service {key}"
        seen.add(key)
    assert len(seen) == 3  # 445, 80, 3306 each exactly once


def test_resolved_seeded_services_drop_out(tmp_path):
    store = _make_store(tmp_path)
    smb = _svc(store, 445)
    http = _svc(store, 80)
    _svc(store, 3306)

    # close every open lead with a result
    for s in (smb, http):
        for l in store.list_leads(int(s.id)):
            if l.status == LeadStatus.OPEN:
                state.done(store, int(l.id), "checked, no finding")
    # cover all seeded coverage on smb/http
    for s in (smb, http):
        for c in store.list_coverage(int(s.id)):
            store.set_coverage(int(s.id), c.activity, tested=True)
    # mysql has no preset -> no leads, no coverage -> discovered-not-covered
    tabs = next_leads(store)
    assert len(tabs) == 1
    assert tabs[0].reason_key == "discovered-not-covered"
    assert tabs[0].port == 3306
