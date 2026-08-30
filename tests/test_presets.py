"""Tests for methodology presets + auto-seeding (M2)."""

import pytest

from scopeout.core.model import Store, LeadStatus
from scopeout.core.presets import seed_service, seed_all, preset_for
from scopeout.core.importer import import_nmap_file

SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun version="7.94" xmloutputversion="1.04">
<host><status state="up"/>
<address addr="10.1.1.5" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="445"><state state="open"/><service name="netbios-ssn"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH"/></port>
<port protocol="tcp" portid="3306"><state state="open"/><service name="mysql"/></port>
</ports>
</host>
</nmaprun>
"""


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


def test_preset_for_known_and_unknown():
    assert preset_for("http") is not None
    assert preset_for("microsoft-ds") is not None
    assert preset_for("zzz-unknown") is None
    assert preset_for("") is None


def test_seed_service_smb(tmp_path):
    store = Store(":memory:")
    xml_path = tmp_path / "s.xml"
    xml_path.write_text(SAMPLE, encoding="utf-8")
    import_nmap_file(store, xml_path)

    # Find the 445/netbios-ssn service on 10.1.1.5
    asset = next(a for a in store.list_assets() if a.ip == "10.1.1.5")
    smb = next(s for s in store.list_services(asset.id) if s.port == 445)

    cov = {c.activity: c.tested for c in store.list_coverage(smb.id)}
    assert set(cov) == {"Null session test", "SMB signing check", "Share enumeration"}
    assert all(tested is False for tested in cov.values())

    leads = store.list_leads(smb.id)
    assert len(leads) == 1
    assert leads[0].title == "Test SMB null session"
    assert leads[0].status == LeadStatus.OPEN
    store.close()


def test_seed_service_http(tmp_path):
    store = Store(":memory:")
    xml_path = tmp_path / "s.xml"
    xml_path.write_text(SAMPLE, encoding="utf-8")
    import_nmap_file(store, xml_path)
    asset = next(a for a in store.list_assets() if a.ip == "10.1.1.5")
    http = next(s for s in store.list_services(asset.id) if s.port == 80)
    cov = {c.activity for c in store.list_coverage(http.id)}
    assert "Fingerprint / headers" in cov
    assert "Interesting paths / robots.txt" in cov
    assert len(store.list_leads(http.id)) == 2
    store.close()


def test_seed_service_ssh(tmp_path):
    store = Store(":memory:")
    xml_path = tmp_path / "s.xml"
    xml_path.write_text(SAMPLE, encoding="utf-8")
    import_nmap_file(store, xml_path)
    asset = next(a for a in store.list_assets() if a.ip == "10.1.1.5")
    ssh = next(s for s in store.list_services(asset.id) if s.port == 22)
    cov = {c.activity for c in store.list_coverage(ssh.id)}
    assert "Version / weak ciphers check" in cov
    assert "Auth methods review" in cov
    store.close()


def test_unseeded_service_gets_no_preset(tmp_path):
    store = Store(":memory:")
    xml_path = tmp_path / "s.xml"
    xml_path.write_text(SAMPLE, encoding="utf-8")
    import_nmap_file(store, xml_path)
    asset = next(a for a in store.list_assets() if a.ip == "10.1.1.5")
    mysql = next(s for s in store.list_services(asset.id) if s.port == 3306)
    assert store.list_coverage(mysql.id) == []
    assert store.list_leads(mysql.id) == []
    store.close()


def test_seed_is_idempotent(tmp_path):
    store = Store(":memory:")
    xml_path = tmp_path / "s.xml"
    xml_path.write_text(SAMPLE, encoding="utf-8")
    import_nmap_file(store, xml_path)
    import_nmap_file(store, xml_path)  # re-import
    asset = next(a for a in store.list_assets() if a.ip == "10.1.1.5")

    total_cov = sum(len(store.list_coverage(s.id)) for s in store.list_services(asset.id))
    total_leads = sum(len(store.list_leads(s.id)) for s in store.list_services(asset.id))
    # SMB:3cov/1lead, HTTP:3cov/2lead, SSH:2cov/1lead, MySQL:none
    assert total_cov == 8
    assert total_leads == 4
    store.close()


def test_seed_all_summary():
    # Build services directly (no auto-seed), then seed_all applies presets.
    store = Store(":memory:")
    aid = store.upsert_asset("10.1.1.5")
    s_smb = store.upsert_service(aid, 445, name="netbios-ssn")
    s_http = store.upsert_service(aid, 80, name="http")
    s_ssh = store.upsert_service(aid, 22, name="ssh")
    store.upsert_service(aid, 3306, name="mysql")

    res = seed_all(store)
    assert res["seeded"]["coverage"] == 8  # 3+3+2
    assert res["seeded"]["leads"] == 4     # 1+2+1
    assert res["services_with_preset"] == {
        "netbios-ssn": 1, "http": 1, "ssh": 1, "mysql": 1,
    }

    # idempotent: running again seeds nothing new
    res2 = seed_all(store)
    assert res2["seeded"]["coverage"] == 0
    assert res2["seeded"]["leads"] == 0
    store.close()
