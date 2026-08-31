"""Tests for credential-reuse suggestions (v2 planner) - decision support only."""

import pytest

from scopeout.core.importer import import_nmap_file
from scopeout.core.model import Store
from scopeout.core.planner import _service_name_family, credential_suggestions

BASE = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun version="7.94" xmloutputversion="1.04">
<host><status state="up"/>
<address addr="10.0.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="445"><state state="open"/><service name="netbios-ssn"/></port>
</ports>
</host>
<host><status state="up"/>
<address addr="10.0.0.2" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
</ports>
</host>
<host><status state="up"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="445"><state state="open"/><service name="smb"/></port>
</ports>
</host>
<host><status state="up"/>
<address addr="10.0.0.9" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
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


def _svc(store, ip, port):
    asset = next(a for a in store.list_assets() if a.ip == ip)
    return next(s for s in store.list_services(asset.id) if s.port == port)


def test_service_name_family():
    assert _service_name_family("microsoft-ds") == "smb"
    assert _service_name_family("netbios-ssn") == "smb"
    assert _service_name_family("smb") == "smb"
    assert _service_name_family("http") == "http"
    assert _service_name_family("weird") == "weird"


def test_detects_related_services(store):
    # add a credential on 10.0.0.1:445 (netbios-ssn)
    store.add_credential(_svc(store, "10.0.0.1", 445).id, "guest", "(blank)")

    sug = credential_suggestions(store)
    # The 10.0.0.1 credential should suggest the other SMB services (2 and 5)
    related = {(s.related_ip, s.related_port) for s in sug}
    assert ("10.0.0.2", 445) in related
    assert ("10.0.0.5", 445) in related
    # The SSH host is not related to SMB - must NOT be suggested
    assert not any(s.related_ip == "10.0.0.9" for s in sug)


def test_excludes_origin_service(store):
    store.add_credential(_svc(store, "10.0.0.1", 445).id, "guest", "(blank)")
    sug = credential_suggestions(store)
    # must not suggest the credential's own host
    assert not any(s.related_ip == "10.0.0.1" and s.related_port == 445 for s in sug)


def test_multiple_credentials(store):
    store.add_credential(_svc(store, "10.0.0.1", 445).id, "guest", "(blank)")
    store.add_credential(_svc(store, "10.0.0.2", 445).id, "admin", "P@ss")
    sug = credential_suggestions(store)
    origins = {(s.origin_ip, s.username) for s in sug}
    assert ("10.0.0.1", "guest") in origins
    assert ("10.0.0.2", "admin") in origins


def test_no_credentials_yields_no_suggestions(store):
    assert credential_suggestions(store) == []


def test_suggestion_is_decision_support_only(store):
    """Suggestions must never carry login actions / network behavior."""
    store.add_credential(_svc(store, "10.0.0.1", 445).id, "guest", "(blank)")
    sug = credential_suggestions(store)
    assert sug
    for s in sug:
        # only descriptive fields - no 'attempt', no 'login', no 'spray'
        assert not any(k in s.reason.lower()
                       for k in ("login attempt", "spray", "brute", "auto"))
