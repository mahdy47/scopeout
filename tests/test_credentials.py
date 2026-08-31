"""Tests for credential storage (v2) - model + state.auth_add."""

import pytest

from scopeout.core import state
from scopeout.core.importer import import_nmap_file
from scopeout.core.model import Store

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
<host><status state="up"/>
<address addr="10.1.1.6" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
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


def test_add_credential_via_store(store):
    sid = _svc(store, "10.1.1.5", 445).id
    cid = store.add_credential(sid, "guest", "(blank)", origin="smbclient -L")
    creds = store.list_credentials(sid)
    assert len(creds) == 1
    assert creds[0].id == cid
    assert creds[0].username == "guest"
    assert creds[0].credential == "(blank)"
    assert creds[0].origin == "smbclient -L"


def test_list_credentials_all(store):
    sid5 = _svc(store, "10.1.1.5", 445).id
    sid6 = _svc(store, "10.1.1.6", 445).id
    store.add_credential(sid5, "guest", "(blank)")
    store.add_credential(sid6, "admin", "P@ss")
    creds = store.list_credentials()
    assert len(creds) == 2
    assert {c.username for c in creds} == {"guest", "admin"}


def test_list_credentials_by_service(store):
    sid5 = _svc(store, "10.1.1.5", 445).id
    sid6 = _svc(store, "10.1.1.6", 445).id
    store.add_credential(sid5, "guest", "(blank)")
    store.add_credential(sid6, "admin", "P@ss")
    assert len(store.list_credentials(sid5)) == 1
    assert store.list_credentials(sid5)[0].username == "guest"


def test_credential_cascade_delete(store):
    sid5 = _svc(store, "10.1.1.5", 445).id
    store.add_credential(sid5, "guest", "(blank)")
    asset = next(a for a in store.list_assets() if a.ip == "10.1.1.5")
    store.conn.execute("DELETE FROM assets WHERE id = ?", (asset.id,))
    store.conn.commit()
    assert store.list_credentials() == []


def test_auth_add_command(store):
    res = state.auth_add(store, "10.1.1.5:445", "guest", "(blank)", "smbclient")
    assert res["username"] == "guest"
    sid = _svc(store, "10.1.1.5", 445).id
    creds = store.list_credentials(sid)
    assert len(creds) == 1
    assert creds[0].credential == "(blank)"


def test_auth_add_bad_service_raises(store):
    with pytest.raises(state.ScopeoutError):
        state.auth_add(store, "10.1.1.5:9999", "x", "y")


def test_auth_add_does_not_attempt_auth(store):
    """auth_add must only record; it must never touch the network or auth."""
    sid = _svc(store, "10.1.1.5", 445).id
    state.auth_add(store, "10.1.1.5:445", "user", "pass")
    # No leads/results should be created by merely recording a credential.
    assert store.list_credentials(sid)  # recorded
    for lead in store.list_leads(sid):
        assert store.list_results(int(lead.id)) == []


def test_credentials_persist_across_reopen(tmp_path):
    """The credentials table is created on any store open and is durable."""
    db_file = tmp_path / "persist.db"
    s1 = Store(str(db_file))
    aid = s1.upsert_asset("10.9.9.9")
    sid = s1.upsert_service(aid, 445, name="netbios-ssn")
    s1.add_credential(sid, "guest", "(blank)", origin="smbclient")
    s1.close()

    s2 = Store(str(db_file))  # schema re-run; table must already exist
    creds = s2.list_credentials()
    assert len(creds) == 1
    assert creds[0].username == "guest"
    assert creds[0].origin == "smbclient"
    s2.close()


# The v1 schema predates the credentials table. Opening such a database with
# the current Store must migrate safely: preserve all existing data and add the
# new table without erroring or dropping anything.
_V1_SCHEMA = """
CREATE TABLE assets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL,
    hostname   TEXT,
    os         TEXT,
    created_at TEXT
);
CREATE UNIQUE INDEX idx_assets_ip ON assets(ip);
CREATE TABLE services (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port     INTEGER NOT NULL,
    proto    TEXT NOT NULL DEFAULT 'tcp',
    name     TEXT NOT NULL DEFAULT '',
    version  TEXT,
    banner   TEXT
);
CREATE UNIQUE INDEX idx_services_asset_port ON services(asset_id, port, proto);
CREATE TABLE observations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    text       TEXT NOT NULL,
    created_at TEXT
);
CREATE TABLE leads (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    title      TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'OPEN',
    reason     TEXT NOT NULL DEFAULT '',
    created_at TEXT,
    closed_at  TEXT
);
CREATE TABLE results (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    lead_id    INTEGER NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
    outcome    TEXT NOT NULL,
    evidence   TEXT NOT NULL DEFAULT '',
    created_at TEXT
);
CREATE TABLE coverage (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    activity   TEXT NOT NULL,
    tested     INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX idx_coverage_service_activity ON coverage(service_id, activity);
"""


def test_open_v1_db_migrates_and_preserves_data(tmp_path):
    """A database created before v2 (no credentials table) opens cleanly,
    keeps its existing rows, and gains a working credentials table."""
    import sqlite3

    db_file = tmp_path / "v1.db"
    con = sqlite3.connect(str(db_file))
    con.executescript(_V1_SCHEMA)
    con.execute(
        "INSERT INTO assets (ip, hostname, os, created_at) "
        "VALUES ('10.5.5.5', 'old.lab', 'Linux', '2026-01-01T00:00:00')"
    )
    con.execute(
        "INSERT INTO services (asset_id, port, name) VALUES (1, 445, 'netbios-ssn')"
    )
    con.commit()
    con.close()

    s = Store(str(db_file))  # migration must succeed
    assets = s.list_assets()
    assert len(assets) == 1
    assert assets[0].ip == "10.5.5.5"          # existing data preserved
    assert assets[0].hostname == "old.lab"
    sid = s.list_services(assets[0].id)[0].id

    # empty before adding, usable right after migration
    assert s.list_credentials() == []
    s.add_credential(sid, "guest", "(blank)", origin="smbclient")
    creds = s.list_credentials(sid)
    assert len(creds) == 1
    assert creds[0].username == "guest"
    s.close()

