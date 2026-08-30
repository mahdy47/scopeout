"""Integration tests for the CLI (M4) - invoke scopeout.cli.main() in-process.

These exercise real argument parsing, dispatch, and a real on-disk SQLite store
(per-test temp db), so they cover the full user-facing surface.
"""

import pytest

from scopeout.cli import main, DEFAULT_DB

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
def db(tmp_path):
    p = tmp_path / "scan.xml"
    p.write_text(BASE, encoding="utf-8")
    db_file = str(tmp_path / "t.db")
    main(["--db", db_file, "import", str(p)])
    return db_file


def test_import_refuses_missing_file(tmp_path, capsys):
    rc = main(["--db", str(tmp_path / "x.db"), "import",
               str(tmp_path / "nope.xml")])
    assert rc == 1
    out = capsys.readouterr().err
    assert "no such file" in out


def test_import_then_leads(db, capsys):
    rc = main(["--db", db, "leads"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "NEXT LEADS" in out
    assert "10.1.1.5" in out


def test_leads_ascii_flag(db, capsys):
    rc = main(["--db", db, "--ascii", "leads"])
    assert rc == 0
    assert "NEXT LEADS" in capsys.readouterr().out


def test_coverage_board(db, capsys):
    rc = main(["--db", db, "--ascii", "coverage"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "10.1.1.5" in out
    assert "0/3 covered" in out    # fresh scan: nothing covered yet
    assert "[ ]" in out            # ASCII not-done mark


def test_coverage_single_host(db, capsys):
    rc = main(["--db", db, "--ascii", "coverage", "10.1.1.5"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "10.1.1.5" in out


def test_coverage_unknown_host_is_error(db, capsys):
    rc = main(["--db", db, "coverage", "192.0.2.9"])
    assert rc == 1
    assert "no asset" in capsys.readouterr().err


def test_status_shows_lead_ids(db, capsys):
    rc = main(["--db", db, "--ascii", "status", "10.1.1.5"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "[OPEN] 1 -" in out      # lead id surfaced for `done`


def test_status_no_host_shows_all(db, capsys):
    rc = main(["--db", db, "--ascii", "status"])
    assert rc == 0
    assert "10.1.1.5" in capsys.readouterr().out


def test_done_closes_lead_and_changes_board(db, capsys):
    # 445 is the first imported service -> its seeded lead has id 1
    rc = main(["--db", db, "--ascii", "done", "10.1.1.5:445", "1",
               "guest login accepted", "smbclient -L"])
    assert rc == 0
    # closing the 445 null-session lead removes the SMB service from the board
    rc = main(["--db", db, "--ascii", "leads"])
    out = capsys.readouterr().out
    assert "10.1.1.5:445" not in out


def test_done_wrong_host_rejected(db, capsys):
    # lead 1 belongs to 10.1.1.5:445; request it under a different host:port
    rc = main(["--db", db, "done", "10.1.1.5:80", "1", "x"])
    assert rc == 1
    assert "does not belong" in capsys.readouterr().err


def test_done_unknown_lead(db, capsys):
    rc = main(["--db", db, "done", "10.1.1.5:445", "9999", "x"])
    assert rc == 1
    assert "no lead" in capsys.readouterr().err


def test_note_and_obs(db, capsys):
    assert main(["--db", db, "obs", "10.1.1.5:80", "Apache"]) == 0
    assert main(["--db", db, "note", "10.1.1.5:80", "endpoint at /admin"]) == 0
    main(["--db", db, "--ascii", "status", "10.1.1.5"])
    out = capsys.readouterr().out
    assert "Apache" in out
    assert "endpoint at /admin" in out
