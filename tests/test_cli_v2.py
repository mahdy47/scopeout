"""CLI integration tests for v2 (report + auth + creds)."""

import pytest

from scopeout.cli import main

BASE = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun version="7.94" xmloutputversion="1.04">
<host><status state="up"/>
<address addr="10.1.1.5" addrtype="ipv4"/>
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
def db(tmp_path):
    p = tmp_path / "scan.xml"
    p.write_text(BASE, encoding="utf-8")
    db_file = str(tmp_path / "t.db")
    main(["--db", db_file, "import", str(p)])
    return db_file


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


def test_report_to_stdout(db, capsys):
    rc = main(["--db", db, "report"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "# Engagement Report" in out
    assert "10.1.1.5" in out


def test_report_output_file(db, tmp_path, capsys):
    out_path = tmp_path / "report.md"
    rc = main(["--db", db, "report", "--output", str(out_path)])
    assert rc == 0
    assert "report written to" in capsys.readouterr().out
    content = out_path.read_text(encoding="utf-8")
    assert "# Engagement Report" in content


def test_report_uses_recorded_findings(db, capsys):
    main(["--db", db, "done", "10.1.1.5:445", "1",
          "guest login accepted", "smbclient -L"])
    main(["--db", db, "report"])
    out = capsys.readouterr().out
    assert "guest login accepted" in out
    assert "smbclient -L" in out


# ---------------------------------------------------------------------------
# auth + creds
# ---------------------------------------------------------------------------


def test_auth_add(db, capsys):
    rc = main(["--db", db, "auth", "add", "10.1.1.5:445", "guest",
               "(blank)", "smbclient"])
    assert rc == 0
    assert "recorded credential for guest" in capsys.readouterr().out


def test_auth_add_unknown_service(db, capsys):
    rc = main(["--db", db, "auth", "add", "10.1.1.5:9999", "x", "y"])
    assert rc == 1
    assert "no open service" in capsys.readouterr().err


def test_auth_list_empty(db, capsys):
    rc = main(["--db", db, "auth", "list"])
    assert rc == 0
    assert "no credentials recorded" in capsys.readouterr().out


def test_auth_list_after_add(db, capsys):
    main(["--db", db, "auth", "add", "10.1.1.5:445", "guest", "(blank)"])
    rc = main(["--db", db, "auth", "list"])
    assert rc == 0
    assert "guest" in capsys.readouterr().out


def test_creds_empty(db, capsys):
    rc = main(["--db", db, "creds"])
    assert rc == 0
    assert "credential-reuse" in capsys.readouterr().out


def test_creds_after_add_suggests_related(db, capsys):
    # credential on 10.1.1.5:445 (SMB) should surface 10.1.1.6:445 (SMB)
    main(["--db", db, "auth", "add", "10.1.1.5:445", "guest", "(blank)"])
    rc = main(["--db", db, "creds"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "10.1.1.6:445" in out
    # must not claim any auto-auth
    assert "no automated checks" in out


def test_creds_preserves_decision_support_only(db, capsys):
    main(["--db", db, "auth", "add", "10.1.1.5:445", "guest", "(blank)"])
    main(["--db", db, "creds"])
    out = capsys.readouterr().out
    assert "suggestions only" in out
    assert "observed/tested" in out
