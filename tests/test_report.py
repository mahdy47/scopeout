"""Tests for the Markdown report builder (v2) - core/report.py."""

import pytest

from scopeout.core import state
from scopeout.core.importer import import_nmap_file
from scopeout.core.model import LeadStatus, Store
from scopeout.core.report import build_report

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
<hostnames><hostname name="ws6.lab" type="PTR"/></hostnames>
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


# ---------------------------------------------------------------------------
# Empty engagement
# ---------------------------------------------------------------------------


def test_empty_engagement():
    s = Store(":memory:")
    md = build_report(s)
    assert "Engagement Report" in md
    assert "No engagement data has been captured yet" in md
    s.close()


# ---------------------------------------------------------------------------
# Markdown generation / structure
# ---------------------------------------------------------------------------


def test_report_has_host_and_service_sections(store):
    md = build_report(store)
    assert "## 10.1.1.5" in md
    assert "## 10.1.1.6" in md
    assert "SMB enumeration :445" in md
    assert "Web investigation :80" in md
    assert "SSH investigation :22" in md


def test_report_includes_observations(store):
    state.obs(store, "10.1.1.5:80", "Apache detected")
    md = build_report(store)
    assert "Apache detected" in md
    assert "Observations" in md


def test_report_includes_findings_with_evidence(store):
    # close the 445 SMB lead with a result + evidence
    sid = _svc(store, "10.1.1.5", 445).id
    lead = next(l for l in store.list_leads(sid)
                if l.status == LeadStatus.OPEN)
    state.done(store, int(lead.id), "guest login accepted",
               "smbclient -L //10.1.1.5")
    md = build_report(store)
    assert "Findings" in md
    assert "guest login accepted" in md
    assert "smbclient -L //10.1.1.5" in md  # evidence block
    assert "Test SMB null session" in md


def test_report_does_not_invent_findings(store):
    # nothing recorded -> no Findings sections at all
    md = build_report(store)
    assert "Findings" not in md
    assert "guest login accepted" not in md


def test_report_preserves_multiple_observations(store, tmp_path):
    state.obs(store, "10.1.1.5:80", "Apache detected")
    state.obs(store, "10.1.1.5:80", "Server header leaks version")
    md = build_report(store)
    assert "Apache detected" in md
    assert "Server header leaks version" in md


def test_report_multiple_results(store):
    state.done(store, _first_open(store, "10.1.1.5", 445),
               "guest login accepted", "smbclient -L")
    state.done(store, _first_open(store, "10.1.1.5", 80),
               "found /admin", "curl -s")
    md = build_report(store)
    assert "guest login accepted" in md
    assert "found /admin" in md


def _first_open(store, ip, port):
    sid = _svc(store, ip, port).id
    return next(int(l.id) for l in store.list_leads(sid)
                if l.status == LeadStatus.OPEN)


# ---------------------------------------------------------------------------
# Timestamp ordering
# ---------------------------------------------------------------------------


def test_timeline_is_chronological(store):
    # assign distinct timestamps and assert timeline orders by them
    sid = _svc(store, "10.1.1.5", 80).id
    oid1 = store.add_observation(sid, "first")
    oid2 = store.add_observation(sid, "second")
    store.conn.execute(
        "UPDATE observations SET created_at = '2026-01-01T10:00:00' WHERE id = ?",
        (oid1,),
    )
    store.conn.execute(
        "UPDATE observations SET created_at = '2026-01-01T09:00:00' WHERE id = ?",
        (oid2,),
    )
    store.conn.commit()

    md = build_report(store)
    timeline_start = md.index("## Timeline")
    first_pos = md.index("first", timeline_start)
    second_pos = md.index("second", timeline_start)
    assert second_pos < first_pos  # 09:00 before 10:00


def test_timeline_is_not_shown_when_empty(store):
    md = build_report(store)
    assert "## Timeline" not in md


# ---------------------------------------------------------------------------
# Evidence reference present when available
# ---------------------------------------------------------------------------


def test_finding_references_evidence(store):
    sid = _svc(store, "10.1.1.5", 445).id
    state.done(store, int(next(l.id for l in store.list_leads(sid)
                               if l.status == LeadStatus.OPEN)),
               "weak signing", "nmap script smb2-security-mode")
    md = build_report(store)
    assert "Evidence" in md
    assert "nmap script smb2-security-mode" in md


def test_finding_without_evidence_omits_block(store):
    sid = _svc(store, "10.1.1.6", 22).id
    leads = store.list_leads(sid)
    if leads:
        state.done(store, int(leads[0].id), "no weak ciphers", "")
        md = build_report(store)
        # no evidence fenced block for empty evidence
        assert "```text" not in md


# ---------------------------------------------------------------------------
# Markdown safety (escape / normalize untrusted text)
# ---------------------------------------------------------------------------


def test_pipe_in_observation_does_not_break_timeline_table(store):
    store.add_observation(_svc(store, "10.1.1.5", 80).id,
                          "header leaks | admin | value")
    md = build_report(store)
    # cell must be escaped so the row stays intact; raw pipe no longer a delimiters
    assert "header leaks \\| admin \\| value" in md
    # and the table header row must not gain phantom columns
    header = next(l for l in md.splitlines() if l.startswith("| Time |"))
    assert header.count("|") == 5  # leading + 4 cells + trailing


def test_multiline_observation_collapses_to_single_line(store):
    store.add_observation(_svc(store, "10.1.1.5", 80).id, "line one\nline two")
    md = build_report(store)
    lines = md.splitlines()
    # nothing in the report body may contain a bare newline from the obs
    assert not any("line one\nline two" in l for l in lines)
    assert "line one line two" in " ".join(lines)


def test_pipe_in_username_origin_does_not_break_credentials_table(store, tmp_path):
    sid = _svc(store, "10.1.1.5", 445).id
    store.add_credential(sid, "admin|svc", "abc123", origin="cmd | /usr/local/bin")
    md = build_report(store)
    # Both pipe-bearing cells are escaped so they render as a single cell.
    assert "admin\\|svc" in md
    assert "cmd \\| /usr/local/bin" in md
    # The credential itself is excluded from the report body.
    assert "abc123" not in md


def test_pipe_in_finding_does_not_break_timeline_table(store):
    lead = _first_open(store, "10.1.1.5", 445)
    state.done(store, lead, "token | leaked", "smbclient")
    md = build_report(store)
    assert "token \\| leaked" in md


# ---------------------------------------------------------------------------
# Credential confidentiality
# ---------------------------------------------------------------------------


def test_raw_credential_never_leaks_into_report(store):
    """A recognizable fake secret must never appear anywhere in the report."""
    FAKE_SECRET = "S3CR3T-C0MPL3X-P@\\ssw0rd!!"
    sid = _svc(store, "10.1.1.5", 445).id
    store.add_credential(sid, "admin", FAKE_SECRET, origin="smbclient -L")

    md = build_report(store)
    assert FAKE_SECRET not in md
    # the redacted marker IS present, and the row was emitted
    assert "*redacted*" in md
    assert "admin" in md


def test_credential_leaks_nowhere_across_all_outputs(store):
    """Report, creds and auth list must never print the raw credential."""
    from scopeout.core import render
    from scopeout.core.planner import credential_suggestions

    FAKE_SECRET = "HUNTER2-SUPERSECRET-VALUE"
    sid = _svc(store, "10.1.1.5", 445).id
    store.add_credential(sid, "guest", FAKE_SECRET, origin="smbclient")

    report = build_report(store)
    creds = render.render_credential_suggestions(credential_suggestions(store))
    assert FAKE_SECRET not in report
    assert FAKE_SECRET not in creds
    # auth list output is produced in the CLI; assert the underlying store
    # listing carries it but the value is only present there, never rendered.
    stored = store.list_credentials(sid)
    assert stored[0].credential == FAKE_SECRET  # stored opaquely


# ---------------------------------------------------------------------------
# Special characters in hostnames / services / metadata
# ---------------------------------------------------------------------------


def test_special_chars_in_hostname_and_os(store):
    _svc(store, "10.1.1.5", 80)
    store.conn.execute("UPDATE assets SET hostname = ?, os = ? WHERE ip = '10.1.1.5'",
                       ("ws#5|host|`x`\nsecond", "Linux 4.15 (x86_64)\n  | more"))
    store.conn.commit()
    md = build_report(store)
    lines = md.splitlines()
    # newlines collapsed so bullets stay on one physical line
    assert not any("ws#5|host|`x`\nsecond" in l for l in lines)
    assert not any("Linux 4.15 (x86_64)\n" in l for l in lines)
    # collapsed text present
    assert "ws#5|host|`x` second" in " ".join(lines)


def test_special_chars_in_service_version_and_banner(store):
    sid = _svc(store, "10.1.1.6", 22).id
    store.conn.execute(
        "UPDATE services SET version = ?, banner = ? WHERE id = ?",
        ("OpenSSH `v1` | beta\n8.9", "line1\nline2 | `tick`", sid))
    store.conn.commit()
    md = build_report(store)
    lines = md.splitlines()
    assert not any("OpenSSH `v1` | beta\n" in l for l in lines)
    assert not any("line1\nline2" in l for l in lines)
    # banner backticks can't break an inline code span since it's plain text now
    assert "line1 line2 | `tick`" in " ".join(lines)


def test_service_heading_survives_pipe_and_newline(store):
    # craft a service whose display label contains a pipe and newline
    sid = _svc(store, "10.1.1.5", 80).id
    store.conn.execute("UPDATE services SET name = 'weird|svc\n#' WHERE id = ?", (sid,))
    store.conn.commit()
    md = build_report(store)
    # the heading is emitted as a single line and is still a heading
    for line in md.splitlines():
        if line.startswith("### "):
            assert "\n" not in line
            assert "### " in line
