"""Tests for the nmap XML importer (M1)."""

import xml.etree.ElementTree as ET

import pytest

from scopeout.core.importer import import_nmap_file, parse_nmap_xml
from scopeout.core.model import Store

SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun version="7.94" xmloutputversion="1.04">
<host><status state="up"/>
<address addr="10.1.1.5" addrtype="ipv4"/>
<hostnames><hostname name="ws5.lab" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2p1"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.41"/></port>
<port protocol="tcp" portid="445"><state state="open"/><service name="netbios-ssn"/></port>
<port protocol="tcp" portid="999"><state state="closed"/><service name="tcpwrapped"/></port>
</ports>
<osmatch name="Linux 4.15 - 5.8 (91%)"/>
</host>
<host><status state="up"/>
<address addr="10.1.1.6" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1"/></port>
</ports>
</host>
</nmaprun>
"""


def test_parse_nmap_xml_structure():
    hosts = parse_nmap_xml(SAMPLE)
    assert len(hosts) == 2
    ws5 = hosts[0]
    assert ws5["ip"] == "10.1.1.5"
    assert ws5["hostname"] == "ws5.lab"
    assert ws5["os"] == "Linux 4.15 - 5.8 (91%)"
    # closed port excluded
    assert len(ws5["services"]) == 3
    ports = [s["port"] for s in ws5["services"]]
    assert ports == [22, 80, 445]
    assert ws5["services"][0]["version"] == "OpenSSH 8.2p1"


def test_parse_closed_port_excluded():
    hosts = parse_nmap_xml(SAMPLE)
    ports = [s["port"] for s in hosts[0]["services"]]
    assert 999 not in ports


def test_import_nmap_file_populates_store(tmp_path):
    xml_path = tmp_path / "scan.xml"
    xml_path.write_text(SAMPLE, encoding="utf-8")
    store = Store(":memory:")
    summary = import_nmap_file(store, xml_path)

    assert summary["assets"] == 2
    assert summary["services"] == 4

    assets = store.list_assets()
    assert [a.ip for a in assets] == ["10.1.1.5", "10.1.1.6"]
    ws5 = next(a for a in assets if a.ip == "10.1.1.5")
    assert ws5.hostname == "ws5.lab"
    assert len(store.list_services(ws5.id)) == 3

    svc22 = next(s for s in store.list_services(ws5.id) if s.port == 22)
    assert svc22.name == "ssh"
    assert svc22.version == "OpenSSH 8.2p1"
    store.close()


def test_reimport_is_idempotent(tmp_path):
    xml_path = tmp_path / "scan.xml"
    xml_path.write_text(SAMPLE, encoding="utf-8")
    store = Store(":memory:")
    import_nmap_file(store, xml_path)
    import_nmap_file(store, xml_path)
    assert len(store.list_assets()) == 2
    ws5 = next(a for a in store.list_assets() if a.ip == "10.1.1.5")
    assert len(store.list_services(ws5.id)) == 3
    store.close()


def test_invalid_xml_raises():
    with pytest.raises(ET.ParseError):
        parse_nmap_xml("<nmaprun><broken></nmaprun>")
