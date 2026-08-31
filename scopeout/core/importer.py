"""nmap XML (-oX) importer.

Parses an nmap scan's `-oX` XML output and populates the scopeout store with
Asset and Service entities. Tested/coverage and lead seeding is NOT done here
(that belongs to presets + state in a later milestone) - this milestone only
imports discovery facts.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .model import Store
from .presets import seed_service

# Common service names whose entries often carry a version product string.
_VERSION_HINTS = {"ssh", "http", "https", "smb", "ftp", "smb2", "netbios-ssn"}


def _clean(text: str | None) -> str | None:
    if text is None:
        return None
    return " ".join(text.split())


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Return a list of import dicts from an nmap XML document.

    Each dict looks like::

        {
            "ip": "10.0.0.1",
            "hostname": None,
            "os": None,
            "services": [
                {"port": 22, "proto": "tcp", "name": "ssh",
                 "version": "OpenSSH 8.2p1", "banner": None},
                ...
            ],
        }
    """
    root = ET.fromstring(xml_text)
    hosts: list[dict] = []

    for host in root.iter("host"):
        # Address
        ip = None
        for addr in host.iter("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr")
                break
        if not ip:
            continue

        # Hostname
        hostname = None
        for hname in host.iter("hostname"):
            hostname = hname.get("name")
            if hostname:
                break

        # OS (first <osmatch> guess)
        os_guess = None
        for osmatch in host.iter("osmatch"):
            os_guess = osmatch.get("name")
            break

        # Services
        services = []
        for port in host.iter("port"):
            port_state = port.find("state")
            if port_state is None or port_state.get("state") != "open":
                continue
            svc = port.find("service")
            port_id = port.get("portid")
            proto = port.get("protocol") or "tcp"
            name = svc.get("name", "") if svc is not None else ""
            version = None
            banner = None
            if svc is not None:
                prod = svc.get("product")
                ver = svc.get("version")
                if prod or ver:
                    version = _clean(
                        f"{prod or ''}{' ' + ver if ver else ''}".strip()
                    ) or None
                if name in _VERSION_HINTS:
                    banner = _clean(
                        f"{prod or ''} {ver or ''} {svc.get('extrainfo', '')}"
                    ).strip() or None
            # port-id may carry trailing slashes on some nmap versions
            port_num = _parse_port(port_id, proto)
            if port_num is None:
                continue
            services.append({
                "port": port_num,
                "proto": proto,
                "name": name,
                "version": version,
                "banner": banner,
            })

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "os": os_guess,
            "services": services,
        })

    return hosts


def _parse_port(port_id: str, proto: str) -> int | None:
    txt = port_id.strip().rstrip("/")
    try:
        return int(txt)
    except ValueError:
        return None


def import_nmap_file(store: Store, path: str | Path) -> dict:
    """Parse an nmap `-oX` file into the store.

    Returns a summary dict::

        {
          "assets": 2,
          "services": 5,
          "seeded": {"coverage": 11, "leads": 6},
          "hosts": [
              {"ip": "10.10.10.25", "services": 3, "seeded_cov": 8, "seeded_leads": 5},
              ...
          ],
        }
    """
    _reject_url(str(path))
    xml_text = Path(path).read_text(encoding="utf-8")
    hosts = parse_nmap_xml(xml_text)

    assets = 0
    services = 0
    total_cov = 0
    total_leads = 0
    detail = []
    for h in hosts:
        asset_id = store.upsert_asset(
            ip=h["ip"], hostname=h["hostname"], os=h["os"]
        )
        assets += 1
        svc_count = 0
        for s in h["services"]:
            service_id = store.upsert_service(
                asset_id=asset_id,
                port=s["port"],
                proto=s["proto"],
                name=s["name"],
                version=s["version"],
                banner=s["banner"],
            )
            seeded = seed_service(store, service_id, s["name"] or "")
            total_cov += len(seeded["coverage"])
            total_leads += len(seeded["leads"])
            svc_count += 1
        services += svc_count
        detail.append({"ip": h["ip"], "services": svc_count})

    return {
        "assets": assets,
        "services": services,
        "seeded": {"coverage": total_cov, "leads": total_leads},
        "hosts": detail,
    }


def _reject_url(path: str) -> None:
    # Guard / helper - import_nmap_file reads a local file only; any URL-ish
    # input should be an error rather than a silent read.
    if re.match(r"^https?://", path):
        raise ValueError(f"expected a local nmap XML path, got URL: {path}")
