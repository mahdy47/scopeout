"""Core data model for scopeout.

Entities:

    Asset -> Service -> [Observation, Lead, Coverage]
                             |
                           Lead -> Result

An Asset is a discovered host. Each Service (ip:port/proto/name) on an Asset
carries:
  - observations (free-text recon findings, e.g. "Apache detected")
  - leads (investigation hypotheses / next-step items, with a lifecycle)
  - coverage items (methodology activities that mark "tested / not tested")

The state captured here is what drives the planner (decision support) in a
later milestone.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


def utcnow() -> str:
    """ISO-8601 UTC timestamp string used across the store."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class LeadStatus(str, Enum):
    OPEN = "OPEN"
    DONE = "DONE"
    BLOCKED = "BLOCKED"


# ---------------------------------------------------------------------------
# Plain data holders (used when reading entities out of the store)
# ---------------------------------------------------------------------------


@dataclass
class Asset:
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    id: Optional[int] = None
    created_at: str = field(default_factory=utcnow)


@dataclass
class Service:
    asset_id: int
    port: int
    proto: str = "tcp"
    name: str = ""
    version: Optional[str] = None
    banner: Optional[str] = None
    id: Optional[int] = None


@dataclass
class Observation:
    service_id: int
    text: str
    id: Optional[int] = None
    created_at: str = field(default_factory=utcnow)


@dataclass
class Lead:
    service_id: int
    title: str
    status: LeadStatus = LeadStatus.OPEN
    reason: str = ""
    id: Optional[int] = None
    created_at: str = field(default_factory=utcnow)
    closed_at: Optional[str] = None


@dataclass
class Result:
    lead_id: int
    outcome: str
    evidence: str = ""
    id: Optional[int] = None
    created_at: str = field(default_factory=utcnow)


@dataclass
class CoverageItem:
    service_id: int
    activity: str
    tested: bool = False
    id: Optional[int] = None


@dataclass
class Credential:
    service_id: int
    username: str
    credential: str
    origin: str = ""
    id: Optional[int] = None
    created_at: str = field(default_factory=utcnow)


# ---------------------------------------------------------------------------
# The store: owns the SQLite schema + row<->dataclass mapping.
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL,
    hostname   TEXT,
    os         TEXT,
    created_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);

CREATE TABLE IF NOT EXISTS services (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port     INTEGER NOT NULL,
    proto    TEXT NOT NULL DEFAULT 'tcp',
    name     TEXT NOT NULL DEFAULT '',
    version  TEXT,
    banner   TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_services_asset_port
    ON services(asset_id, port, proto);

CREATE TABLE IF NOT EXISTS observations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    text       TEXT NOT NULL,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS leads (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    title      TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'OPEN',
    reason     TEXT NOT NULL DEFAULT '',
    created_at TEXT,
    closed_at  TEXT
);

CREATE TABLE IF NOT EXISTS results (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    lead_id    INTEGER NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
    outcome    TEXT NOT NULL,
    evidence   TEXT NOT NULL DEFAULT '',
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS coverage (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    activity   TEXT NOT NULL,
    tested     INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_coverage_service_activity
    ON coverage(service_id, activity);

CREATE TABLE IF NOT EXISTS credentials (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    username   TEXT NOT NULL,
    credential TEXT NOT NULL,
    origin     TEXT NOT NULL DEFAULT '',
    created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_credentials_service
    ON credentials(service_id);
"""


class Store:
    def __init__(self, path: str = ":memory:"):
        # check_same_thread=False allows the read-only web layer (which runs
        # handlers in a threadpool) to query the store from any thread. The CLI
        # is single-threaded, so this is a no-op there. The web layer only
        # reads, so there is no concurrent-write hazard to serialize.
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # -- assets -------------------------------------------------------------

    def upsert_asset(self, ip: str, hostname: Optional[str] = None,
                     os: str | None = None) -> int:
        cur = self.conn.execute(
            "SELECT id FROM assets WHERE ip = ?", (ip,)
        )
        row = cur.fetchone()
        if row:
            self.conn.execute(
                "UPDATE assets SET hostname = COALESCE(?, hostname),"
                " os = COALESCE(?, os) WHERE id = ?",
                (hostname, os, row["id"]),
            )
            self.conn.commit()
            return int(row["id"])
        cur = self.conn.execute(
            "INSERT INTO assets (ip, hostname, os, created_at)"
            " VALUES (?, ?, ?, ?)",
            (ip, hostname, os, utcnow()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def get_asset(self, asset_id: int) -> Optional[Asset]:
        row = self.conn.execute(
            "SELECT * FROM assets WHERE id = ?", (asset_id,)
        ).fetchone()
        return self._asset(row) if row else None

    def list_assets(self) -> list[Asset]:
        rows = self.conn.execute("SELECT * FROM assets ORDER BY ip").fetchall()
        return [self._asset(r) for r in rows]

    @staticmethod
    def _asset(r: sqlite3.Row) -> Asset:
        return Asset(id=r["id"], ip=r["ip"], hostname=r["hostname"], os=r["os"],
                     created_at=r["created_at"])

    # -- services -----------------------------------------------------------

    def upsert_service(self, asset_id: int, port: int, proto: str = "tcp",
                       name: str = "", version: Optional[str] = None,
                       banner: Optional[str] = None) -> int:
        cur = self.conn.execute(
            "SELECT id FROM services WHERE asset_id = ? AND port = ? AND proto = ?",
            (asset_id, port, proto),
        )
        row = cur.fetchone()
        if row:
            self.conn.execute(
                "UPDATE services SET name = COALESCE(NULLIF(?, ''), name),"
                " version = COALESCE(?, version), banner = COALESCE(?, banner)"
                " WHERE id = ?",
                (name, version, banner, row["id"]),
            )
            self.conn.commit()
            return int(row["id"])
        cur = self.conn.execute(
            "INSERT INTO services (asset_id, port, proto, name, version, banner)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (asset_id, port, proto, name, version, banner),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def list_services(self, asset_id: Optional[int] = None) -> list[Service]:
        if asset_id is None:
            rows = self.conn.execute("SELECT * FROM services ORDER BY asset_id, port").fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM services WHERE asset_id = ? ORDER BY port",
                (asset_id,),
            ).fetchall()
        return [self._service(r) for r in rows]

    @staticmethod
    def _service(r: sqlite3.Row) -> Service:
        return Service(id=r["id"], asset_id=r["asset_id"], port=r["port"],
                       proto=r["proto"], name=r["name"], version=r["version"],
                       banner=r["banner"])

    # -- observations -------------------------------------------------------

    def add_observation(self, service_id: int, text: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO observations (service_id, text, created_at)"
            " VALUES (?, ?, ?)",
            (service_id, text, utcnow()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def list_observations(self, service_id: int) -> list[Observation]:
        rows = self.conn.execute(
            "SELECT * FROM observations WHERE service_id = ? ORDER BY id",
            (service_id,),
        ).fetchall()
        return [
            Observation(id=r["id"], service_id=r["service_id"], text=r["text"],
                        created_at=r["created_at"])
            for r in rows
        ]

    # -- leads --------------------------------------------------------------

    def add_lead(self, service_id: int, title: str, reason: str = "") -> int:
        cur = self.conn.execute(
            "INSERT INTO leads (service_id, title, status, reason, created_at)"
            " VALUES (?, ?, 'OPEN', ?, ?)",
            (service_id, title, reason, utcnow()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def set_lead_status(self, lead_id: int, status: LeadStatus) -> None:
        self.conn.execute(
            "UPDATE leads SET status = ?, closed_at = ? WHERE id = ?",
            (status.value, utcnow() if status != LeadStatus.OPEN else None,
             lead_id),
        )
        self.conn.commit()

    def list_leads(self, service_id: Optional[int] = None,
                   status: Optional[LeadStatus] = None) -> list[Lead]:
        sql = "SELECT * FROM leads"
        clauses, params = [], []
        if service_id is not None:
            clauses.append("service_id = ?")
            params.append(service_id)
        if status is not None:
            clauses.append("status = ?")
            params.append(status.value)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id"
        rows = self.conn.execute(sql, tuple(params)).fetchall()
        return [
            Lead(id=r["id"], service_id=r["service_id"], title=r["title"],
                 status=LeadStatus(r["status"]), reason=r["reason"],
                 created_at=r["created_at"], closed_at=r["closed_at"])
            for r in rows
        ]

    # -- results ------------------------------------------------------------

    def add_result(self, lead_id: int, outcome: str, evidence: str = "") -> int:
        cur = self.conn.execute(
            "INSERT INTO results (lead_id, outcome, evidence, created_at)"
            " VALUES (?, ?, ?, ?)",
            (lead_id, outcome, evidence, utcnow()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def list_results(self, lead_id: int) -> list[Result]:
        rows = self.conn.execute(
            "SELECT * FROM results WHERE lead_id = ? ORDER BY id", (lead_id,)
        ).fetchall()
        return [
            Result(id=r["id"], lead_id=r["lead_id"], outcome=r["outcome"],
                   evidence=r["evidence"], created_at=r["created_at"])
            for r in rows
        ]

    # -- coverage -----------------------------------------------------------

    def set_coverage(self, service_id: int, activity: str, tested: bool) -> None:
        row = self.conn.execute(
            "SELECT id FROM coverage WHERE service_id = ? AND activity = ?",
            (service_id, activity),
        ).fetchone()
        if row:
            self.conn.execute(
                "UPDATE coverage SET tested = ? WHERE id = ?",
                (1 if tested else 0, row["id"]),
            )
        else:
            self.conn.execute(
                "INSERT INTO coverage (service_id, activity, tested) VALUES (?, ?, ?)",
                (service_id, activity, 1 if tested else 0),
            )
        self.conn.commit()

    def list_coverage(self, service_id: int) -> list[CoverageItem]:
        rows = self.conn.execute(
            "SELECT * FROM coverage WHERE service_id = ? ORDER BY activity",
            (service_id,),
        ).fetchall()
        return [
            CoverageItem(id=r["id"], service_id=r["service_id"],
                         activity=r["activity"], tested=bool(r["tested"]))
            for r in rows
        ]

    # -- credentials ---------------------------------------------------------

    def add_credential(self, service_id: int, username: str, credential: str,
                       origin: str = "") -> int:
        cur = self.conn.execute(
            "INSERT INTO credentials (service_id, username, credential,"
            " origin, created_at) VALUES (?, ?, ?, ?, ?)",
            (service_id, username, credential, origin, utcnow()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def list_credentials(self, service_id: Optional[int] = None) -> list[Credential]:
        if service_id is None:
            rows = self.conn.execute(
                "SELECT * FROM credentials ORDER BY id").fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM credentials WHERE service_id = ? ORDER BY id",
                (service_id,),
            ).fetchall()
        return [
            Credential(id=r["id"], service_id=r["service_id"],
                       username=r["username"], credential=r["credential"],
                       origin=r["origin"], created_at=r["created_at"])
            for r in rows
        ]
