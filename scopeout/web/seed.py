"""Read-only data source for the web layer.

Persistence model
-----------------
scopeout's core is a local, synchronous SQLite ``Store``
(``scopeout.core.model.Store``). Vercel serverless functions run on an
**ephemeral, non-persistent** filesystem: any file written by one invocation
is gone by the next, and a checked-in SQLite database cannot be written in
production. A *writable* local SQLite file is therefore incompatible with a
serverless deployment.

By design (user decision), the web layer serves a **read-only snapshot**:

  * the snapshot is built ONCE from a real ScopeOut dataset
    (``examples/sample.xml``) through the **same core import logic** the CLI
    uses (``scopeout.core.importer.import_nmap_file``);
  * no fake data is ever shown, and nothing is written back to disk;
  * the API is read-only, so an in-memory store per warm function instance is
    safe and represents an identical, honest snapshot.

This is deliberately NOT advertised as a persistent, write-capable service. A
write-persistent deployment would require an external database (e.g.
Vercel/Neon Postgres or Turso/libSQL) behind a ``Store``-compatible adapter,
which is out of scope for the current milestone.
"""

from __future__ import annotations

import os
from pathlib import Path

from scopeout.core.importer import import_nmap_file
from scopeout.core.model import Store

# Default bundled seed dataset (real data included in the repository).
_DEFAULT_SEED = Path(__file__).resolve().parents[2] / "examples" / "sample.xml"


def _resolve_seed_path(seed_path: str | None) -> Path | None:
    """Resolve the seed XML path, honouring an explicit override or env var."""
    if seed_path is not None:
        p = Path(seed_path)
        return p if p.exists() else None
    env = os.environ.get("SCOPEOUT_WEB_SEED")
    if env:
        p = Path(env)
        return p if p.exists() else None
    return _DEFAULT_SEED if _DEFAULT_SEED.exists() else None


def create_store(seed_path: str | None = None) -> Store:
    """Build a read-only in-memory :class:`Store`.

    When a seed dataset is available it is imported through the core importer
    (identical to ``scopeout import <xml>``). When ``seed_path=":"`` is passed,
    or no seed resolves, an empty in-memory store is returned (used for the
    empty-database case and for tests).

    Callers MUST call ``store.close()`` when done.
    """
    store = Store(":memory:")
    path: Path | None = None
    if seed_path != ":":  # explicit empty sentinel
        path = _resolve_seed_path(seed_path)
    if path is not None:
        try:
            import_nmap_file(store, path)
        except (OSError, Exception):  # noqa: BLE001
            # A broken/missing seed should not take the whole service down;
            # fall back to an empty snapshot so the API still responds.
            store.close()
            store = Store(":memory:")
    return store
