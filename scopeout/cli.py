"""scopeout command-line interface (M4 + v2).

Commands:
    import  <nmap.xml>               ingest an nmap -oX scan
    leads                             prioritized NEXT LEADS board
    coverage [host]                   coverage board per service
    done    <host:port> <lead_id> [outcome] [evidence]
    note    <host:port> "text"
    obs     <host:port> "text"
    status  [host]                    investigation tree for a host (or all)
    report  [--output FILE]           generate a Markdown engagement report
    creds                             credential-reuse suggestions (v2)
    auth add <host:port> <user> <cred> [origin]   record a credential (v2)
    auth list [host:port]             list recorded credentials (v2)

Global options:
    --db PATH     SQLite database file (default ./scopeout.db)
    --ascii       force ASCII glyphs instead of UTF-8 (✓/✗)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .core import state
from .core.importer import import_nmap_file
from .core.model import Store
from .core.planner import next_leads, credential_suggestions
from .core import render
from .core.report import build_report

DEFAULT_DB = "scopeout.db"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scopeout",
        description="Engagement-state engine for penetration testing - "
                    "assets, services, leads, coverage, decision support.",
    )
    p.add_argument("--db", default=DEFAULT_DB, help="SQLite database file")
    p.add_argument("--ascii", action="store_true",
                   help="use ASCII glyphs instead of UTF-8 marks")

    sub = p.add_subparsers(dest="command", required=True)

    sp_import = sub.add_parser("import", help="ingest an nmap -oX scan")
    sp_import.add_argument("xml", help="path to nmap XML (-oX) file")

    sub.add_parser("leads", help="show the prioritized NEXT LEADS board")

    sp_cov = sub.add_parser("coverage", help="coverage board per service")
    sp_cov.add_argument("host", nargs="?", default=None,
                        help="restrict to one host (ip)")

    sp_done = sub.add_parser("done", help="close a lead with an outcome")
    sp_done.add_argument("spec", help="<host:port> the lead belongs to")
    sp_done.add_argument("lead_id", type=int, help="lead id (see `status`)")
    sp_done.add_argument("outcome", nargs="?", default="checked, see evidence",
                         help="what was found (default: 'checked, see evidence')")
    sp_done.add_argument("evidence", nargs="?", default="",
                         help="supporting command/output")

    for name in ("note", "obs"):
        s = sub.add_parser(name, help=f"add an observation to a service ({name})")
        s.add_argument("spec", help="<host:port>")
        s.add_argument("text", help="free text")

    sp_status = sub.add_parser("status", help="show the investigation tree")
    sp_status.add_argument("host", nargs="?", default=None,
                           help="restrict to one host (ip); defaults to all")

    sp_report = sub.add_parser("report", help="generate a Markdown engagement report")
    sp_report.add_argument("--output", "-o", default=None,
                           help="write the report to a file instead of stdout")

    sub.add_parser("creds", help="credential-reuse suggestions (decision support)")

    sp_auth = sub.add_parser("auth", help="credential inventory (decision support)")
    auth_sub = sp_auth.add_subparsers(dest="auth_action", required=True)

    sp_auth_add = auth_sub.add_parser("add", help="record a credential")
    sp_auth_add.add_argument("spec", help="<host:port> where it was observed/tested")
    sp_auth_add.add_argument("username", help="username")
    sp_auth_add.add_argument("credential", help="credential or reference")
    sp_auth_add.add_argument("origin", nargs="?", default="",
                             help="where it was observed (optional)")

    sp_auth_list = auth_sub.add_parser("list", help="list recorded credentials")
    sp_auth_list.add_argument("spec", nargs="?", default=None,
                              help="<host:port> to filter, or all if omitted")

    return p


def _marks(args) -> dict:
    if args.ascii:
        return render.ASCII_MARKS
    if render.supports_unicode():
        return render.UNICODE_MARKS
    return render.ASCII_MARKS


def _open_store(args) -> Store:
    return Store(args.db)


def _select_assets(store, host: str | None) -> list:
    assets = store.list_assets()
    if host is not None:
        assets = [a for a in assets if a.ip == host]
        if not assets:
            raise state.ScopeoutError(f"no asset with ip {host!r}")
    return assets


def cmd_import(args) -> int:
    store = _open_store(args)
    try:
        summary = import_nmap_file(store, args.xml)
    except FileNotFoundError:
        print(f"scopeout: no such file: {args.xml}", file=sys.stderr)
        return 1
    finally:
        store.close()
    print(
        f"imported {summary['assets']} assets, {summary['services']} services"
        f" (seeded {summary['seeded']['coverage']} coverage items,"
        f" {summary['seeded']['leads']} leads)"
    )
    for h in summary["hosts"]:
        print(f"  {h['ip']:<18} {h['services']} service(s)")
    return 0


def cmd_leads(args) -> int:
    store = _open_store(args)
    try:
        board = next_leads(store)
    finally:
        store.close()
    print(render.render_leads(board))
    return 0


def cmd_coverage(args) -> int:
    store = _open_store(args)
    marks = _marks(args)
    done, notdone = marks["done"], marks["notdone"]
    try:
        assets = _select_assets(store, args.host)
        for asset in assets:
            print(f"\n{asset.ip}")
            print("-" * len(asset.ip))
            for svc in store.list_services(int(asset.id)):
                cov = store.list_coverage(int(svc.id))
                if not cov:
                    print(f"  :{svc.port} ({svc.name or 'unknown'}) - no coverage items")
                    continue
                tested = sum(1 for c in cov if c.tested)
                print(f"  :{svc.port} ({svc.name or 'unknown'})  "
                      f"{tested}/{len(cov)} covered")
                for c in cov:
                    mark = done if c.tested else notdone
                    print(f"    {mark} {c.activity}")
    except state.ScopeoutError as e:
        print(f"scopeout: {e}", file=sys.stderr)
        return 1
    finally:
        store.close()
    return 0


def cmd_done(args) -> int:
    store = _open_store(args)
    try:
        # Resolve the service + lead, and validate the lead belongs to it.
        sid = state._resolve_service(store, args.spec)
        lead = next((l for l in store.list_leads() if l.id == args.lead_id), None)
        if lead is None:
            raise state.ScopeoutError(f"no lead with id {args.lead_id}")
        if int(lead.service_id) != sid:
            raise state.ScopeoutError(
                f"lead {args.lead_id} does not belong to {args.spec}"
            )
        state.done(store, args.lead_id, args.outcome, args.evidence)
    except state.ScopeoutError as e:
        print(f"scopeout: {e}", file=sys.stderr)
        return 1
    finally:
        store.close()
    print(f"lead {args.lead_id} marked DONE: {args.outcome}")
    return 0


def cmd_observational(args, kind: str) -> int:
    store = _open_store(args)
    try:
        if kind == "obs":
            state.obs(store, args.spec, args.text)
        else:
            state.note(store, args.spec, args.text)
    except state.ScopeoutError as e:
        print(f"scopeout: {e}", file=sys.stderr)
        return 1
    finally:
        store.close()
    print(f"added observation to {args.spec}")
    return 0


def cmd_status(args) -> int:
    store = _open_store(args)
    marks = _marks(args)
    try:
        assets = _select_assets(store, args.host)
        for i, asset in enumerate(assets):
            print(render.render_status(store, asset, marks=marks))
            if i != len(assets) - 1:
                print()
    except state.ScopeoutError as e:
        print(f"scopeout: {e}", file=sys.stderr)
        return 1
    finally:
        store.close()
    return 0


def cmd_report(args) -> int:
    store = _open_store(args)
    try:
        md = build_report(store)
    finally:
        store.close()
    if args.output:
        try:
            Path(args.output).write_text(md, encoding="utf-8")
        except OSError as e:
            print(f"scopeout: could not write report: {e}", file=sys.stderr)
            return 1
        print(f"report written to {args.output}")
    else:
        print(md)
    return 0


def cmd_creds(args) -> int:
    store = _open_store(args)
    try:
        suggestions = credential_suggestions(store)
    finally:
        store.close()
    print(render.render_credential_suggestions(suggestions))
    return 0


def cmd_auth_add(args) -> int:
    store = _open_store(args)
    try:
        res = state.auth_add(store, args.spec, args.username, args.credential,
                             origin=args.origin)
    except state.ScopeoutError as e:
        print(f"scopeout: {e}", file=sys.stderr)
        return 1
    finally:
        store.close()
    print(
        f"recorded credential for {args.username} (id {res['credential_id']}) "
        f"on {args.spec}"
    )
    return 0


def cmd_auth_list(args) -> int:
    store = _open_store(args)
    try:
        if args.spec:
            sid = state._resolve_service(store, args.spec)
            creds = store.list_credentials(sid)
            label = args.spec
        else:
            creds = store.list_credentials()
            label = "all services"
    except state.ScopeoutError as e:
        print(f"scopeout: {e}", file=sys.stderr)
        return 1
    finally:
        store.close()

    if not creds:
        print(f"no credentials recorded for {label}")
        return 0
    print(f"credentials ({label}):")
    for c in creds:
        origin = f"  origin: {c.origin}" if c.origin else ""
        print(f"  [{c.id}] {c.username} @ service {c.service_id} (id){origin}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    dispatch = {
        "import": cmd_import,
        "leads": cmd_leads,
        "coverage": cmd_coverage,
        "done": cmd_done,
        "note": lambda a: cmd_observational(a, "note"),
        "obs": lambda a: cmd_observational(a, "obs"),
        "status": cmd_status,
        "report": cmd_report,
        "creds": cmd_creds,
        "auth": _cmd_auth_dispatch,
    }
    return dispatch[args.command](args)


def _cmd_auth_dispatch(args) -> int:
    if args.auth_action == "add":
        return cmd_auth_add(args)
    return cmd_auth_list(args)


if __name__ == "__main__":
    sys.exit(main())
