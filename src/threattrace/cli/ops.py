from __future__ import annotations

import argparse
import sys
from collections.abc import Callable

Runner = Callable[[list[str]], None]


def _run_module(module: str, argv: list[str]) -> None:
    sys.argv = [sys.argv[0], *argv]
    mod = __import__(module, fromlist=["main"])
    result = mod.main()
    if isinstance(result, int):
        raise SystemExit(result)


def _run_cape_enrichment(argv: list[str]) -> None:
    sys.argv = [sys.argv[0], *argv]
    from threattrace.cape import evidence_enrichment

    raise SystemExit(evidence_enrichment.main())


def _set_runner(parser: argparse.ArgumentParser, runner: Runner, argv: list[str] | None = None) -> None:
    parser.set_defaults(runner=runner, mapped_argv=argv)


def _add_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    help_text: str,
    runner: Runner,
    argv: list[str] | None = None,
) -> None:
    _set_runner(subparsers.add_parser(name, help=help_text, add_help=False), runner, argv)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ThreatTrace operational launcher")
    sub = parser.add_subparsers(dest="command", required=True, metavar="{db,ingest,cape,detection,vr}")

    db = sub.add_parser("db", help="Database operations")
    db_sub = db.add_subparsers(dest="db_command", required=True)
    _add_command(db_sub, "init", "Initialize DB schema", lambda argv: _run_module("threattrace.cli.init_db", argv))
    _add_command(db_sub, "harden", "Apply DB hardening", lambda argv: _run_module("threattrace.db.hardening", argv))

    ingest = sub.add_parser("ingest", help="Ingestion operations")
    ingest_sub = ingest.add_subparsers(dest="ingest_command", required=True)
    _add_command(ingest_sub, "malwarebazaar", "Run MalwareBazaar ingest", lambda argv: _run_module("threattrace.cli.ingest_weekly", argv))
    _add_command(ingest_sub, "bootstrap", "Run initial MalwareBazaar ingest", lambda argv: _run_module("threattrace.cli.bootstrap_ingest", argv))
    _add_command(ingest_sub, "malshare", "Run MalShare ingest", lambda argv: _run_module("threattrace.malshare.ingest", argv))
    _add_command(ingest_sub, "malshare-repair", "Repair MalShare metadata", lambda argv: _run_module("threattrace.malshare.ingest", ["--repair-existing", *argv]))

    cape = sub.add_parser("cape", help="CAPE operations")
    cape_sub = cape.add_subparsers(dest="cape_command", required=True)
    _add_command(cape_sub, "batch", "Dispatch analysis batch", lambda argv: _run_module("threattrace.cli.run_daily_batch", argv))
    _add_command(cape_sub, "recover", "Recover failed runs", lambda argv: _run_module("threattrace.recovery.error_recovery", argv))
    _add_command(cape_sub, "enrich", "Plan CAPE evidence enrichment", _run_cape_enrichment)
    _add_command(cape_sub, "archive", "Archive completed analyses", lambda argv: _run_module("threattrace.cape.archive", argv))

    detection = sub.add_parser("detection", help="Detection outputs")
    detection_sub = detection.add_subparsers(dest="detection_command", required=True)
    _add_command(detection_sub, "export", "Export detection IoCs", lambda argv: _run_module("threattrace.detection.ioc_export", argv))
    _add_command(detection_sub, "artifacts", "Generate Velociraptor artifacts", lambda argv: _run_module("threattrace.detection.velociraptor_artifacts", argv))

    vr = sub.add_parser("vr", help="Velociraptor validation")
    vr_sub = vr.add_subparsers(dest="vr_command", required=True)
    commands: tuple[tuple[str, str, str], ...] = (
        ("select", "Select samples", "select-samples"),
        ("prepare", "Prepare staged package", "prepare-sample-package"),
        ("plan", "Write validation plan", "first-test-plan"),
        ("collect", "Start artifact collection", "run-collection"),
        ("export", "Export artifact rows", "export-result"),
        ("compare", "Compare expected and observed results", "compare-results"),
        ("revert", "Revert VM snapshot", "revert-client"),
        ("flows", "List recent flows", "list-flows"),
        ("cleanup-flows", "Cancel stale flows", "cleanup-flows"),
        ("status", "Show validation status", "status"),
    )
    for name, help_text, mapped in commands:
        _add_command(vr_sub, name, help_text, lambda argv, command=mapped: _run_module("threattrace.velociraptor.vr_validation", [command, *argv]))
    _add_command(vr_sub, "process", "Process one sample", lambda argv: _run_module("threattrace.velociraptor.vr_process_sample", argv))
    _add_command(vr_sub, "batch", "Process samples sequentially", lambda argv: _run_module("threattrace.velociraptor.vr_batch", argv))
    _add_command(vr_sub, "import-detections", "Import archived detections", lambda argv: _run_module("threattrace.velociraptor.vr_persistence", argv))
    _add_command(vr_sub, "network", "Network isolation operations", lambda argv: _run_module("threattrace.velociraptor.vr_network_security", argv))

    return parser


def main() -> None:
    parser = build_parser()
    args, rest = parser.parse_known_args()
    runner: Runner = args.runner
    runner([*(args.mapped_argv or []), *rest])


if __name__ == "__main__":
    main()
