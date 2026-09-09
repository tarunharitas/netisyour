"""Command-line interface for Sentinel NIDS.

Run `sentinel-nids --help` (or `python -m nids.cli --help`) after installing
the package for full usage.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import yaml

from .database import Database
from .pipeline import Pipeline, run_live_capture, run_pcap_analysis


DEFAULT_CONFIG_PATH = "config.yaml"


def load_config(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        print(f"Config file not found: {path}", file=sys.stderr)
        sys.exit(1)
    with p.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _db_from_config(config: dict) -> Database:
    db_path = config.get("database", {}).get("path", "nids.db")
    return Database(db_path)


def cmd_init_db(args, config: dict) -> None:
    db = _db_from_config(config)
    db.init_db()
    print(f"Initialized database at {db.path}")


def cmd_monitor(args, config: dict) -> None:
    db = _db_from_config(config)
    db.init_db()
    pipeline = Pipeline(config, db)

    bpf_filter = config.get("capture", {}).get("bpf_filter")
    print(f"Monitoring {args.interface}; Ctrl+C to stop")
    start = time.time()
    try:
        run_live_capture(pipeline, args.interface, count=args.count, bpf_filter=bpf_filter)
    except KeyboardInterrupt:
        pass
    elapsed = time.time() - start
    s = pipeline.stats
    print(f"Finished in {elapsed:.2f}s; processing errors={s.processing_errors}")
    print(f"{s.packets_processed} packets processed")
    print(f"{s.alerts_generated} alerts")


def cmd_analyze(args, config: dict) -> None:
    db = _db_from_config(config)
    db.init_db()
    pipeline = Pipeline(config, db)

    print(f"Analyzing {args.pcap}")
    start = time.time()
    run_pcap_analysis(pipeline, args.pcap)
    elapsed = time.time() - start
    s = pipeline.stats
    print(f"Finished in {elapsed:.2f}s; processing errors={s.processing_errors}")
    print(f"{s.packets_processed} packets processed")
    print(f"{s.alerts_generated} alerts")


def cmd_dashboard(args, config: dict) -> None:
    from .dashboard import run_dashboard
    db = _db_from_config(config)
    db.init_db()
    dash_cfg = config.get("dashboard", {})
    host = dash_cfg.get("host", "127.0.0.1")
    port = dash_cfg.get("port", 5000)
    print(f"Dashboard running at http://{host}:{port}")
    run_dashboard(db, host=host, port=port)


def cmd_alerts(args, config: dict) -> None:
    db = _db_from_config(config)
    alerts = db.get_alerts(limit=args.limit, severity=args.severity, status=args.status)
    if not alerts:
        print("No alerts found for the given filters.")
        return
    for a in alerts:
        print(f"[{a['id']}] {a['alert_type']} severity={a['severity']} "
              f"confidence={a['confidence']:.2f} status={a['status']} "
              f"src={a.get('src_ip')} dst={a.get('dst_ip')} :: {a['description']}")


def cmd_update_alert(args, config: dict) -> None:
    db = _db_from_config(config)
    ok = db.update_alert(args.alert_id, status=args.status, note=args.note)
    print("Updated." if ok else "Alert not found or nothing to update.")


def cmd_export(args, config: dict) -> None:
    db = _db_from_config(config)
    data = db.export_alerts(fmt=args.format)
    Path(args.output).write_text(data, encoding="utf-8")
    print(f"Exported alerts to {args.output}")


def cmd_cleanup(args, config: dict) -> None:
    db = _db_from_config(config)
    retention_days = config.get("database", {}).get("retention_days", 30)
    removed = db.cleanup(retention_days)
    print(f"Removed {removed} alert(s) older than {retention_days} days.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel-nids",
                                      description="Sentinel NIDS - passive network intrusion & anomaly detection")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Path to config.yaml")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="Create the SQLite database and tables").set_defaults(func=cmd_init_db)

    p_monitor = sub.add_parser("monitor", help="Capture live traffic from an interface")
    p_monitor.add_argument("--interface", required=True, help="Network interface name")
    p_monitor.add_argument("--count", type=int, default=0, help="Stop after N packets (0 = until Ctrl+C)")
    p_monitor.set_defaults(func=cmd_monitor)

    p_analyze = sub.add_parser("analyze", help="Analyze a saved PCAP file")
    p_analyze.add_argument("--pcap", required=True, help="Path to a .pcap/.pcapng file")
    p_analyze.set_defaults(func=cmd_analyze)

    sub.add_parser("dashboard", help="Run the local Flask dashboard").set_defaults(func=cmd_dashboard)

    p_alerts = sub.add_parser("alerts", help="List stored alerts")
    p_alerts.add_argument("--limit", type=int, default=50)
    p_alerts.add_argument("--severity", choices=["low", "medium", "high"])
    p_alerts.add_argument("--status", choices=["new", "investigating", "resolved", "false_positive", "ignored"])
    p_alerts.set_defaults(func=cmd_alerts)

    p_update = sub.add_parser("update-alert", help="Update an alert's status or note")
    p_update.add_argument("alert_id", type=int)
    p_update.add_argument("--status", choices=["new", "investigating", "resolved", "false_positive", "ignored"])
    p_update.add_argument("--note")
    p_update.set_defaults(func=cmd_update_alert)

    p_export = sub.add_parser("export", help="Export alerts to a file")
    p_export.add_argument("--format", choices=["json", "csv"], default="json")
    p_export.add_argument("--output", required=True)
    p_export.set_defaults(func=cmd_export)

    sub.add_parser("cleanup", help="Delete data older than the configured retention period").set_defaults(func=cmd_cleanup)

    return parser


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    config = load_config(args.config)
    args.func(args, config)


if __name__ == "__main__":
    main()
