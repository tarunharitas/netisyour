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

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

from .database import Database
from .pipeline import Pipeline, run_live_capture, run_pcap_analysis
from .reporter import ReportGenerator


DEFAULT_CONFIG_PATH = "config.yaml"
console = Console()


def load_config(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        console.print(f"[bold red]Config file not found: {path}[/bold red]", style="red")
        sys.exit(1)
    with p.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _db_from_config(config: dict) -> Database:
    db_path = config.get("database", {}).get("path", "nids.db")
    return Database(db_path)


def cmd_init_db(args, config: dict) -> None:
    db = _db_from_config(config)
    db.init_db()
    console.print(f"[green]Initialized database at {db.path}[/green]")


def cmd_monitor(args, config: dict) -> None:
    db = _db_from_config(config)
    db.init_db()
    pipeline = Pipeline(config, db)

    bpf_filter = config.get("capture", {}).get("bpf_filter")
    
    console.print(Panel.fit(f"Monitoring {args.interface}\nPress Ctrl+C to stop", title="Live Capture"))
    start = time.time()
    
    try:
        with Progress() as progress:
            task = progress.add_task("[cyan]Processing packets...", total=args.count if args.count > 0 else None)
            # A bit of a hack: to actually update progress we'd need callbacks in run_live_capture
            run_live_capture(pipeline, args.interface, count=args.count, bpf_filter=bpf_filter)
    except KeyboardInterrupt:
        pass
        
    elapsed = time.time() - start
    s = pipeline.stats
    
    console.print(f"[bold]Finished in {elapsed:.2f}s[/bold]")
    console.print(f"Packets: {s.packets_processed} | Alerts: {s.alerts_generated} | Errors: {s.processing_errors}")


def cmd_analyze(args, config: dict) -> None:
    db = _db_from_config(config)
    db.init_db()
    pipeline = Pipeline(config, db)

    console.print(Panel.fit(f"Analyzing {args.pcap}", title="PCAP Analysis"))
    start = time.time()
    run_pcap_analysis(pipeline, args.pcap)
    elapsed = time.time() - start
    s = pipeline.stats
    
    console.print(f"[bold]Finished in {elapsed:.2f}s[/bold]")
    console.print(f"Packets: {s.packets_processed} | Alerts: {s.alerts_generated} | Errors: {s.processing_errors}")


def cmd_app(args, config: dict) -> None:
    from .app import launch_desktop_app
    launch_desktop_app(config_path=args.config)


def cmd_dashboard(args, config: dict) -> None:
    from .dashboard import create_app
    db = _db_from_config(config)
    db.init_db()
    dash_cfg = config.get("dashboard", {})
    host = dash_cfg.get("host", "127.0.0.1")
    port = dash_cfg.get("port", 5000)
    
    app, socketio = create_app(db)
    console.print(f"Dashboard running at [bold green]http://{host}:{port}[/bold green]")
    socketio.run(app, host=host, port=port)


def cmd_alerts(args, config: dict) -> None:
    db = _db_from_config(config)
    alerts = db.get_alerts(limit=args.limit, severity=args.severity, status=args.status)
    if not alerts:
        console.print("No alerts found for the given filters.")
        return
        
    table = Table(title="Recent Alerts")
    table.add_column("ID", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Severity")
    table.add_column("Src -> Dst")
    table.add_column("Description")
    
    for a in alerts:
        sev_color = "red" if a['severity'] == "high" else "yellow" if a['severity'] == "medium" else "green"
        src = f"{a.get('src_ip', '')}:{a.get('src_port', '')}"
        dst = f"{a.get('dst_ip', '')}:{a.get('dst_port', '')}"
        table.add_row(
            str(a['id']), 
            a['alert_type'], 
            f"[{sev_color}]{a['severity']}[/{sev_color}]", 
            f"{src} -> {dst}", 
            a['description']
        )
        
    console.print(table)


def cmd_update_alert(args, config: dict) -> None:
    db = _db_from_config(config)
    ok = db.update_alert(args.alert_id, status=args.status, note=args.note)
    console.print("[green]Updated.[/green]" if ok else "[red]Alert not found or nothing to update.[/red]")


def cmd_export(args, config: dict) -> None:
    db = _db_from_config(config)
    data = db.export_alerts(fmt=args.format)
    Path(args.output).write_text(data, encoding="utf-8")
    console.print(f"[green]Exported alerts to {args.output}[/green]")


def cmd_cleanup(args, config: dict) -> None:
    db = _db_from_config(config)
    retention_days = config.get("database", {}).get("retention_days", 30)
    removed = db.cleanup(retention_days)
    console.print(f"Removed [bold]{removed}[/bold] alert(s) older than {retention_days} days.")


def cmd_hosts(args, config: dict) -> None:
    db = _db_from_config(config)
    if not hasattr(db, 'get_hosts'):
        console.print("[red]Host inventory not supported by this DB version.[/red]")
        return
        
    hosts = db.get_hosts(limit=args.limit)
    if not hosts:
        console.print("No hosts discovered yet.")
        return
        
    table = Table(title="Discovered Hosts")
    table.add_column("IP Address", style="cyan")
    table.add_column("MAC")
    table.add_column("OS Guess")
    table.add_column("Services")
    table.add_column("First Seen")
    
    for h in hosts:
        services = h.get('services', {})
        srv_str = ", ".join(f"{p}/{s}" for p, s in services.items()) if services else ""
        fs = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(h.get('first_seen', 0)))
        table.add_row(
            h.get('ip', ''),
            h.get('mac', ''),
            h.get('os_guess', ''),
            srv_str,
            fs
        )
    console.print(table)


def cmd_sessions(args, config: dict) -> None:
    db = _db_from_config(config)
    if not hasattr(db, 'get_sessions'):
        console.print("[red]Session tracking not supported by this DB version.[/red]")
        return
        
    sessions = db.get_sessions(limit=args.limit, state=args.state)
    if not sessions:
        console.print("No sessions found.")
        return
        
    table = Table(title="Active / Recent Sessions")
    table.add_column("ID", style="cyan", overflow="fold")
    table.add_column("State", style="green")
    table.add_column("Service")
    table.add_column("Bytes Sent/Recv")
    
    for s in sessions:
        table.add_row(
            s.get('session_id', ''),
            s.get('state', ''),
            s.get('service', s.get('tls_sni', s.get('http_host', ''))),
            f"{s.get('bytes_sent', 0)} / {s.get('bytes_recv', 0)}"
        )
    console.print(table)


def cmd_network_map(args, config: dict) -> None:
    db = _db_from_config(config)
    if not hasattr(db, 'get_hosts'):
        console.print("[red]Host inventory not supported by this DB version.[/red]")
        return
        
    hosts = db.get_hosts(limit=100)
    console.print(Panel("[bold]Network Topology[/bold]"))
    for h in hosts:
        ip = h.get('ip')
        mac = h.get('mac') or 'Unknown MAC'
        console.print(f"  ├── [cyan]{ip}[/cyan] ({mac}) - {h.get('os_guess', 'Unknown OS')}")


def cmd_report(args, config: dict) -> None:
    db = _db_from_config(config)
    reporter = ReportGenerator(db, config)
    out = reporter.generate(format=args.format, output_path=args.output)
    console.print(f"[bold green]Report generated at {out}[/bold green]")


def cmd_scan_profile(args, config: dict) -> None:
    console.print(Panel("Scan Profile Summary:\nDetecting stealthy SYN scans, UDP sweeps, and intense enumeration.", title="Scan Profile"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel-nids", description="Sentinel NIDS - passive network intrusion & anomaly detection")
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
    sub.add_parser("app", help="Launch 1-click standalone desktop application window").set_defaults(func=cmd_app)

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

    p_hosts = sub.add_parser("hosts", help="List discovered hosts")
    p_hosts.add_argument("--limit", type=int, default=50)
    p_hosts.set_defaults(func=cmd_hosts)

    p_sessions = sub.add_parser("sessions", help="Show active/recent TCP sessions")
    p_sessions.add_argument("--limit", type=int, default=50)
    p_sessions.add_argument("--state", choices=["SYN_SENT", "ESTABLISHED", "FIN_WAIT", "CLOSED", "RESET", "TIMEOUT"])
    p_sessions.set_defaults(func=cmd_sessions)

    sub.add_parser("network-map", help="Simple ASCII network topology").set_defaults(func=cmd_network_map)

    p_report = sub.add_parser("report", help="Generate pentest report")
    p_report.add_argument("--format", choices=["html", "markdown", "json"], default="html")
    p_report.add_argument("--output", default="report.html")
    p_report.set_defaults(func=cmd_report)

    sub.add_parser("scan-profile", help="Summarize detected scan patterns").set_defaults(func=cmd_scan_profile)

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
