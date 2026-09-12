"""Sentinel NIDS - Desktop Application Launcher.

Provides a 1-click standalone desktop application (like WhatsApp or Discord)
powered by pywebview and Flask-SocketIO. Automatically discovers active network
interfaces, launches the packet sniffer in the background, and displays the
real-time dashboard in a sleek native Windows application window.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from typing import Optional

import yaml

from .database import Database
from .dashboard import create_app
from .pipeline import Pipeline, run_live_capture
from .reporter import ReportGenerator

logger = logging.getLogger("nids.app")


def detect_best_interface(configured_iface: Optional[str] = None) -> str:
    """Automatically detect the best network interface to capture on."""
    try:
        from scapy.all import conf, get_working_ifaces
        working = [i.name for i in get_working_ifaces()]
        
        # 1. If configured interface is valid, use it
        if configured_iface and configured_iface in working:
            return configured_iface
            
        # 2. Prioritize common wireless & wired adapter names
        for candidate in ["WiFi", "Wi-Fi", "Ethernet", "WLAN"]:
            for iface in working:
                if candidate.lower() in iface.lower():
                    return iface
                    
        # 3. Fallback to Scapy's default route interface
        if hasattr(conf, "iface") and conf.iface:
            if hasattr(conf.iface, "name"):
                return conf.iface.name
            return str(conf.iface)
            
        if working:
            return working[0]
    except Exception as exc:
        logger.warning("Auto-detection failed, using fallback: %s", exc)
        
    return configured_iface or "Wi-Fi"


class AppEngine:
    """Manages the background capture pipeline, database, and web server."""

    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.db = Database(self.config.get("database", {}).get("path", "nids.db"))
        self.db.init_db()

        self.pipeline: Optional[Pipeline] = None
        self.capture_thread: Optional[threading.Thread] = None
        self.is_monitoring = False
        
        configured_iface = self.config.get("capture", {}).get("interface", "Wi-Fi")
        self.interface = detect_best_interface(configured_iface)

    def _load_config(self) -> dict:
        if os.path.exists(self.config_path):
            with open(self.config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}

    def start_monitoring(self) -> bool:
        """Start capturing packets in a background daemon thread."""
        if self.is_monitoring:
            return True
            
        try:
            self.pipeline = Pipeline(self.config, self.db)
            self.is_monitoring = True
            
            def _capture_worker():
                try:
                    logger.info("Starting live capture on %s", self.interface)
                    run_live_capture(self.pipeline, self.interface, count=0)
                except Exception as exc:
                    logger.error("Capture stopped with error: %s", exc)
                finally:
                    self.is_monitoring = False

            self.capture_thread = threading.Thread(
                target=_capture_worker, name="sentinel-capture-daemon", daemon=True
            )
            self.capture_thread.start()
            return True
        except Exception as exc:
            logger.error("Failed to start monitoring: %s", exc)
            self.is_monitoring = False
            return False

    def stop_monitoring(self) -> None:
        """Stop packet capture."""
        if self.pipeline:
            self.pipeline.stop()
            self.pipeline = None
        self.is_monitoring = False

    def generate_report_html(self) -> str:
        """Generate pentest assessment report HTML string."""
        reporter = ReportGenerator(self.db, self.config)
        return reporter.generate(format="html")


def launch_desktop_app(config_path: str = "config.yaml", host: str = "127.0.0.1", port: int = 5000):
    """Launch the native desktop window application."""
    engine = AppEngine(config_path)
    app, socketio = create_app(engine.db)

    # Add desktop control endpoints
    @app.route("/api/engine/status")
    def engine_status():
        stats = engine.pipeline.stats if engine.pipeline else None
        return {
            "is_monitoring": engine.is_monitoring,
            "interface": engine.interface,
            "packets_processed": stats.packets_processed if stats else 0,
            "alerts_generated": stats.alerts_generated if stats else 0,
            "dropped_packets": stats.dropped_packets if stats else 0,
        }

    @app.route("/api/engine/toggle", methods=["POST"])
    def engine_toggle():
        if engine.is_monitoring:
            engine.stop_monitoring()
        else:
            engine.start_monitoring()
        return engine_status()

    @app.route("/api/report/download")
    def download_report():
        from flask import Response
        report_html = engine.generate_report_html()
        return Response(
            report_html,
            mimetype="text/html",
            headers={"Content-Disposition": "attachment;filename=sentinel_security_report.html"}
        )

    @app.route("/api/db/clear", methods=["POST"])
    def clear_db():
        with engine.db._connect() as conn:
            conn.executescript(
                "DELETE FROM alerts; DELETE FROM hosts; DELETE FROM sessions; "
                "DELETE FROM credentials; DELETE FROM traffic_stats; DELETE FROM signatures_log; VACUUM;"
            )
        return {"status": "cleared"}

    # Start Flask-SocketIO server in a background thread
    server_thread = threading.Thread(
        target=lambda: socketio.run(app, host=host, port=port, debug=False, use_reloader=False),
        daemon=True,
        name="sentinel-web-server"
    )
    server_thread.start()
    time.sleep(1.2)  # Give server a moment to bind

    # Start packet sniffer automatically!
    engine.start_monitoring()

    # Launch native Desktop Window using pywebview
    try:
        import webview
        
        window = webview.create_window(
            title=f"Sentinel NIDS v2.0 — Network Security Center (Interface: {engine.interface})",
            url=f"http://{host}:{port}",
            width=1320,
            height=850,
            min_size=(950, 650),
            background_color="#0f1420"
        )
        
        # When desktop window is closed, cleanly shut down
        def on_closed():
            logger.info("Closing desktop window, stopping engine...")
            engine.stop_monitoring()

        window.events.closed += on_closed
        webview.start()
    except ImportError:
        logger.warning("pywebview not installed. Opening in default browser instead.")
        import webbrowser
        webbrowser.open(f"http://{host}:{port}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            engine.stop_monitoring()


if __name__ == "__main__":
    launch_desktop_app()
