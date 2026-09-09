"""Local Flask dashboard for reviewing alerts.

Binds to 127.0.0.1 by default and has no multi-user authentication -- it is
meant for local analyst review, not for exposure on a shared network.
"""

from __future__ import annotations

from typing import Optional

from flask import Flask, jsonify, render_template, request

from .database import Database


def _query_limit(value: Optional[str], default: int) -> int:
    try:
        return max(1, min(int(value), 1000)) if value is not None else default
    except (TypeError, ValueError):
        return default


def create_app(db: Database) -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def index():
        summary = db.summary()
        severity = request.args.get("severity") or None
        status = request.args.get("status") or None
        alerts = db.get_alerts(limit=100, severity=severity, status=status)
        return render_template(
            "index.html",
            summary=summary,
            alerts=alerts,
            severity_filter=severity or "",
            status_filter=status or "",
        )

    @app.route("/api/summary")
    def api_summary():
        return jsonify(db.summary())

    @app.route("/api/alerts")
    def api_alerts():
        limit = _query_limit(request.args.get("limit"), 50)
        severity = request.args.get("severity") or None
        status = request.args.get("status") or None
        alert_type = request.args.get("alert_type") or None
        return jsonify(db.get_alerts(limit=limit, severity=severity, status=status,
                                      alert_type=alert_type))

    @app.route("/api/alerts/<int:alert_id>", methods=["GET", "POST"])
    def api_alert_detail(alert_id: int):
        if request.method == "POST":
            data = request.get_json(silent=True) or request.form
            status = data.get("status")
            note = data.get("note")
            updated = db.update_alert(alert_id, status=status, note=note)
            if not updated:
                return jsonify({"error": "alert not found or no fields to update"}), 404
            return jsonify(db.get_alert(alert_id))
        alert = db.get_alert(alert_id)
        if not alert:
            return jsonify({"error": "not found"}), 404
        return jsonify(alert)

    @app.route("/api/traffic")
    def api_traffic():
        limit = _query_limit(request.args.get("limit"), 60)
        return jsonify(db.get_recent_traffic(limit=limit))

    return app


def run_dashboard(db: Database, host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
    app = create_app(db)
    app.run(host=host, port=port, debug=debug)
