"""Local Flask dashboard for reviewing alerts and monitoring network activity.

Binds to 127.0.0.1 by default. Includes SocketIO for real-time updates.
"""

from __future__ import annotations

import time
from typing import Optional

from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO

from .database import Database


def _query_limit(value: Optional[str], default: int) -> int:
    try:
        return max(1, min(int(value), 1000)) if value is not None else default
    except (TypeError, ValueError):
        return default


def create_app(db: Database):
    app = Flask(__name__)
    socketio = SocketIO(app, cors_allowed_origins='*')
    
    start_time = time.time()

    @app.after_request
    def after_request(response):
        if request.path.startswith('/api/'):
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        return response

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
        
    @app.route("/hosts")
    def hosts_page():
        return render_template("hosts.html")
        
    @app.route("/sessions")
    def sessions_page():
        return render_template("sessions.html")
        
    @app.route("/alert/<int:alert_id>")
    def alert_detail_page(alert_id: int):
        alert = db.get_alert(alert_id)
        if not alert:
            return "Alert not found", 404
        return render_template("alert_detail.html", alert=alert)

    @app.route("/api/summary")
    def api_summary():
        return jsonify(db.summary())

    @app.route("/api/alerts")
    def api_alerts():
        limit = _query_limit(request.args.get("limit"), 50)
        severity = request.args.get("severity") or None
        status = request.args.get("status") or None
        alert_type = request.args.get("alert_type") or None
        return jsonify(db.get_alerts(limit=limit, severity=severity, status=status, alert_type=alert_type))

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
        
    @app.route("/api/hosts")
    def api_hosts():
        limit = _query_limit(request.args.get("limit"), 100)
        hosts = []
        if hasattr(db, 'get_hosts'):
            hosts = db.get_hosts(limit=limit)
        return jsonify(hosts)
        
    @app.route("/api/hosts/<ip>")
    def api_host_detail(ip: str):
        if hasattr(db, 'get_host'):
            host = db.get_host(ip)
            if host:
                return jsonify(host)
        return jsonify({"error": "not found"}), 404
        
    @app.route("/api/sessions")
    def api_sessions():
        limit = _query_limit(request.args.get("limit"), 100)
        state = request.args.get("state")
        sessions = []
        if hasattr(db, 'get_sessions'):
            sessions = db.get_sessions(limit=limit, state=state)
        return jsonify(sessions)
        
    @app.route("/api/credentials")
    def api_credentials():
        limit = _query_limit(request.args.get("limit"), 50)
        credentials = []
        if hasattr(db, 'get_credentials'):
            credentials = db.get_credentials(limit=limit)
        return jsonify(credentials)
        
    @app.route("/api/dashboard")
    def api_dashboard():
        return jsonify({
            "summary": db.summary(),
            "uptime": time.time() - start_time
        })
        
    @app.route("/api/health")
    def api_health():
        return jsonify({
            "status": "ok",
            "uptime": time.time() - start_time
        })

    return app, socketio


def emit_alert(socketio: SocketIO, alert_dict: dict):
    socketio.emit('new_alert', alert_dict, namespace='/')
