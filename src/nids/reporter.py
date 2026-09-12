import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from .database import Database

class ReportGenerator:
    def __init__(self, db: Database, config: dict):
        self.db = db
        self.config = config

    def generate(self, format: str = 'html', output_path: str = 'report.html') -> str:
        data = self._gather_data()
        
        if format.lower() == 'html':
            content = self._generate_html(data)
        elif format.lower() == 'markdown':
            content = self._generate_markdown(data)
        elif format.lower() == 'json':
            content = json.dumps(data, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")

        Path(output_path).write_text(content, encoding="utf-8")
        return output_path

    def _gather_data(self) -> Dict[str, Any]:
        alerts = self.db.get_alerts(limit=1000)
        hosts = []
        try:
            # Assuming db has get_hosts and get_sessions in v2.0
            if hasattr(self.db, 'get_hosts'):
                hosts = self.db.get_hosts(limit=1000)
        except Exception:
            pass

        sessions = []
        try:
            if hasattr(self.db, 'get_sessions'):
                sessions = self.db.get_sessions(limit=1000)
        except Exception:
            pass
            
        credentials = []
        try:
            if hasattr(self.db, 'get_credentials'):
                credentials = self.db.get_credentials(limit=1000)
        except Exception:
            pass

        summary = self.db.summary()

        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "analyst_info": self.config.get("analyst", "Sentinel NIDS Automated Analysis"),
            "summary": summary,
            "alerts": alerts,
            "hosts": hosts,
            "sessions": sessions,
            "credentials": credentials
        }

    def _generate_html(self, data: dict) -> str:
        try:
            from jinja2 import Environment, FileSystemLoader
            env = Environment(loader=FileSystemLoader(str(Path(__file__).parent / "templates")))
            template = env.get_template("report.html")
            return template.render(**data)
        except Exception as e:
            # Fallback to basic HTML if jinja fails
            return f"<html><body><h1>Report Generation Error</h1><p>{str(e)}</p></body></html>"

    def _generate_markdown(self, data: dict) -> str:
        lines = []
        lines.append(f"# Sentinel NIDS Penetration Test Report")
        lines.append(f"**Generated:** {data['timestamp']}")
        lines.append(f"**Analyst:** {data['analyst_info']}")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append(f"- Total Alerts: {data['summary'].get('total_alerts', 0)}")
        lines.append(f"- High Severity: {data['summary'].get('by_severity', {}).get('high', 0)}")
        lines.append(f"- Unique Hosts: {len(data['hosts'])}")
        lines.append("")
        
        lines.append("## Findings")
        for a in data["alerts"]:
            lines.append(f"### {a['alert_type']} ({a['severity'].upper()})")
            lines.append(f"**Description:** {a['description']}")
            if a.get('mitre_technique'):
                lines.append(f"**MITRE ATT&CK:** {a['mitre_technique']} ({a.get('mitre_tactic', '')})")
            lines.append(f"**Evidence:** {json.dumps(a.get('evidence', {}))}")
            lines.append("")

        lines.append("## Host Inventory")
        for h in data["hosts"]:
            lines.append(f"- **{h.get('ip')}**: {h.get('os_guess', 'Unknown OS')}, Ports: {h.get('open_ports', [])}")
        
        return "\n".join(lines)
