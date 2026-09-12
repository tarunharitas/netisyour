import sys
import json
import logging
from .models import Alert

logger = logging.getLogger(__name__)

class AlertNotifier:
    def __init__(self, config: dict):
        self.config = config.get("notifications", {})
        self.channels = self.config.get("channels", ["desktop"])
        self.min_severity = self.config.get("min_severity", "low")
        self.severities = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    def notify(self, alert: Alert) -> None:
        alert_sev = self.severities.get(alert.severity.lower(), 1)
        min_sev = self.severities.get(self.min_severity.lower(), 1)
        if alert_sev < min_sev:
            return

        if "desktop" in self.channels:
            self._send_desktop(alert)
        if "webhook" in self.channels:
            self._send_webhook(alert)

    def _send_webhook(self, alert: Alert) -> None:
        webhook_url = self.config.get("webhook_url")
        if not webhook_url:
            return
        try:
            import urllib.request
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(alert.to_dict()).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                pass
        except Exception as e:
            logger.error(f"Failed to send webhook notification: {e}")

    def _send_desktop(self, alert: Alert) -> None:
        sys.stderr.write('\a')
        sys.stderr.flush()
        try:
            from rich.console import Console
            console = Console(stderr=True)
            color = "red" if alert.severity in ("high", "critical") else "yellow" if alert.severity == "medium" else "cyan"
            console.print(f"[{color} bold]ALERT [{alert.severity.upper()}]: {alert.alert_type}[/] - {alert.description}")
        except ImportError:
            sys.stderr.write(f"\nALERT [{alert.severity.upper()}]: {alert.alert_type} - {alert.description}\n")
            sys.stderr.flush()
