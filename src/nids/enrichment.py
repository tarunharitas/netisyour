"""Threat intelligence enrichment for alerts and host records.

Provides optional GeoIP lookups (MaxMind GeoLite2) and threat feed
checking. All enrichment is optional -- if databases or feeds are not
configured, enrichment gracefully returns empty results.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Dict, Optional

from .models import Alert, HostRecord

logger = logging.getLogger("nids.enrichment")


class EnrichmentEngine:
    """Enriches alerts and host records with external threat intelligence.

    Currently supports:
      - GeoIP country/ASN lookup (MaxMind GeoLite2, optional)
      - Known-bad IP list matching (configurable feeds)
      - Private/reserved IP detection
    """

    def __init__(self, config: dict):
        enrich_cfg = config.get("enrichment", {})
        geo_cfg = enrich_cfg.get("geoip", {})
        feed_cfg = enrich_cfg.get("threat_feeds", {})

        self._geoip_enabled = geo_cfg.get("enabled", False)
        self._geoip_reader = None
        self._feeds_enabled = feed_cfg.get("enabled", False)
        self._known_bad_ips: set = set()

        # -- GeoIP setup (optional dependency) --
        if self._geoip_enabled:
            db_path = geo_cfg.get("database_path", "")
            if db_path:
                try:
                    import geoip2.database  # type: ignore
                    self._geoip_reader = geoip2.database.Reader(db_path)
                    logger.info("GeoIP database loaded from %s", db_path)
                except ImportError:
                    logger.warning(
                        "geoip2 package not installed. Install with: "
                        "pip install geoip2"
                    )
                    self._geoip_enabled = False
                except Exception as exc:
                    logger.warning("Failed to load GeoIP database: %s", exc)
                    self._geoip_enabled = False

        # -- Threat feeds setup --
        if self._feeds_enabled:
            feed_urls = feed_cfg.get("feeds", [])
            self._load_threat_feeds(feed_urls)

    def _load_threat_feeds(self, feed_urls: list) -> None:
        """Load known-bad IPs from configured threat intelligence feeds.

        Each feed URL should point to a plain-text file with one IP per line.
        Lines starting with # are comments. Loading errors are logged but
        never crash the application.
        """
        import urllib.request

        for url in feed_urls:
            try:
                with urllib.request.urlopen(url, timeout=10) as resp:
                    text = resp.read().decode("utf-8", errors="ignore")
                    for line in text.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            try:
                                ipaddress.ip_address(line)
                                self._known_bad_ips.add(line)
                            except ValueError:
                                continue
                logger.info(
                    "Loaded %d IPs from threat feed: %s",
                    len(self._known_bad_ips),
                    url,
                )
            except Exception as exc:
                logger.warning("Failed to load threat feed %s: %s", url, exc)

    # -- Public API ---------------------------------------------------------

    def enrich_alert(self, alert: Alert) -> Alert:
        """Add GeoIP and threat intel context to an alert."""
        if alert.src_ip:
            geo = self.geoip_lookup(alert.src_ip)
            if geo:
                alert.geo_src = geo.get("country")
                alert.evidence.setdefault("geo_src", geo)

            if self.is_known_bad(alert.src_ip):
                alert.evidence["known_bad_src"] = True
                if alert.severity == "medium":
                    alert.severity = "high"
                alert.confidence = min(alert.confidence + 0.1, 1.0)

        if alert.dst_ip:
            geo = self.geoip_lookup(alert.dst_ip)
            if geo:
                alert.geo_dst = geo.get("country")
                alert.evidence.setdefault("geo_dst", geo)

            if self.is_known_bad(alert.dst_ip):
                alert.evidence["known_bad_dst"] = True

        return alert

    def enrich_host(self, host: HostRecord) -> HostRecord:
        """Add GeoIP data to a host record."""
        if not host.is_local:
            geo = self.geoip_lookup(host.ip)
            if geo:
                host.geo_country = geo.get("country")
                host.geo_asn = geo.get("asn")
        return host

    def geoip_lookup(self, ip: str) -> Optional[Dict[str, str]]:
        """Look up country and ASN for an IP address.

        Returns None for private/reserved IPs or if GeoIP is not configured.
        """
        if not self._geoip_enabled or not self._geoip_reader:
            return None

        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                return None
        except ValueError:
            return None

        try:
            response = self._geoip_reader.city(ip)
            result = {
                "country": response.country.name or "Unknown",
                "country_code": response.country.iso_code or "??",
                "city": response.city.name or "",
            }
            # Try ASN lookup if available
            try:
                asn_response = self._geoip_reader.asn(ip)
                result["asn"] = (
                    f"AS{asn_response.autonomous_system_number} "
                    f"{asn_response.autonomous_system_organization}"
                )
            except Exception:
                pass
            return result
        except Exception:
            return None

    def is_known_bad(self, ip: str) -> bool:
        """Check if an IP appears in loaded threat intelligence feeds."""
        return ip in self._known_bad_ips

    def is_private_ip(self, ip: str) -> bool:
        """Check if an IP is in a private/reserved range."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_reserved
        except ValueError:
            return False

    def close(self) -> None:
        """Release resources (close GeoIP database reader)."""
        if self._geoip_reader:
            try:
                self._geoip_reader.close()
            except Exception:
                pass
