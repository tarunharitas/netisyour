"""Capture pipeline: bounded queue + worker threads.

The same pipeline and DetectionEngine are used for both live traffic and
offline PCAP analysis, so the detection logic is identical and testable in
both modes.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .database import Database
from .detectors import DetectionEngine
from .parser import parse_packet

logger = logging.getLogger("nids.pipeline")


@dataclass
class PipelineStats:
    packets_received: int = 0
    packets_processed: int = 0
    processing_errors: int = 0
    alerts_generated: int = 0
    dropped_packets: int = 0


class Pipeline:
    """Owns the bounded queue, worker thread, writer thread, periodic stats windows, and
    graceful shutdown for a capture or PCAP-analysis run.
    """

    def __init__(self, config: dict, db: Database, on_alert: Optional[Callable] = None):
        self.config = config
        self.db = db
        self.engine = DetectionEngine(config)
        self.on_alert = on_alert

        capture_cfg = config.get("capture", {})
        self.queue_size = capture_cfg.get("queue_size", 20000)
        self.stats_interval_seconds = capture_cfg.get("stats_interval_seconds", 10)

        self._queue: "queue.Queue" = queue.Queue(maxsize=self.queue_size)
        self._alert_queue: "queue.Queue" = queue.Queue()
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._writer_thread: Optional[threading.Thread] = None
        
        self.stats = PipelineStats()

        self._window_start = time.time()
        self._window_packet_count = 0
        self._window_byte_count = 0
        self._lock = threading.Lock()

    # -- Public API ---------------------------------------------------------

    def start_workers(self) -> None:
        self._worker_thread = threading.Thread(target=self._worker_loop, name="nids-worker", daemon=True)
        self._writer_thread = threading.Thread(target=self._writer_loop, name="nids-writer", daemon=True)
        self._worker_thread.start()
        self._writer_thread.start()

    def submit(self, raw_packet) -> None:
        """Called by the capture source (live sniffer or PCAP reader)."""
        self.stats.packets_received += 1
        try:
            self._queue.put(raw_packet, timeout=1)
        except queue.Full:
            self.stats.dropped_packets += 1
            logger.warning("Packet queue full; dropping packet")

    def stop(self, timeout: float = 5.0) -> None:
        if self._stop_event.is_set():
            return
        self._stop_event.set()
        
        if self._worker_thread:
            self._worker_thread.join(timeout=timeout)
        if self._writer_thread:
            self._writer_thread.join(timeout=timeout)
            
        self._flush_window()

    # -- Internals ------------------------------------------------------

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                raw_packet = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._handle_packet(raw_packet)
            except Exception:
                self.stats.processing_errors += 1
                logger.exception("Error processing packet")
            finally:
                self._queue.task_done()

    def _writer_loop(self) -> None:
        batch = []
        while not self._stop_event.is_set() or not self._alert_queue.empty():
            try:
                alert = self._alert_queue.get(timeout=1.0)
                batch.append(alert)
                self._alert_queue.task_done()
            except queue.Empty:
                pass
                
            if len(batch) >= 100 or (batch and self._alert_queue.empty()):
                try:
                    self.db.insert_alerts_batch(batch)
                except Exception:
                    logger.exception("Failed to insert alert batch")
                batch = []

    def _handle_packet(self, raw_packet) -> None:
        record = parse_packet(raw_packet)

        with self._lock:
            self._window_packet_count += 1
            self._window_byte_count += record.packet_size
            if (record.timestamp - self._window_start) >= self.stats_interval_seconds:
                self._flush_window(now=record.timestamp)

        alerts = self.engine.process(record)
        for alert in alerts:
            self._alert_queue.put(alert)
            self.stats.alerts_generated += 1
            logger.info("ALERT %s: %s", alert.alert_type, alert.description)
            if self.on_alert:
                try:
                    self.on_alert(alert)
                except Exception:
                    logger.exception("Error in on_alert callback")

        self.stats.packets_processed += 1

    def _flush_window(self, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        if self._window_packet_count == 0 and now == self._window_start:
            return
        self.db.insert_traffic_window(
            window_start=self._window_start,
            window_seconds=self.stats_interval_seconds,
            packet_count=self._window_packet_count,
            byte_count=self._window_byte_count,
        )
        self._window_start = now
        self._window_packet_count = 0
        self._window_byte_count = 0


def run_live_capture(pipeline: Pipeline, interface: str, count: int = 0,
                      bpf_filter: Optional[str] = None) -> None:
    """Capture live packets with Scapy and feed them into the pipeline.

    count=0 means capture until interrupted (Ctrl+C). Requires Npcap on
    Windows and typically Administrator/root privileges.
    """
    from scapy.all import sniff

    pipeline.start_workers()

    def _on_packet(pkt):
        pipeline.submit(pkt)

    try:
        sniff(iface=interface, prn=_on_packet, store=False, count=count, filter=bpf_filter)
    except KeyboardInterrupt:
        pass
    finally:
        pipeline.stop()


def run_pcap_analysis(pipeline: Pipeline, pcap_path: str) -> None:
    """Replay a saved PCAP file through the same detection pipeline used for
    live capture, enabling repeatable, safe, offline testing.
    """
    from scapy.all import PcapReader

    pipeline.start_workers()
    try:
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                pipeline.submit(pkt)
    except KeyboardInterrupt:
        pass
    finally:
        pipeline.stop()
