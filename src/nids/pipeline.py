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


class Pipeline:
    """Owns the bounded queue, worker threads, periodic stats windows, and
    graceful shutdown for a capture or PCAP-analysis run.
    """

    def __init__(self, config: dict, db: Database):
        self.config = config
        self.db = db
        self.engine = DetectionEngine(config)

        capture_cfg = config.get("capture", {})
        self.queue_size = capture_cfg.get("queue_size", 10000)
        self.num_workers = capture_cfg.get("workers", 2)
        self.stats_interval_seconds = capture_cfg.get("stats_interval_seconds", 10)

        self._queue: "queue.Queue" = queue.Queue(maxsize=self.queue_size)
        self._stop_event = threading.Event()
        self._workers = []
        self._lock = threading.Lock()
        self._engine_lock = threading.Lock()
        self._stop_lock = threading.Lock()
        self._stopped = False
        self.stats = PipelineStats()

        self._window_start = time.time()
        self._window_packet_count = 0
        self._window_byte_count = 0

    # -- Public API ---------------------------------------------------------

    def start_workers(self) -> None:
        for i in range(self.num_workers):
            t = threading.Thread(target=self._worker_loop, name=f"nids-worker-{i}", daemon=True)
            t.start()
            self._workers.append(t)

    def submit(self, raw_packet) -> None:
        """Called by the capture source (live sniffer or PCAP reader)."""
        self.stats.packets_received += 1
        try:
            self._queue.put(raw_packet, timeout=1)
        except queue.Full:
            logger.warning("Packet queue full; dropping packet")

    def stop(self, timeout: float = 5.0) -> None:
        with self._stop_lock:
            if self._stopped:
                return
            self._stop_event.set()
            for t in self._workers:
                t.join(timeout=timeout)
            self._flush_window()
            self._stopped = True

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

    def _handle_packet(self, raw_packet) -> None:
        record = parse_packet(raw_packet)

        with self._lock:
            self._window_packet_count += 1
            self._window_byte_count += record.packet_size
            if (record.timestamp - self._window_start) >= self.stats_interval_seconds:
                self._flush_window(now=record.timestamp)

        with self._engine_lock:
            alerts = self.engine.process(record)
        for alert in alerts:
            self.db.insert_alert(alert)
            self.stats.alerts_generated += 1
            logger.info("ALERT %s: %s", alert.alert_type, alert.description)

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
    finally:
        pipeline.stop()
