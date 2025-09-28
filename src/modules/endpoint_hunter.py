"""EndpointHunter Implementation

Adds lightweight process lineage rarity, persistence artifact detection,
execution burst anomaly, and signed mismatch heuristics.

Confidence deltas are bounded per factor (<=0.05) and cumulative <=0.15 per event.
"""
from __future__ import annotations
import time
from typing import Dict, Any, List, Tuple
from collections import defaultdict, deque

try:
	from prometheus_client import Gauge, Counter
except Exception:  # pragma: no cover
	Gauge = None  # type: ignore
	Counter = None  # type: ignore

class EndpointHunter:
	def __init__(self, config):
		self.config = config
		self.parent_child_freq: Dict[str, Dict[str,int]] = defaultdict(lambda: defaultdict(int))
		self.rare_cutoff = 5  # after this many sightings the lineage is no longer rare
		self.host_exec_windows: Dict[str, deque] = defaultdict(lambda: deque())  # timestamps of recent execs
		self.host_last_burst: Dict[str, float] = {}
		self.window_seconds = 60
		self.exec_burst_multiplier = 1.25
		self.min_events_for_burst = 8
		if not hasattr(EndpointHunter,'_metrics_init'):
			try:
				if Gauge:
					EndpointHunter.lineage_cache_size = Gauge('endpoint_lineage_cache_size','Parent process lineage map size')  # type: ignore
				if Counter:
					EndpointHunter.exec_burst_events_total = Counter('endpoint_exec_burst_events_total','Execution burst anomaly events detected')  # type: ignore
				EndpointHunter._metrics_init = True
			except Exception:
				pass

	async def initialize(self):
		return

	async def health_check(self):
		return True

	async def shutdown(self):
		return

	def _update_lineage(self, parent: str, child: str):
		m = self.parent_child_freq[parent]
		m[child] += 1
		try:
			if hasattr(self.__class__,'lineage_cache_size'):
				self.__class__.lineage_cache_size.set(len(self.parent_child_freq))  # type: ignore
		except Exception:
			pass

	def _detect_rare_lineage(self, parent: str, child: str) -> Tuple[bool,float]:
		m = self.parent_child_freq.get(parent)
		if not m:
			return True, 0.05  # first time parent observed spawning child => rare
		count = m.get(child,0)
		if count == 0:
			return True, 0.05
		if count < self.rare_cutoff:
			return True, 0.03
		return False, 0.0

	def _update_exec_window(self, host: str, ts: float) -> float:
		dq = self.host_exec_windows[host]
		dq.append(ts)
		cutoff = ts - self.window_seconds
		while dq and dq[0] < cutoff:
			dq.popleft()
		return len(dq)


	def _detect_exec_burst(self, host: str, window_len: int, ts: float) -> Tuple[bool,float]:
		"""Detect execution bursts when recent executions exceed configured thresholds."""
		if window_len >= self.min_events_for_burst:
			last = self.host_last_burst.get(host)
			threshold = self.min_events_for_burst * self.exec_burst_multiplier
			if window_len >= threshold:
				if not last or (ts - last) >= (self.window_seconds / 2):
					self.host_last_burst[host] = ts
					return True, 0.04
		return False, 0.0

	def _detect_persistence(self, event: Dict[str,Any]) -> Tuple[bool,float]:
		reg = (event.get('registry_path') or '').lower()
		svc = (event.get('service_name') or '').lower()
		cmd = (event.get('cmdline') or event.get('command_line') or '').lower()
		indicators = 0
		if any(k in reg for k in ('run\\','runonce','services\\','currentversion\\policies\\explorer\\run')):
			indicators += 1
		if svc and ('install' in cmd or 'create' in cmd):
			indicators += 1
		if 'schtasks' in cmd and ( '/create' in cmd or '/sc' in cmd):
			indicators += 1
		if indicators:
			return True, 0.05
		return False, 0.0

	def _detect_signed_mismatch(self, event: Dict[str,Any]) -> Tuple[bool,float]:
		signed = event.get('signed')
		sig_valid = event.get('signature_valid')
		if signed is True and sig_valid is False:
			return True, 0.03
		return False, 0.0

	async def analyze_event(self, event: Dict[str,Any]) -> Dict[str,Any]:
		factors: List[str] = []
		delta_total = 0.0
		parent = None
		child = None
		proc = event.get('process') or {}
		if isinstance(proc, dict):
			child = proc.get('name') or event.get('process_name')
			parent = proc.get('parent_name') or event.get('parent_process') or event.get('parent_name')
		else:
			child = event.get('process_name')
			parent = event.get('parent_name')
		if parent and child:
			parent_l = str(parent).lower(); child_l = str(child).lower()
			rare, d = self._detect_rare_lineage(parent_l, child_l)
			self._update_lineage(parent_l, child_l)
			if rare:
				factors.append('endpoint:rare_lineage'); delta_total += d
		host = event.get('host_id') or event.get('host')
		now = time.time()
		if host:
			window_len = self._update_exec_window(str(host), now)
			burst, d = self._detect_exec_burst(str(host), window_len, now)
			if burst:
				factors.append('endpoint:exec_burst'); delta_total += d
				try:
					if hasattr(self.__class__,'exec_burst_events_total'):
						self.__class__.exec_burst_events_total.inc()  # type: ignore
				except Exception: pass
		pers, d = self._detect_persistence(event)
		if pers:
			factors.append('endpoint:persistence_candidate'); delta_total += d
		mism, d = self._detect_signed_mismatch(event)
		if mism:
			factors.append('endpoint:signed_mismatch'); delta_total += d
		# Cap cumulative to 0.15
		if delta_total > 0.15:
			scale = 0.15 / delta_total
			delta_total *= scale
		return {'factors': factors, 'confidence_delta': round(delta_total,4)}
