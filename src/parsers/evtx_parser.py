from __future__ import annotations

from typing import Any, Dict, List

def parse_evtx_bytes(content: bytes) -> dict[str, Any]:
    """Parse EVTX content if python-evtx is available; return basic events and hints.
    Extracts a subset of fields needed for endpoint factors.
    """
    try:
        from Evtx.Evtx import Evtx  # type: ignore
        from Evtx.Views import evtx_file_xml_view  # type: ignore
    except Exception:
        raise RuntimeError('python-evtx not installed')

    events: list[dict[str, Any]] = []
    hints = { 'exec_events': 0, 'persistence_events': 0 }
    try:
        import io
        with Evtx(io.BytesIO(content)) as log:
            for i, rec in enumerate(log.records()):  # type: ignore
                try:
                    xml = rec.xml()
                    # Very lightweight scan for EventID and a few fields
                    eid = _extract_between(xml, '<EventID>', '</EventID>')
                    if eid: eid = eid.strip()
                    provider = _extract_between(xml, '<Provider Name="', '"')
                    # Sysmon process creation ID: 1; Windows Security 4688; service install 7045
                    if eid in {'1','4688','7045','4697','2','7','11','13'}:
                        events.append({ 'event_id': eid, 'provider': provider, 'xml': xml[:2000] })
                        if eid in {'1','4688'}:
                            hints['exec_events'] += 1
                        if eid in {'7045','4697','13'}:
                            hints['persistence_events'] += 1
                    if len(events) >= 10000:  # safety cap
                        break
                except Exception:
                    continue
    except Exception:
        pass
    return { 'events': events, 'hints': hints }


def _extract_between(s: str, start: str, end: str) -> str | None:
    a = s.find(start)
    if a == -1:
        return None
    a += len(start)
    b = s.find(end, a)
    if b == -1:
        return None
    return s[a:b]
