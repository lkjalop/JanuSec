import io
from typing import Any, Dict, Iterable, List


def _as_list(obj: Any) -> List[Any]:
    if obj is None:
        return []
    if isinstance(obj, list):
        return obj
    return [obj]


def normalize_sysmon_event(evt: Dict[str, Any]) -> Dict[str, Any]:
    ts = evt.get('UtcTime') or evt.get('Timestamp') or evt.get('ts')
    host = evt.get('Computer') or evt.get('ComputerName')
    user = evt.get('User') or evt.get('TargetUserName')
    pid = evt.get('ProcessId') or evt.get('pid')
    image = evt.get('Image') or evt.get('ProcessName') or evt.get('ImagePath')
    hashval = evt.get('Hash') or evt.get('sha256') or evt.get('Hashes')
    event_id = evt.get('EventID') or evt.get('EventId') or evt.get('id')
    command = evt.get('CommandLine') or evt.get('cmdline')
    action = evt.get('Action') or evt.get('event_action')
    path = (
        evt.get('TargetFilename')
        or evt.get('FileName')
        or evt.get('ImageLoaded')
        or evt.get('Path')
    )

    if 'Event' in evt and isinstance(evt['Event'], dict):
        e = evt['Event']
        sys = e.get('System', {})
        data = e.get('EventData', {})
        if not ts:
            ts = (sys.get('TimeCreated', {}) or {}).get('SystemTime')
        if not host:
            host = sys.get('Computer')
        if not event_id:
            ev_id = sys.get('EventID')
            event_id = ev_id if isinstance(ev_id, int) else (ev_id or {}).get('#text')
        user = user or data.get('User') or data.get('TargetUserName')
        image = image or data.get('Image') or data.get('ProcessName')
        pid = pid or data.get('ProcessId')
        hashval = hashval or data.get('Hashes') or data.get('sha256')
        if not command:
            command = data.get('CommandLine') or data.get('cmdline')
        if not action:
            action = data.get('Action') or data.get('Operation') or data.get('Task')
        if not path:
            path = (
                data.get('TargetFilename')
                or data.get('ImageLoaded')
                or data.get('Path')
                or data.get('Destination')
            )

    canonical: Dict[str, Any] = {
        'source': 'sysmon',
        'ts': ts,
        'host': host,
        'user': user,
        'process': image,
        'pid': pid,
        'file_hash': hashval,
        'event_id': event_id,
        'command_line': command,
        'action': action,
        'path': path,
        'raw': evt,
    }
    return {k: v for k, v in canonical.items() if v is not None}


def parse_evtx_bytes(data: bytes) -> Iterable[Dict[str, Any]]:
    try:
        from Evtx.Evtx import Evtx  # type: ignore
        from Evtx.Views import evtx_file_xml_view  # type: ignore
        with Evtx(io.BytesIO(data)) as evtx:
            for record in evtx_file_xml_view(evtx):
                yield {'Event': {'Xml': record}}
    except Exception:
        yield {'Event': {'RawEVTX': True, 'Size': len(data)}}
