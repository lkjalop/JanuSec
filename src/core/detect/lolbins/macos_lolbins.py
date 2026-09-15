MACOS_LOLBINS = {
    'curl': {'pattern': 'download+execute', 'risk': 0.6},
    'osascript': {'pattern': 'apple_script_exec', 'risk': 0.7},
    'python': {'pattern': 'inline_exec', 'risk': 0.5},
    'bash': {'pattern': 'script_exec', 'risk': 0.5},
}


def detect(command: str) -> dict:
    c = (command or '').lower()
    for name, meta in MACOS_LOLBINS.items():
        if name in c:
            return {'name': name, 'pattern': meta['pattern'], 'risk': meta['risk']}
    return {'name': None, 'pattern': None, 'risk': 0.0}
