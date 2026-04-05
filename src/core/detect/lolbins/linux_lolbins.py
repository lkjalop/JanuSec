LINUX_LOLBINS = {
    'curl': {'pattern': 'download+execute', 'risk': 0.6},
    'wget': {'pattern': 'download', 'risk': 0.5},
    'bash': {'pattern': 'script_exec', 'risk': 0.5},
    'sh': {'pattern': 'script_exec', 'risk': 0.4},
    'python': {'pattern': 'inline_exec', 'risk': 0.5},
    'nc': {'pattern': 'reverse_shell', 'risk': 0.8},
}


def detect(command: str) -> dict:
    c = (command or '').lower()
    for name, meta in LINUX_LOLBINS.items():
        if name in c:
            return {'name': name, 'pattern': meta['pattern'], 'risk': meta['risk']}
    return {'name': None, 'pattern': None, 'risk': 0.0}
