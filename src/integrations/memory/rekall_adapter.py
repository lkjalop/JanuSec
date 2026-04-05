from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


class RekallAdapter:
    """Thin wrapper around Rekall CLI with fixture fallback."""

    def __init__(
        self,
        *,
        executable: Optional[str] = None,
        python_bin: Optional[str] = None,
        default_plugins: Optional[Iterable[str]] = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        self.executable = executable or os.getenv('REKALL_PATH') or 'rekall'
        self.python_bin = python_bin or shutil.which('python3') or shutil.which('python') or 'python3'
        self.default_plugins = list(default_plugins or ['pslist', 'dlllist', 'memmap'])
        self.timeout_seconds = timeout_seconds

    def run_plugins(
        self,
        dump_path: Path,
        *,
        profile: Optional[str] = None,
        plugins: Optional[Iterable[str]] = None,
        plugin_args: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, Any]:
        dump_path = Path(dump_path)
        if not dump_path.exists():
            raise FileNotFoundError(f'memory dump not found: {dump_path}')
        result: Dict[str, Any] = {}
        for plugin in list(plugins or self.default_plugins):
            result[plugin] = self._run_single_plugin(dump_path, plugin, profile, plugin_args or {})
        return result

    def _run_single_plugin(
        self,
        dump_path: Path,
        plugin: str,
        profile: Optional[str],
        plugin_args: Dict[str, List[str]],
    ) -> Any:
        if self._rekall_available():
            cmd = [self.python_bin, self.executable, '-f', str(dump_path), plugin, '--format', 'json']
            if profile:
                cmd.extend(['--profile', profile])
            extra = plugin_args.get(plugin) or []
            cmd.extend(extra)
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            except Exception as exc:  # pragma: no cover
                return self._simulate_output(dump_path, plugin, error=str(exc))
            if proc.returncode == 0 and proc.stdout.strip():
                try:
                    return json.loads(proc.stdout)
                except json.JSONDecodeError:
                    return {'raw': proc.stdout}
            error_msg = proc.stderr.strip() or proc.stdout.strip() or f'rekall_exit_{proc.returncode}'
            return self._simulate_output(dump_path, plugin, error=error_msg)
        return self._simulate_output(dump_path, plugin)

    def _rekall_available(self) -> bool:
        exe = self.executable
        if not exe:
            return False
        if os.path.isabs(exe) or os.path.sep in exe:
            return Path(exe).exists()
        return shutil.which(exe) is not None

    def _simulate_output(self, dump_path: Path, plugin: str, error: Optional[str] = None) -> Dict[str, Any]:
        fixtures = [
            dump_path.with_suffix(f'.{plugin}.rekall.json'),
            dump_path.with_suffix('.rekall.json'),
        ]
        for fixture in fixtures:
            if fixture.exists():
                try:
                    return json.loads(fixture.read_text(encoding='utf-8'))
                except Exception:
                    continue
        return {'plugin': plugin, 'status': 'not_run', 'error': error or 'rekall_unavailable'}


__all__ = ['RekallAdapter']
