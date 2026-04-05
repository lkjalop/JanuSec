from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


class Volatility3Adapter:
    """Thin wrapper around Volatility 3 CLI with graceful fallbacks."""

    def __init__(
        self,
        *,
        executable: Optional[str] = None,
        python_bin: Optional[str] = None,
        default_plugins: Optional[Iterable[str]] = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        self.executable = executable or os.getenv("VOLATILITY3_PATH") or "vol.py"
        self.python_bin = python_bin or os.getenv("VOLATILITY3_PYTHON") or shutil.which("python3") or shutil.which("python") or "python3"
        self.default_plugins = list(default_plugins or ["windows.pslist", "windows.dlllist", "windows.malfind"])
        self.timeout_seconds = timeout_seconds

    def run_plugins(
        self,
        dump_path: Path,
        *,
        plugins: Optional[Iterable[str]] = None,
        profile: Optional[str] = None,
        plugin_args: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, Any]:
        """Execute plugins against a dump. Falls back to JSON fixtures when Volatility is unavailable."""

        dump_path = Path(dump_path)
        selected_plugins = list(plugins or self.default_plugins)
        plugin_args = plugin_args or {}
        results: Dict[str, Any] = {}

        if not dump_path.exists():
            raise FileNotFoundError(f"memory dump not found: {dump_path}")

        for plugin in selected_plugins:
            plugin_result = self._run_single_plugin(dump_path, plugin, profile, plugin_args.get(plugin) or [])
            results[plugin] = plugin_result
        return results

    def _run_single_plugin(
        self,
        dump_path: Path,
        plugin: str,
        profile: Optional[str],
        extra_args: List[str],
    ) -> Any:
        cmd: List[str] = []
        output: Any = None
        if self._volatility_available():
            cmd = [self.python_bin, self.executable, "-f", str(dump_path), plugin, "--output=json"]
            if profile:
                cmd.extend(["--profile", profile])
            cmd.extend(extra_args or [])
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=self.timeout_seconds,
                )
            except Exception as exc:  # pragma: no cover - runtime environment specific
                return self._simulate_output(dump_path, plugin, error=str(exc))

            if proc.returncode == 0 and proc.stdout.strip():
                try:
                    output = json.loads(proc.stdout)
                except json.JSONDecodeError:
                    output = {"raw": proc.stdout}
            else:
                error_msg = proc.stderr.strip() or proc.stdout.strip() or f"volatility_exit_{proc.returncode}"
                return self._simulate_output(dump_path, plugin, error=error_msg)
        else:
            output = self._simulate_output(dump_path, plugin)
        return output

    def _volatility_available(self) -> bool:
        return shutil.which(self.executable) is not None or Path(self.executable).exists()

    def _simulate_output(self, dump_path: Path, plugin: str, error: Optional[str] = None) -> Dict[str, Any]:
        """Load offline fixture when Volatility is unavailable."""
        fixture_paths = [
            dump_path.with_suffix(f".{plugin}.json"),
            dump_path.with_suffix(".json"),
        ]
        for fixture in fixture_paths:
            if fixture.exists():
                try:
                    return json.loads(fixture.read_text(encoding="utf-8"))
                except Exception:
                    continue
        return {"plugin": plugin, "status": "not_run", "error": error or "volatility_unavailable"}


__all__ = ["Volatility3Adapter"]
