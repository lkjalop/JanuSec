"""Compatibility shim: provide SyslogMessage when upstream package isn't installed.
This allows tests to import syslog_rfc5424_parser without adding the external dependency.
"""
from src.third_party_shims.syslog_rfc5424_parser import SyslogMessage  # type: ignore

__all__ = ["SyslogMessage"]
