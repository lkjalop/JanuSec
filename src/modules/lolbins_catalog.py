from __future__ import annotations

WINDOWS_LOLBINS = {
    'mshta.exe','rundll32.exe','regsvr32.exe','wmic.exe','powershell.exe','wscript.exe','cscript.exe','schtasks.exe','bitsadmin.exe','certutil.exe'
}

MACOS_LOLBINS = {
    'osascript','curl','python','ruby','bash','launchctl','osascript','ssh'
}

LINUX_LOLBINS = {
    'bash','sh','curl','wget','python','perl','nc','socat','systemctl','cron'
}

__all__ = ['WINDOWS_LOLBINS','MACOS_LOLBINS','LINUX_LOLBINS']
