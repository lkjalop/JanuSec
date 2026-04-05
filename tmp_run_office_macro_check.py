from importlib import import_module
from src.core.correlation.rules.week1.office_macro_chain import office_macro_spawn_powershell, office_macro_chain

# positive case: direct powershell in process with encoded command
event1 = {
    'event.source': 'VBA macro in document.docm',
    'process': 'PowerShell.exe',
    'cmdline': '-EncodedCommand SGVsbG8=',
}
# child-based case
event2 = {
    'event.source': 'document.xlsm',
    'process': 'winword.exe',
    'children': [
        {'process': 'powershell.exe', 'cmdline': '-EncodedCommand SGVsbG8='}
    ]
}
# false positive
event3 = {
    'event.source': 'document.pdf',
    'process': 'acrobat.exe',
    'cmdline': '/n'
}

print('event1 ->', office_macro_spawn_powershell(event1))
print('event2 ->', office_macro_spawn_powershell(event2))
print('event3 ->', office_macro_spawn_powershell(event3))

# external c2 chain
event4 = {
    'parent_process': 'winword.exe',
    'child_process': 'powershell.exe',
    'network_outbound_domains': ['evil.example.com']
}
print('event4 external chain ->', office_macro_chain(event4))
