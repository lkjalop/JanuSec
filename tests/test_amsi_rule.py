from src.core.correlation.rules.week1.amsi_bypass import amsi_bypass_rule


def test_amsi_encoded_command_detected():
    evt = {'process': {'cmdline': 'powershell -NoP -NonI -EncodedCommand ABCDEF'}}
    assert amsi_bypass_rule(evt) is True


def test_amsi_registry_edit_detected():
    evt = {'process': {'cmdline': 'powershell Set-ItemProperty -Path HKLM\\Software\\Amsi -Name Enabled -Value 0'}}
    assert amsi_bypass_rule(evt) is True


def test_amsi_parent_winword_spawn():
    evt = {'process': {'exe': 'powershell.exe', 'cmdline': 'powershell -Command Start-Sleep 1'}, 'parent': {'cmdline': 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE'}}
    assert amsi_bypass_rule(evt) is True
