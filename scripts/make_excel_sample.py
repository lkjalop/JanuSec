from openpyxl import Workbook
import os

out = os.path.join(os.path.dirname(__file__), '..', 'dump', 'Cyberstash_csv2_sample.xlsx')
wb = Workbook()
ws = wb.active
ws.append(['process_name','file_path','hash','command_line','user','host'])
rows = [
    ['powershell.exe','C:\\Users\\Alice\\AppData\\Local\\Temp\\mal.ps1','0000deadbeefcafebabe','powershell -e SGVsbG8=','alice','host-alice'],
    ['svchost.exe','C:\\Windows\\System32\\svchost.exe','abcd1234abcd1234','','system','host-bob'],
    ['notepad.exe','C:\\Temp\\notes.txt','ffffffffffffffff','notepad C:\\Temp\\notes.txt','user1','host-charlie'],
    ['excel.exe','C:\\Users\\bob\\AppData\\Roaming\\evil.xls','12345678123456781234567812345678','excel.exe C:\\Users\\bob\\AppData\\Roaming\\evil.xls','bob','host-bob'],
    ['rundll32.exe','C:\\Windows\\Temp\\drop.dll','0000cafebabedead','rundll32.exe C:\\Windows\\Temp\\drop.dll','svc','host-ev'],
    ['cmd.exe','C:\\Windows\\System32\\cmd.exe','1111222233334444','cmd /c calc.exe','user2','host-delta']
]
for r in rows:
    ws.append(r)
wb.save(out)
print('Wrote', out)
