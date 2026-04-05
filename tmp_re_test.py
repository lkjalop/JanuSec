import re
pat = '(gmail|yahoo|hotmail)\\.com$'
print('pattern repr:', repr(pat))
print('search:', re.search(pat, 'supplier@gmail.com'))
pat2 = '(gmail|yahoo|hotmail)\.com$'
print('pattern2 repr:', repr(pat2))
print('search2:', re.search(pat2, 'supplier@gmail.com'))
# raw string
pat3 = r'(gmail|yahoo|hotmail)\.com$'
print('pattern3 repr:', repr(pat3))
print('search3:', re.search(pat3, 'supplier@gmail.com'))
print('escape count in pattern len:', len(pat), pat)
