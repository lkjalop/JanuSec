from lark import Lark
from src.collectors.rfc3164_parser import RFC3164_GRAMMAR
p = Lark(RFC3164_GRAMMAR, start='start', parser='lalr')
line = "<34>Dec 23 12:34:56 myhost app[123]: A test message"
try:
    tree = p.parse(line)
    print(tree)
    print(tree.pretty())
except Exception as e:
    print('parse error', e)
