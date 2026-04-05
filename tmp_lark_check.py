from lark import Lark
G='start: expr\nexpr: "a"'
parser = Lark(G, start='start', parser='lalr')
print('has parse?', hasattr(parser, 'parse'))
try:
    tree = parser.parse('a')
    print('parsed ok')
except Exception as e:
    print('parse failed', e)
