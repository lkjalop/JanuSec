from src.live import asn_lookup as al1
import src.live.asn_lookup as al2
print('id al1', id(al1))
print('id al2', id(al2))
al1.clear_mapping()
al1.seed_mapping({'8.8.8.8':'AS65001','8.8.4.4':'AS65002'})
print('al1.lookup 8.8.8.8 ->', al1.lookup_asn('8.8.8.8'))
print('al2.lookup 8.8.8.8 ->', al2.lookup_asn('8.8.8.8'))
# import graph_sessions module and then check package attr
import importlib
mod = importlib.import_module('src.api.graph_sessions')
from src.live import asn_lookup as al3
print('id al3', id(al3))
print('al3.lookup 8.8.8.8 ->', al3.lookup_asn('8.8.8.8'))
