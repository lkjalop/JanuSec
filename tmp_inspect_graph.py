from src.api import graph_session_endpoints as gse
s1 = {'entities':{'user':['alice'],'host':['host1'],'ip':['10.0.0.1'],'file_hash':['h1'],'domain':['d1']}}
s2 = {'entities':{'user':['bob','alice'],'host':['host2'],'ip':['10.0.0.2','10.0.0.1'],'file_hash':['h2'],'domain':['d2']}}
print('canonical s1:', gse._canonical_sets(s1))
print('canonical s2:', gse._canonical_sets(s2))
print('compute matrix (wrapped data):', gse._compute_overlap_matrix([('s1', {'data': s1}), ('s2', {'data': s2})]))
print('compute matrix (direct):', gse._compute_overlap_matrix([('s1', s1), ('s2', s2)]))
