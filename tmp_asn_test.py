from src.live import asn_stats
asn_stats.populate_from_source({'AS1':10,'AS2':2,'AS3':1})
print('distinct', asn_stats.get_current_asn_distinct())
print('rarity AS1', asn_stats.rarity('AS1'))
print('percentile AS1', asn_stats.percentile('AS1'))
print('percentile AS3', asn_stats.percentile('AS3'))
