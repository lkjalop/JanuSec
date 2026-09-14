import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.core.correlation.rules.email.bec_impersonation_enriched import email_bec_impersonation_enriched
from src.core.correlation.rules.lolbin.macos_lolbin_enriched import macos_lolbin_enriched

print('run email rule:')
e = {'from_address':'ceo@notcorp.com','display_name':'Chief Executive Officer','reply_to':'att@malicious.com','subject':'urgent wire'}
print(email_bec_impersonation_enriched(e))
print('emission:', e.get('correlation_emission'))

print('\nrun macos rule:')
m = {'process_name':'osascript','cmdline':'osascript -e "do shell script"','user':'alice'}
print(macos_lolbin_enriched(m))
print('emission:', m.get('correlation_emission'))
