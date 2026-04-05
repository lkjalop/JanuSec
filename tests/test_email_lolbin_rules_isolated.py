from src.core.correlation.rules.email.bec_impersonation_enriched import email_bec_impersonation_enriched
from src.core.correlation.rules.email.dkim_dmarc_failure_enriched import email_dkim_dmarc_failure_enriched
from src.core.correlation.rules.email.display_name_fuzzy_enriched import email_display_name_fuzzy_enriched
from src.core.correlation.rules.lolbin.macos_lolbin_enriched import macos_lolbin_enriched
from src.core.correlation.rules.lolbin.linux_lolbin_enriched import linux_lolbin_enriched


def test_email_bec_impersonation():
    event = {'from_address':'ceo@notcorp.com','display_name':'Chief Executive Officer','reply_to':'att@malicious.com','subject':'urgent wire'}
    assert email_bec_impersonation_enriched(event) is True


def test_dkim_dmarc_failure():
    event = {'spf_result':'pass','dkim_result':'fail','dmarc_result':'fail'}
    assert email_dkim_dmarc_failure_enriched(event) is True


def test_display_name_fuzzy():
    event = {'display_name':'John Q Public','user_directory_lookup':{'display_name':'John Public'}}
    assert email_display_name_fuzzy_enriched(event) is True


def test_macos_lolbin():
    event = {'process_name':'osascript','cmdline':'osascript -e "do shell script"','user':'alice'}
    assert macos_lolbin_enriched(event) is True


def test_linux_lolbin():
    event = {'process_name':'cron','cmdline':'/usr/sbin/cron','uid':1001}
    assert linux_lolbin_enriched(event) is True
