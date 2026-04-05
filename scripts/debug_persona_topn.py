import traceback
from src.reporting.persona_views import generate_persona_view


def make_report_with_many_items(n=50):
    report = {
        'report_id': 'r-test-topn',
        'verdict': {'final_verdict': 'REVIEW', 'final_confidence': 0.5, 'all_factors': []},
        'network_highlights': {},
        'summary': {},
        'verdict_stats': {},
        'risk_quantification': {'severity': 'MEDIUM'},
    }
    # Populate fields expected by persona summaries
    report['verdict']['all_factors'] = [{'factor_name': f'f{i}', 'contribution_score': float(i), 'evidence_count': i} for i in range(n)]
    report['evidence_items'] = [{'extracted_iocs': {'ip': [f'10.0.0.{i}']}} for i in range(n)]
    report['attack_timeline'] = [{'entity': f'host{i}'} for i in range(n)]
    report['recommended_actions'] = [{'primary_action': f'a{i}', 'urgency': 'normal'} for i in range(n)]
    return report


def main():
    rpt = make_report_with_many_items(40)
    try:
        v = generate_persona_view(rpt, persona='executive', disclosure_level=2, top_n=5)
        print('Generated persona view OK')
        print(v)
    except Exception as e:
        print('Exception during generate_persona_view:')
        traceback.print_exc()


if __name__ == '__main__':
    main()
