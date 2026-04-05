from src.soar.engine import ENGINE

PLAYBOOK = {
  'id': 'pb_basic',
  'name': 'BasicNotifyAndTag',
  'steps': [
    {'id':'s1','action':'slack_notify','with_args':{'text':'Hello','channel':'#demo'}},
    {'id':'s2','action':'tag_event','with_args':{'tag':'demo'}, 'when':'True'}
  ]
}

def test_playbook_sequential_execution():
    ENGINE.load(PLAYBOOK)
    import asyncio
    ctx = {'event_id':'evt-1'}
    result = asyncio.run(ENGINE.run('pb_basic', ctx))
    assert result['outcome'] == 'success'
    assert len(result['steps']) == 2
    assert any(s.get('result',{}).get('sent') for s in result['steps'])
    assert 'event_tags' in ctx and 'demo' in ctx['event_tags']
