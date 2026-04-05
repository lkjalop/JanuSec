import pytest


def test_list_pagination_and_edit(test_app):
    from fastapi.testclient import TestClient
    # Build a synchronous TestClient backed by the FastAPI test app
    client = TestClient(test_app)
    # Ensure endpoint responds for page 1
    r = client.get('/api/v1/labeling/list?page=1&page_size=5')
    assert r.status_code == 200
    j = r.json()
    assert 'rows' in j
    # If there is at least one row and it has id, try edit (best-effort)
    if j.get('rows'):
        row = j['rows'][0]
        lid = row.get('id') or row.get('ID') or row.get('Id')
        if lid:
            r2 = client.patch('/api/v1/labeling/edit?label_id=%d&label=test_edit' % int(lid))
            assert r2.status_code in (200,204)
