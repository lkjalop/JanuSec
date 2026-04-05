import tempfile
from src.integrations import falco_adapter
from src.core import ebpf_correlation as ec


def test_process_falco_file(monkeypatch):
    # prepare a temp file with two falco JSON lines
    lines = [
        '{"rule":"kprobe_attach","output":"attach failed","priority":"Warning","output_fields":{"proc.pid":111,"proc.name":"bad"}}',
        '{"rule":"execve_spike","output":"execve spike","priority":"Error","output_fields":{"proc.pid":222,"proc.name":"weird"}}'
    ]
    tf = tempfile.NamedTemporaryFile('w+', delete=False)
    try:
        for l in lines:
            tf.write(l + '\n')
        tf.flush()
        tf.close()
        # monkeypatch emit_incident to avoid calling server
        monkeypatch.setattr(ec, 'emit_incident', lambda enriched: {'status':'local','result':enriched})
        count = falco_adapter.process_falco_file(tf.name)
        assert count == 2
    finally:
        import os
        try:
            os.unlink(tf.name)
        except Exception:
            pass
