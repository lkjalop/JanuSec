try:
    from src.domains.binary.static_analyzer import analyze_pe_bytes
except Exception:
    # fallback: provide stub that signals dependency missing
    def analyze_pe_bytes(buf: bytes):
        return {'error': 'static_analyzer_unavailable'}

__all__ = ['analyze_pe_bytes']
