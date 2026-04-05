from typing import Callable


def register_geo_asn_enricher(app, enricher: Callable):
    """Attach the geo/asn enricher callable to app.state for use by enrichment pipeline."""
    try:
        app.state.geo_asn_enricher = enricher
    except Exception:
        try:
            setattr(app, 'geo_asn_enricher', enricher)
        except Exception:
            pass

__all__ = ['register_geo_asn_enricher']
