from fastapi import FastAPI, HTTPException
from typing import Any
from .catalog import FactorCatalog

app = FastAPI(title='SultryTAI (demo)')
catalog = FactorCatalog()

@app.on_event('startup')
def startup_event():
    try:
        catalog.load()
    except Exception as e:
        # In demo mode, we don't fatal exit — allow endpoint to report missing catalog
        print('Catalog load error:', e)

@app.get('/health')
def health() -> Any:
    return {'status': 'ok'}

@app.get('/factors')
def get_factors(domain: str = None):
    if not catalog.factors:
        raise HTTPException(status_code=503, detail='catalog not loaded')
    if domain:
        return catalog.find_by_domain(domain)
    return catalog.factors
