"""Persist StandardScaler for feature normalization."""
from __future__ import annotations
from src.security.model_artifacts import load_approved_model
import os, pickle
from typing import Any, List, Dict

def save_scaler(scaler: Any, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as fh:
        pickle.dump(scaler, fh)

def load_scaler(path: str) -> Any:
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    return load_approved_model(path)
