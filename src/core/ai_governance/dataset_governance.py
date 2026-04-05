from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
import hashlib
import json
import logging
import os
from pathlib import Path


logger = logging.getLogger(__name__)


@dataclass
class DatasetCard:
    dataset_id: str
    dataset_name: str
    version: str
    created_date: str
    last_updated: str

    data_sources: List[str]
    data_types: List[str]
    size_records: int
    size_bytes: int
    date_range: Dict[str, str]

    completeness_score: float
    accuracy_score: float
    consistency_score: float
    error_rate: float

    demographic_coverage: Dict[str, Any]
    geographic_coverage: List[str]
    temporal_coverage: str

    bias_testing_performed: bool
    bias_metrics: Dict[str, float]
    known_limitations: List[str]

    data_lineage: List[str]
    data_owners: List[str]
    data_processors: List[str]

    pii_present: bool
    anonymization_applied: bool
    encryption_at_rest: bool
    access_controls: str

    gdpr_compliant: bool
    legal_basis: str
    data_retention_days: int

    schema: Dict[str, str]
    data_format: str
    checksum_sha256: str


class DatasetGovernance:
    """Dataset governance and minimal Article 10 reporting."""

    def __init__(self, data_dir: str = "data/datasets") -> None:
        self.data_dir = data_dir
        self.datasets: Dict[str, DatasetCard] = {}
        self._load_registered_datasets()

    def _cards_dir(self) -> Path:
        return Path(self.data_dir) / "cards"

    def _load_registered_datasets(self) -> None:
        p = self._cards_dir()
        if not p.exists():
            return
        for f in p.glob("*.json"):
            try:
                obj = json.loads(f.read_text(encoding="utf-8"))
                card = DatasetCard(**obj)
                self.datasets[card.dataset_id] = card
            except Exception as exc:
                logger.warning(f"Failed to load dataset card {f}: {exc}")

    def _compute_checksum(self, path: str) -> str:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def register_dataset(self, dataset_id: str, dataset_path: str, metadata: Dict[str, Any]) -> DatasetCard:
        size_bytes = 0
        try:
            if os.path.exists(dataset_path):
                size_bytes = os.path.getsize(dataset_path)
        except Exception:
            size_bytes = 0
        checksum = self._compute_checksum(dataset_path)
        now = datetime.now().isoformat()
        card = DatasetCard(
            dataset_id=dataset_id,
            dataset_name=metadata.get("name", dataset_id),
            version=metadata.get("version", "1.0.0"),
            created_date=now,
            last_updated=now,
            data_sources=metadata.get("sources", []),
            data_types=metadata.get("data_types", []),
            size_records=int(metadata.get("size_records", 0)),
            size_bytes=int(size_bytes),
            date_range=metadata.get("date_range", {}),
            completeness_score=float(metadata.get("completeness_score", 0.0)),
            accuracy_score=float(metadata.get("accuracy_score", 0.0)),
            consistency_score=float(metadata.get("consistency_score", 0.0)),
            error_rate=float(metadata.get("error_rate", 0.0)),
            demographic_coverage=metadata.get("demographic_coverage", {}),
            geographic_coverage=metadata.get("geographic_coverage", []),
            temporal_coverage=metadata.get("temporal_coverage", ""),
            bias_testing_performed=bool(metadata.get("bias_testing_performed", False)),
            bias_metrics=metadata.get("bias_metrics", {}),
            known_limitations=metadata.get("known_limitations", []),
            data_lineage=metadata.get("data_lineage", []),
            data_owners=metadata.get("data_owners", []),
            data_processors=metadata.get("data_processors", []),
            pii_present=bool(metadata.get("pii_present", False)),
            anonymization_applied=bool(metadata.get("anonymization_applied", False)),
            encryption_at_rest=bool(metadata.get("encryption_at_rest", True)),
            access_controls=metadata.get("access_controls", "role_based"),
            gdpr_compliant=bool(metadata.get("gdpr_compliant", False)),
            legal_basis=metadata.get("legal_basis", ""),
            data_retention_days=int(metadata.get("data_retention_days", 0)),
            schema=metadata.get("schema", {}),
            data_format=metadata.get("data_format", "jsonl"),
            checksum_sha256=checksum,
        )
        # Persist card to disk for durability
        try:
            d = self._cards_dir()
            d.mkdir(parents=True, exist_ok=True)
            (d / f"{dataset_id}.json").write_text(json.dumps(card.__dict__, indent=2), encoding="utf-8")
        except Exception:
            pass
        self.datasets[dataset_id] = card
        return card

    def validate_dataset(self, dataset_id: str) -> Dict[str, Any]:
        card = self.datasets.get(dataset_id)
        if not card:
            return {"valid": False, "errors": ["dataset_not_found"], "warnings": []}
        errors: List[str] = []
        warnings: List[str] = []
        if not card.dataset_name:
            errors.append("missing_dataset_name")
        if not card.schema:
            warnings.append("schema_missing")
        if card.pii_present and not card.anonymization_applied:
            warnings.append("pii_present_no_anonymization")
        if not card.bias_testing_performed:
            warnings.append("bias_testing_not_performed")
        if not card.gdpr_compliant:
            errors.append("gdpr_non_compliant")
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "dataset_id": dataset_id,
            "validated_at": datetime.now().isoformat(),
        }

    def generate_article_10_report(self) -> Dict[str, Any]:
        total = len(self.datasets)
        compliant = sum(1 for c in self.datasets.values() if c.gdpr_compliant and c.bias_testing_performed)
        with_pii = sum(1 for c in self.datasets.values() if c.pii_present)
        anonymized = sum(1 for c in self.datasets.values() if c.pii_present and c.anonymization_applied)
        return {
            "compliance_article": "EU AI Act - Article 10",
            "assessment_date": datetime.now().isoformat(),
            "total_datasets": total,
            "compliant_datasets": compliant,
            "compliance_rate": (compliant / total) if total else 0.0,
            "datasets_with_pii": with_pii,
            "pii_anonymization_rate": (anonymized / with_pii) if with_pii else 0.0,
            "dataset_cards": [
                {
                    "dataset_id": c.dataset_id,
                    "dataset_name": c.dataset_name,
                    "version": c.version,
                    "quality_score_avg": (c.completeness_score + c.accuracy_score + c.consistency_score) / 3.0,
                    "gdpr_compliant": c.gdpr_compliant,
                    "bias_tested": c.bias_testing_performed,
                }
                for c in self.datasets.values()
            ],
        }


__all__ = ["DatasetCard", "DatasetGovernance"]

