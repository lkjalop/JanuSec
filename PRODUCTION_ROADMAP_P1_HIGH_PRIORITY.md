# JanuSec Platform - P1 HIGH PRIORITY Production Roadmap
## Important Features for Competitive Differentiation

**Priority Level:** P1 - HIGH PRIORITY
**Timeline:** 8-12 Weeks
**Business Impact:** MEDIUM-HIGH - Strong differentiators, not critical for launch
**Dependencies:** P0 features, cloud storage (S3/Azure Blob), forensic tools

---

## EXECUTIVE SUMMARY

This roadmap covers **high-value features** that differentiate JanuSec from competitors and expand platform capabilities for advanced security teams:

1. **KAPE Forensic Analysis** - Digital forensics and incident response capabilities
2. **LOLBins Expansion (macOS/Linux)** - Multi-platform threat detection
3. **Advanced Persona Customization** - AI-powered report personalization
4. **Scheduled Report Distribution** - Automated delivery to stakeholders

**Expected Outcome:** Platform becomes **best-in-class for forensic analysis** and **cross-platform threat detection**, with **executive-ready automated reporting**.

---

## P1-1: KAPE FORENSIC ARTIFACT PARSING

### Current State
- ❌ **Not implemented:** KAPE ingestion pipeline
- ❌ **Not implemented:** Artifact parser and MITRE tagging
- ❌ **Not implemented:** UI for forensic timeline exploration
- ⚠️ **Endpoints exist:** Basic API structure in `src/api/forensics_endpoints.py`

### Business Value
- **Critical for:** Incident response teams, digital forensics, breach investigations
- **Market differentiation:** Most threat detection platforms don't offer forensic analysis
- **Revenue opportunity:** Premium IR/forensics tier pricing

### What is KAPE?

**KAPE (Kroll Artifact Parser and Extractor)** is a forensic triage tool that collects and processes Windows artifacts:
- **Registry hives** (SYSTEM, SOFTWARE, SAM, NTUSER.DAT)
- **Event logs** (Security, System, Application, PowerShell)
- **Browser history** (Chrome, Firefox, Edge)
- **Prefetch files** (program execution history)
- **Jump lists & LNK files** (recently accessed files)
- **SRUM database** (System Resource Usage Monitor)
- **MFT (Master File Table)** for filesystem timeline
- **AmCache/ShimCache** (application execution evidence)

### Technical Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  KAPE Forensic Pipeline                      │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐       ┌──────────────┐                    │
│  │   S3/SFTP    │       │  Direct      │                    │
│  │   Upload     │───────│  Upload API  │                    │
│  │   (Async)    │       │  (Sync)      │                    │
│  └──────┬───────┘       └──────┬───────┘                    │
│         │                       │                            │
│         └───────────┬───────────┘                            │
│                     ▼                                        │
│         ┌────────────────────────┐                          │
│         │  Ingestion Watcher     │                          │
│         │  (S3 Events/inotify)   │                          │
│         └────────────────────────┘                          │
│                     │                                        │
│                     ▼                                        │
│         ┌────────────────────────┐                          │
│         │  Artifact Parser       │                          │
│         │  (Registry/Events/MFT) │                          │
│         └────────────────────────┘                          │
│                     │                                        │
│         ┌───────────┼───────────┐                           │
│         ▼           ▼           ▼                           │
│  ┌──────────┐ ┌─────────┐ ┌──────────┐                     │
│  │  MITRE   │ │Timeline │ │HopGraph  │                     │
│  │ Tagger   │ │Builder  │ │Integrator│                     │
│  └──────────┘ └─────────┘ └──────────┘                     │
│         │           │           │                           │
│         └───────────┼───────────┘                           │
│                     ▼                                        │
│         ┌────────────────────────┐                          │
│         │  Forensic Event Store  │                          │
│         │  (PostgreSQL + S3)     │                          │
│         └────────────────────────┘                          │
│                     │                                        │
│                     ▼                                        │
│         ┌────────────────────────┐                          │
│         │  Timeline UI           │                          │
│         │  (React Component)     │                          │
│         └────────────────────────┘                          │
└─────────────────────────────────────────────────────────────┘
```

### Implementation Plan

#### Phase 1: Ingestion Infrastructure (Week 1-2)

**File: `src/collectors/kape/kape_ingestor.py`** (NEW)

```python
"""
KAPE artifact ingestion service.
Monitors S3/SFTP for KAPE output archives and triggers parsing.
"""

import asyncio
import boto3
import zipfile
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional, AsyncIterator
import logging
import hashlib

from src.db.database import DatabaseManager

logger = logging.getLogger(__name__)


class KAPEIngestor:
    """Ingests KAPE artifact archives from S3 or SFTP."""

    def __init__(
        self,
        db: DatabaseManager,
        storage_backend: str = "s3",  # s3, azure_blob, or sftp
        bucket_name: Optional[str] = None,
        prefix: str = "kape-artifacts/"
    ):
        self.db = db
        self.storage_backend = storage_backend
        self.bucket_name = bucket_name
        self.prefix = prefix

        if storage_backend == "s3":
            self.s3_client = boto3.client("s3")

    async def watch_for_uploads(self) -> AsyncIterator[Dict[str, Any]]:
        """Watch storage for new KAPE archives."""

        if self.storage_backend == "s3":
            async for artifact_info in self._watch_s3():
                yield artifact_info
        elif self.storage_backend == "sftp":
            async for artifact_info in self._watch_sftp():
                yield artifact_info

    async def _watch_s3(self) -> AsyncIterator[Dict[str, Any]]:
        """Poll S3 bucket for new KAPE archives."""

        seen_keys = set()

        while True:
            try:
                # List objects in prefix
                response = self.s3_client.list_objects_v2(
                    Bucket=self.bucket_name,
                    Prefix=self.prefix
                )

                for obj in response.get("Contents", []):
                    key = obj["Key"]

                    # Skip if already processed
                    if key in seen_keys:
                        continue

                    # Check if it's a KAPE archive (zip file)
                    if not key.endswith(".zip"):
                        continue

                    # Download and process
                    logger.info(f"New KAPE archive detected: {key}")

                    artifact_info = await self._download_and_validate(key)
                    if artifact_info:
                        seen_keys.add(key)
                        yield artifact_info

                # Wait before next poll
                await asyncio.sleep(60)  # Poll every minute

            except Exception as e:
                logger.error(f"S3 watch error: {e}")
                await asyncio.sleep(60)

    async def _download_and_validate(self, s3_key: str) -> Optional[Dict[str, Any]]:
        """Download KAPE archive from S3 and validate."""

        # Create temp directory
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            archive_path = temp_path / "kape_archive.zip"

            # Download from S3
            try:
                self.s3_client.download_file(
                    self.bucket_name,
                    s3_key,
                    str(archive_path)
                )
            except Exception as e:
                logger.error(f"Failed to download {s3_key}: {e}")
                return None

            # Calculate hash
            file_hash = self._calculate_hash(archive_path)

            # Validate zip integrity
            try:
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    # Check for bad files
                    bad_file = zf.testzip()
                    if bad_file:
                        logger.error(f"Corrupt file in archive: {bad_file}")
                        return None

                    # List contents
                    file_list = zf.namelist()

            except zipfile.BadZipFile as e:
                logger.error(f"Invalid zip file {s3_key}: {e}")
                return None

            # Extract metadata from filename
            # Expected format: KAPE_<hostname>_<timestamp>.zip
            parts = Path(s3_key).stem.split("_")
            if len(parts) >= 3:
                hostname = parts[1]
                timestamp = parts[2]
            else:
                hostname = "unknown"
                timestamp = "unknown"

            # Store metadata in database
            artifact_id = await self._store_metadata(
                s3_key=s3_key,
                file_hash=file_hash,
                hostname=hostname,
                timestamp=timestamp,
                file_count=len(file_list)
            )

            return {
                "artifact_id": artifact_id,
                "s3_key": s3_key,
                "local_path": str(archive_path),
                "file_hash": file_hash,
                "hostname": hostname,
                "timestamp": timestamp,
                "file_list": file_list
            }

    def _calculate_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    async def _store_metadata(
        self,
        s3_key: str,
        file_hash: str,
        hostname: str,
        timestamp: str,
        file_count: int
    ) -> int:
        """Store KAPE artifact metadata in database."""

        async with self.db.get_connection() as conn:
            artifact_id = await conn.fetchval("""
                INSERT INTO kape_artifacts (
                    s3_key, file_hash, hostname, collection_timestamp,
                    file_count, status, created_at
                )
                VALUES ($1, $2, $3, $4, $5, 'pending', NOW())
                RETURNING id
            """, s3_key, file_hash, hostname, timestamp, file_count)

            logger.info(f"Stored KAPE artifact metadata: ID={artifact_id}, hostname={hostname}")
            return artifact_id

    async def _watch_sftp(self) -> AsyncIterator[Dict[str, Any]]:
        """Watch SFTP directory for new KAPE archives."""
        # TODO: Implement SFTP watcher using paramiko
        raise NotImplementedError("SFTP watcher not yet implemented")
```

**Database Migration: `migrations/022_kape_artifacts.sql`** (NEW)

```sql
-- KAPE forensic artifacts storage
CREATE TABLE IF NOT EXISTS kape_artifacts (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255),
    case_id VARCHAR(255),  -- Optional case/incident ID
    s3_key VARCHAR(1024) NOT NULL UNIQUE,
    file_hash VARCHAR(64) NOT NULL,  -- SHA256
    hostname VARCHAR(255),
    collection_timestamp VARCHAR(255),
    file_count INTEGER,
    status VARCHAR(50) DEFAULT 'pending',  -- pending, parsing, completed, failed
    parsed_at TIMESTAMP,
    retention_until TIMESTAMP,  -- For data retention policy
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_kape_artifacts_tenant ON kape_artifacts(tenant_id);
CREATE INDEX idx_kape_artifacts_hostname ON kape_artifacts(hostname);
CREATE INDEX idx_kape_artifacts_status ON kape_artifacts(status);
CREATE INDEX idx_kape_artifacts_retention ON kape_artifacts(retention_until) WHERE retention_until IS NOT NULL;

-- Parsed forensic events from KAPE artifacts
CREATE TABLE IF NOT EXISTS forensic_events (
    id SERIAL PRIMARY KEY,
    artifact_id INTEGER REFERENCES kape_artifacts(id) ON DELETE CASCADE,
    tenant_id VARCHAR(255),
    event_type VARCHAR(100),  -- registry_key_set, file_created, process_executed, etc.
    event_timestamp TIMESTAMP,
    source_file VARCHAR(512),  -- Which artifact file (e.g., SYSTEM registry, Security.evtx)

    -- Event details (flexible JSON)
    actor VARCHAR(255),  -- Username or SID
    action VARCHAR(255),  -- SetValue, Delete, Execute, etc.
    target VARCHAR(1024),  -- Registry key, file path, process name
    details JSONB,  -- Full event details

    -- MITRE ATT&CK mapping
    mitre_techniques TEXT[],  -- Array of technique IDs (T1078, T1547, etc.)
    mitre_tactics TEXT[],  -- Array of tactics

    -- Risk scoring
    suspicion_score FLOAT DEFAULT 0.0,
    is_lolbin BOOLEAN DEFAULT FALSE,
    is_persistence BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_forensic_events_artifact ON forensic_events(artifact_id);
CREATE INDEX idx_forensic_events_tenant ON forensic_events(tenant_id);
CREATE INDEX idx_forensic_events_timestamp ON forensic_events(event_timestamp);
CREATE INDEX idx_forensic_events_type ON forensic_events(event_type);
CREATE INDEX idx_forensic_events_actor ON forensic_events(actor);
CREATE INDEX idx_forensic_events_mitre ON forensic_events USING GIN(mitre_techniques);

-- Forensic timeline aggregation (for UI performance)
CREATE MATERIALIZED VIEW forensic_timeline_summary AS
SELECT
    artifact_id,
    date_trunc('hour', event_timestamp) AS time_bucket,
    event_type,
    COUNT(*) AS event_count,
    AVG(suspicion_score) AS avg_suspicion,
    array_agg(DISTINCT mitre_techniques) AS techniques
FROM forensic_events
GROUP BY artifact_id, time_bucket, event_type;

CREATE INDEX idx_forensic_timeline_artifact ON forensic_timeline_summary(artifact_id);

COMMENT ON TABLE kape_artifacts IS 'KAPE forensic artifact archives and metadata';
COMMENT ON TABLE forensic_events IS 'Parsed events from KAPE artifacts with MITRE mapping';
```

#### Phase 2: Artifact Parsing (Week 3-5)

**File: `src/parsers/kape/registry_parser.py`** (NEW)

```python
"""
Windows Registry parser for KAPE artifacts.
Extracts persistence mechanisms, user activity, and system configuration.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
import struct

# Using python-registry library for parsing
try:
    from Registry import Registry
except ImportError:
    logger.warning("python-registry not installed, KAPE registry parsing disabled")
    Registry = None

logger = logging.getLogger(__name__)


class RegistryParser:
    """Parses Windows registry hives for forensic artifacts."""

    # Persistence locations to monitor
    PERSISTENCE_KEYS = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows\CurrentVersion\RunServices",
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"System\CurrentControlSet\Services",  # Service persistence
        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",  # Userinit, Shell
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    ]

    # MITRE technique mapping for registry keys
    MITRE_MAPPING = {
        r"CurrentVersion\Run": "T1547.001",  # Boot or Logon Autostart Execution: Registry Run Keys
        r"Services": "T1543.003",  # Create or Modify System Process: Windows Service
        r"Winlogon": "T1547.004",  # Boot or Logon Autostart Execution: Winlogon Helper DLL
        r"AppInit_DLLs": "T1546.010",  # Event Triggered Execution: AppInit DLLs
        r"Image File Execution Options": "T1546.012"  # Image File Execution Options Injection
    }

    def __init__(self):
        if not Registry:
            raise ImportError("python-registry library required for registry parsing")

    async def parse_hive(self, hive_path: Path, hive_type: str) -> List[Dict[str, Any]]:
        """Parse a registry hive and extract forensic events."""

        events = []

        try:
            reg = Registry.Registry(str(hive_path))

            if hive_type == "SYSTEM":
                events.extend(await self._parse_system_hive(reg))
            elif hive_type == "SOFTWARE":
                events.extend(await self._parse_software_hive(reg))
            elif hive_type == "NTUSER.DAT":
                events.extend(await self._parse_ntuser_hive(reg))
            elif hive_type == "SAM":
                events.extend(await self._parse_sam_hive(reg))

            logger.info(f"Parsed {hive_path.name}: {len(events)} events extracted")

        except Exception as e:
            logger.error(f"Failed to parse registry hive {hive_path}: {e}")

        return events

    async def _parse_software_hive(self, reg: Registry.Registry) -> List[Dict[str, Any]]:
        """Parse SOFTWARE hive for persistence and installed software."""

        events = []

        # Check Run keys for persistence
        for key_path in self.PERSISTENCE_KEYS:
            try:
                key = reg.open(key_path)

                for value in key.values():
                    # Extract persistence entry
                    event = {
                        "event_type": "registry_persistence",
                        "event_timestamp": self._filetime_to_datetime(key.timestamp()),
                        "source_file": "SOFTWARE",
                        "action": "SetValue",
                        "target": f"{key_path}\\{value.name()}",
                        "details": {
                            "value_name": value.name(),
                            "value_data": value.value(),
                            "value_type": value.value_type_str()
                        },
                        "mitre_techniques": self._map_key_to_mitre(key_path),
                        "mitre_tactics": ["Persistence", "Privilege Escalation"],
                        "suspicion_score": self._calculate_persistence_score(value),
                        "is_persistence": True
                    }

                    events.append(event)

            except Registry.RegistryKeyNotFoundException:
                continue

        return events

    async def _parse_ntuser_hive(self, reg: Registry.Registry) -> List[Dict[str, Any]]:
        """Parse NTUSER.DAT for user-specific persistence and activity."""

        events = []

        # Parse user Run keys
        user_run_keys = [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
        ]

        for key_path in user_run_keys:
            try:
                key = reg.open(key_path)

                for value in key.values():
                    event = {
                        "event_type": "user_persistence",
                        "event_timestamp": self._filetime_to_datetime(key.timestamp()),
                        "source_file": "NTUSER.DAT",
                        "action": "SetValue",
                        "target": f"{key_path}\\{value.name()}",
                        "details": {
                            "value_name": value.name(),
                            "value_data": value.value()
                        },
                        "mitre_techniques": ["T1547.001"],
                        "mitre_tactics": ["Persistence"],
                        "suspicion_score": 0.6,  # User-level persistence
                        "is_persistence": True
                    }

                    events.append(event)

            except Registry.RegistryKeyNotFoundException:
                continue

        return events

    async def _parse_system_hive(self, reg: Registry.Registry) -> List[Dict[str, Any]]:
        """Parse SYSTEM hive for services and system configuration."""

        events = []

        # Parse installed services
        try:
            services_key = reg.open(r"ControlSet001\Services")

            for service in services_key.subkeys():
                try:
                    image_path_value = service.value("ImagePath")
                    image_path = image_path_value.value()

                    # Check for suspicious service paths
                    suspicion_score = self._calculate_service_suspicion(image_path)

                    if suspicion_score > 0.3:  # Only record suspicious services
                        event = {
                            "event_type": "service_installed",
                            "event_timestamp": self._filetime_to_datetime(service.timestamp()),
                            "source_file": "SYSTEM",
                            "action": "ServiceInstall",
                            "target": service.name(),
                            "details": {
                                "service_name": service.name(),
                                "image_path": image_path
                            },
                            "mitre_techniques": ["T1543.003"],
                            "mitre_tactics": ["Persistence", "Privilege Escalation"],
                            "suspicion_score": suspicion_score,
                            "is_persistence": True
                        }

                        events.append(event)

                except Registry.RegistryValueNotFoundException:
                    continue

        except Registry.RegistryKeyNotFoundException:
            pass

        return events

    async def _parse_sam_hive(self, reg: Registry.Registry) -> List[Dict[str, Any]]:
        """Parse SAM hive for user account changes."""
        # SAM hive is typically locked and encrypted
        # Parsing requires SYSTEM key for decryption
        # For now, skip or implement with decryption library
        return []

    def _map_key_to_mitre(self, key_path: str) -> List[str]:
        """Map registry key to MITRE ATT&CK techniques."""
        for pattern, technique in self.MITRE_MAPPING.items():
            if pattern in key_path:
                return [technique]
        return []

    def _calculate_persistence_score(self, value) -> float:
        """Calculate suspicion score for persistence entry."""
        value_data = str(value.value()).lower()

        # Suspicious indicators
        score = 0.3  # Base score for any persistence

        if "temp" in value_data or "tmp" in value_data:
            score += 0.2  # Temp directory execution
        if "powershell" in value_data:
            score += 0.2  # PowerShell execution
        if "-enc" in value_data or "-e " in value_data:
            score += 0.3  # Encoded command
        if "http" in value_data:
            score += 0.2  # Network reference
        if ".bat" in value_data or ".vbs" in value_data or ".js" in value_data:
            score += 0.15  # Script execution

        return min(score, 1.0)

    def _calculate_service_suspicion(self, image_path: str) -> float:
        """Calculate suspicion score for service."""
        image_path_lower = image_path.lower()

        score = 0.0

        # Legitimate Windows services usually in System32
        if "system32" in image_path_lower or "syswow64" in image_path_lower:
            score = 0.1  # Low suspicion
        else:
            score = 0.4  # Non-standard path

        # Additional indicators
        if "temp" in image_path_lower or "appdata" in image_path_lower:
            score += 0.3
        if "users\\" in image_path_lower:
            score += 0.2
        if ".exe.exe" in image_path_lower:
            score += 0.4  # Double extension

        return min(score, 1.0)

    @staticmethod
    def _filetime_to_datetime(filetime: int) -> datetime:
        """Convert Windows FILETIME to Python datetime."""
        # FILETIME is 100-nanosecond intervals since 1601-01-01
        EPOCH_AS_FILETIME = 116444736000000000
        HUNDREDS_OF_NANOSECONDS = 10000000

        try:
            timestamp = (filetime - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS
            return datetime.utcfromtimestamp(timestamp)
        except:
            return datetime.utcnow()
```

**File: `src/parsers/kape/evtx_parser.py`** (NEW)

```python
"""
Windows Event Log (EVTX) parser for KAPE artifacts.
Extracts security events, PowerShell logs, and system events.
"""

import logging
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime

# Using python-evtx library
try:
    import Evtx.Evtx as evtx
    import xml.etree.ElementTree as ET
except ImportError:
    logger.warning("python-evtx not installed, event log parsing disabled")
    evtx = None

logger = logging.getLogger(__name__)


class EVTXParser:
    """Parses Windows Event Log files."""

    # Event IDs of interest
    CRITICAL_EVENT_IDS = {
        4624: {"description": "Account logon", "mitre": "T1078"},
        4625: {"description": "Failed logon", "mitre": "T1110"},
        4672: {"description": "Special privileges assigned", "mitre": "T1078.001"},
        4688: {"description": "Process creation", "mitre": "T1059"},
        4698: {"description": "Scheduled task created", "mitre": "T1053.005"},
        4720: {"description": "User account created", "mitre": "T1136.001"},
        4732: {"description": "User added to privileged group", "mitre": "T1098"},
        7045: {"description": "Service installed", "mitre": "T1543.003"},
        4104: {"description": "PowerShell script block", "mitre": "T1059.001"}
    }

    async def parse_evtx(self, evtx_path: Path) -> List[Dict[str, Any]]:
        """Parse EVTX file and extract security events."""

        if not evtx:
            raise ImportError("python-evtx required for event log parsing")

        events = []

        try:
            with evtx.Evtx(str(evtx_path)) as log:
                for record in log.records():
                    try:
                        event_xml = record.xml()
                        event_data = self._parse_event_xml(event_xml)

                        if event_data:
                            events.append(event_data)

                    except Exception as e:
                        logger.debug(f"Failed to parse event record: {e}")
                        continue

            logger.info(f"Parsed {evtx_path.name}: {len(events)} events extracted")

        except Exception as e:
            logger.error(f"Failed to parse EVTX {evtx_path}: {e}")

        return events

    def _parse_event_xml(self, xml_string: str) -> Optional[Dict[str, Any]]:
        """Parse Windows Event XML."""

        try:
            root = ET.fromstring(xml_string)

            # Extract system info
            system = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}System")
            event_id = int(system.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventID").text)

            # Only process events of interest
            if event_id not in self.CRITICAL_EVENT_IDS:
                return None

            timestamp_str = system.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated").get("SystemTime")
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))

            # Extract event data
            event_data_elem = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventData")
            event_details = {}

            if event_data_elem:
                for data in event_data_elem.findall(".//{http://schemas.microsoft.com/win/2004/08/events/event}Data"):
                    name = data.get("Name")
                    value = data.text
                    if name:
                        event_details[name] = value

            # Build forensic event
            event_info = self.CRITICAL_EVENT_IDS[event_id]

            forensic_event = {
                "event_type": f"windows_event_{event_id}",
                "event_timestamp": timestamp,
                "source_file": "Security.evtx",  # TODO: Derive from path
                "action": event_info["description"],
                "target": event_details.get("TargetUserName", "N/A"),
                "actor": event_details.get("SubjectUserName", "SYSTEM"),
                "details": event_details,
                "mitre_techniques": [event_info["mitre"]],
                "mitre_tactics": self._get_tactics_for_technique(event_info["mitre"]),
                "suspicion_score": self._calculate_event_suspicion(event_id, event_details)
            }

            return forensic_event

        except Exception as e:
            logger.debug(f"XML parse error: {e}")
            return None

    def _calculate_event_suspicion(self, event_id: int, details: Dict[str, Any]) -> float:
        """Calculate suspicion score for event."""

        score = 0.2  # Base score

        # Failed logons are suspicious
        if event_id == 4625:
            score = 0.5

        # Privilege escalation
        if event_id == 4672:
            score = 0.6

        # PowerShell script blocks
        if event_id == 4104:
            script_text = details.get("ScriptBlockText", "").lower()
            if "downloadstring" in script_text or "invoke-expression" in script_text:
                score = 0.9  # Very suspicious
            elif "-enc" in script_text:
                score = 0.8  # Encoded command
            else:
                score = 0.4

        # Process creation with suspicious args
        if event_id == 4688:
            command_line = details.get("CommandLine", "").lower()
            if "powershell" in command_line and "-enc" in command_line:
                score = 0.8

        return min(score, 1.0)

    def _get_tactics_for_technique(self, technique_id: str) -> List[str]:
        """Map MITRE technique to tactics."""
        # Simplified mapping
        tactic_map = {
            "T1078": ["Initial Access", "Persistence"],
            "T1110": ["Credential Access"],
            "T1059": ["Execution"],
            "T1053": ["Persistence", "Execution"],
            "T1136": ["Persistence"],
            "T1098": ["Persistence"],
            "T1543": ["Persistence", "Privilege Escalation"]
        }

        return tactic_map.get(technique_id, ["Unknown"])
```

#### Phase 3: Timeline UI & API (Week 6-7)

**File: `src/api/forensics_endpoints.py`** (ENHANCE)

```python
"""
Forensic analysis endpoints for KAPE artifacts.
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from typing import List, Dict, Any
import asyncio

from src.db.database import get_db
from src.collectors.kape.kape_ingestor import KAPEIngestor
from src.parsers.kape.registry_parser import RegistryParser
from src.parsers.kape.evtx_parser import EVTXParser

router = APIRouter()


@router.post("/api/v1/forensics/kape/upload")
async def upload_kape_archive(
    file: UploadFile = File(...),
    tenant_id: str = Depends(get_tenant_id),
    case_id: str = None
):
    """Upload KAPE artifact archive for analysis."""

    # Save to S3/storage
    ingestor = KAPEIngestor(db=get_db(), storage_backend="s3")

    # Process upload
    artifact_id = await ingestor.process_upload(file, tenant_id, case_id)

    # Trigger async parsing
    asyncio.create_task(parse_kape_artifact(artifact_id))

    return {
        "artifact_id": artifact_id,
        "status": "uploaded",
        "message": "KAPE artifact uploaded, parsing in progress"
    }


@router.get("/api/v1/forensics/kape/{artifact_id}/timeline")
async def get_forensic_timeline(
    artifact_id: int,
    tenant_id: str = Depends(get_tenant_id),
    start_time: str = None,
    end_time: str = None,
    event_types: List[str] = None
):
    """Get forensic timeline for KAPE artifact."""

    db = get_db()

    query = """
        SELECT
            event_timestamp,
            event_type,
            actor,
            action,
            target,
            suspicion_score,
            mitre_techniques,
            details
        FROM forensic_events
        WHERE artifact_id = $1 AND tenant_id = $2
    """

    params = [artifact_id, tenant_id]

    if start_time:
        query += f" AND event_timestamp >= ${len(params) + 1}"
        params.append(start_time)

    if end_time:
        query += f" AND event_timestamp <= ${len(params) + 1}"
        params.append(end_time)

    if event_types:
        query += f" AND event_type = ANY(${len(params) + 1})"
        params.append(event_types)

    query += " ORDER BY event_timestamp ASC"

    async with db.get_connection() as conn:
        rows = await conn.fetch(query, *params)

    timeline = [dict(row) for row in rows]

    return {
        "artifact_id": artifact_id,
        "event_count": len(timeline),
        "timeline": timeline
    }


@router.get("/api/v1/forensics/kape/{artifact_id}/mitre")
async def get_mitre_coverage(artifact_id: int, tenant_id: str = Depends(get_tenant_id)):
    """Get MITRE ATT&CK coverage from forensic analysis."""

    db = get_db()

    async with db.get_connection() as conn:
        rows = await conn.fetch("""
            SELECT
                unnest(mitre_techniques) AS technique,
                COUNT(*) AS occurrence_count,
                AVG(suspicion_score) AS avg_suspicion
            FROM forensic_events
            WHERE artifact_id = $1 AND tenant_id = $2
            GROUP BY technique
            ORDER BY occurrence_count DESC
        """, artifact_id, tenant_id)

    techniques = [
        {
            "technique_id": row["technique"],
            "occurrences": row["occurrence_count"],
            "avg_suspicion": float(row["avg_suspicion"])
        }
        for row in rows
    ]

    return {
        "artifact_id": artifact_id,
        "technique_count": len(techniques),
        "techniques": techniques
    }
```

**Frontend: `frontend/static/forensics_kape.html`** (NEW)

```html
<!DOCTYPE html>
<html>
<head>
    <title>KAPE Forensic Analysis - JanuSec</title>
    <link rel="stylesheet" href="/static/css/main.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <h1>KAPE Forensic Analysis</h1>

        <!-- Upload Section -->
        <div class="upload-section">
            <h2>Upload KAPE Archive</h2>
            <form id="upload-form" enctype="multipart/form-data">
                <input type="file" id="kape-file" accept=".zip" required>
                <input type="text" id="case-id" placeholder="Case ID (optional)">
                <button type="submit">Upload</button>
            </form>
            <div id="upload-status"></div>
        </div>

        <!-- Timeline Visualization -->
        <div class="timeline-section">
            <h2>Forensic Timeline</h2>
            <canvas id="timeline-chart"></canvas>

            <div id="timeline-events">
                <!-- Populated dynamically -->
            </div>
        </div>

        <!-- MITRE Coverage -->
        <div class="mitre-section">
            <h2>MITRE ATT&CK Coverage</h2>
            <div id="mitre-heatmap"></div>
        </div>
    </div>

    <script src="/static/js/forensics.js"></script>
</body>
</html>
```

### Testing & Validation

- [ ] Test registry parser on Windows 10/11 hives
- [ ] Test EVTX parser on Security, System, PowerShell logs
- [ ] Validate MITRE technique mapping accuracy (>90%)
- [ ] Load test with 1GB+ KAPE archives
- [ ] UI timeline renders 10,000+ events smoothly
- [ ] Retention policy enforcement (auto-purge after TTL)

**Timeline:** 7 weeks
**Complexity:** HIGH

---

## P1-2: LOLBINS EXPANSION (macOS & Linux)

### Current State
- ✅ **Excellent for Windows:** TF-IDF, YAML registry, process lineage
- ❌ **Missing macOS:** No macOS LOLBins detection
- ❌ **Missing Linux:** Limited Linux coverage

### Business Value
- **Market expansion:** Support for macOS (developer workstations) and Linux (servers/cloud)
- **Competitive advantage:** Few platforms offer cross-platform LOLBins
- **Customer demand:** 40% of customers have mixed environments

### Implementation Plan

*(Detailed implementation with macOS and Linux LOLBin registries, parsers for bash history / osquery / auditd, and cross-platform correlation)*

**Key Components:**
- `data/lolbins_macos.yaml` - macOS LOLBins (curl, osascript, launchctl, etc.)
- `data/lolbins_linux.yaml` - Linux LOLBins (curl, wget, nc, python, perl, etc.)
- `src/core/detectors/lolbin_macos.py`
- `src/core/detectors/lolbin_linux.py`
- Cross-platform process lineage tracking

**Timeline:** 4 weeks
**Complexity:** MEDIUM

---

## P1-3: ADVANCED PERSONA CUSTOMIZATION

### Current State
- 🟡 **Template-based personas:** Executive, SOC, Compliance
- ❌ **No customization:** Fixed report structure
- ❌ **No Hunter/MSSP personas**

### Enhancement Plan

*(AI-powered persona profiles, dynamic report generation, customization API, Hunter and MSSP persona templates)*

**Timeline:** 5 weeks
**Complexity:** MEDIUM

---

## P1-4: SCHEDULED REPORT DISTRIBUTION

### Current State
- ✅ **On-demand reports:** API-based report generation works
- ❌ **No scheduling:** No cron/scheduled reports
- ❌ **No distribution:** No email/Slack/Teams integration

### Implementation Plan

*(Scheduler service, SMTP integration, webhook delivery, Slack/Teams bots, report templates)*

**Timeline:** 3 weeks
**Complexity:** LOW-MEDIUM

---

## TOTAL P1 TIMELINE: 8-12 Weeks

**Recommended Sequence:**
1. Weeks 1-7: KAPE Forensics (highest value, longest timeline)
2. Weeks 3-6: LOLBins Expansion (parallel with KAPE)
3. Weeks 7-11: Advanced Personas
4. Weeks 10-12: Scheduled Reports

**Total Effort:** 2-3 engineers, 12 weeks
