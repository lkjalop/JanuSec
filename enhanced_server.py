#!/usr/bin/env python3
"""
Enhanced JanuSec Server with Pluggable Database Support
Toyota Camry approach - reliable, maintainable, easily configurable
"""

import os
import sys
import asyncio
import time
import logging
from pathlib import Path

# Add src to Python path
current_dir = Path(__file__).parent
src_dir = current_dir / "src"
sys.path.insert(0, str(src_dir))
sys.path.insert(0, str(current_dir))

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("Loaded environment from .env file")
except ImportError:
    print("python-dotenv not installed, using system environment")

# Set up environment
os.environ.setdefault("PYTHONPATH", str(current_dir))
os.environ.setdefault("EVENT_QUEUE_MAX", "2000")
os.environ.setdefault("API_KEYS_JSON", '[{"key":"devkey123","scopes":["*"]}]')
os.environ.setdefault("ENABLE_CSV_UPLOAD", "true")

# Import database adapter
from database_adapter import init_database, database_health, shutdown_database, store_event, store_alert, get_recent_events, get_recent_alerts

# FastAPI imports
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from typing import Dict, Any

# Original server components
try:
    from api.server import app as original_app
    ORIGINAL_APP_AVAILABLE = True
except ImportError as e:
    print(f"Original app not available: {e}")
    ORIGINAL_APP_AVAILABLE = False
    app = FastAPI(title="JanuSec Enhanced API", version="0.9.1")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Enhanced event processing
async def process_event_with_database(event_data: Dict[str, Any]) -> Dict[str, Any]:
    """Process event and store in database"""
    start_time = time.time()

    # Simple classification logic (replace with actual pipeline)
    proc_name = event_data.get('proc_name', '').lower()
    parent_proc = event_data.get('parent_proc', '').lower()
    dest_port = event_data.get('dest_port', 0)
    command_line = event_data.get('command_line', '').lower()

    # Basic threat detection
    confidence = 0.05  # Default benign
    verdict = "benign"
    factors = []

    # Rule 1: Office macro spawning PowerShell
    if parent_proc in ['winword.exe', 'excel.exe', 'outlook.exe'] and proc_name == 'powershell.exe':
        confidence += 0.4
        factors.append("office_macro_powershell")

    # Rule 2: Suspicious ports
    if dest_port in [4444, 1337, 8080, 31337]:
        confidence += 0.3
        factors.append("suspicious_outbound_port")

    # Rule 3: Encoded commands
    if 'enc' in command_line or 'encoded' in command_line:
        confidence += 0.2
        factors.append("encoded_command")

    # Rule 4: Process injection indicators
    if proc_name in ['svchost.exe', 'rundll32.exe'] and 'winword' in parent_proc:
        confidence += 0.25
        factors.append("process_injection")

    # Determine verdict
    if confidence >= 0.7:
        verdict = "malicious"
    elif confidence >= 0.3:
        verdict = "suspicious"
    else:
        verdict = "benign"

    processing_time = (time.time() - start_time) * 1000

    result = {
        "event_id": event_data.get('id'),
        "verdict": verdict,
        "confidence": confidence,
        "factors": factors,
        "processing_time_ms": processing_time
    }

    # Store in database
    try:
        await store_event(
            event_data.get('id'),
            event_data,
            verdict,
            confidence
        )

        # Store alert if malicious or highly suspicious
        if confidence >= 0.6:
            await store_alert({
                "event_id": event_data.get('id'),
                "alert_type": "threat_detected",
                "severity": "high" if confidence >= 0.8 else "medium",
                "message": f"{verdict.title()} activity detected: {', '.join(factors)}",
                "confidence": confidence,
                "factors": factors,
                "verdict": verdict
            })

    except Exception as e:
        logger.error(f"Database storage error: {e}")
        # Continue processing even if database fails

    return result

# Enhanced API endpoints
if not ORIGINAL_APP_AVAILABLE:
    @app.get("/health")
    async def enhanced_health():
        """Enhanced health check with database status"""
        db_health = await database_health()

        return {
            "status": "healthy",
            "database": db_health,
            "uptime_seconds": time.time(),
            "version": "0.9.1-enhanced"
        }

    @app.post("/api/v1/endpoints/log_batch")
    async def enhanced_log_batch(payload: Dict[str, Any]):
        """Enhanced log batch processing with database storage"""
        events = payload.get('events', [])
        results = []

        for event in events[:100]:  # Limit batch size
            result = await process_event_with_database(event)
            results.append(result)

        return {
            "accepted": len(results),
            "failed": 0,
            "errors": [],
            "results": results if payload.get('include_results', False) else None,
            "database_enabled": True
        }

    @app.get("/api/v1/events/recent")
    async def get_events_recent(limit: int = 100):
        """Get recent events from database"""
        events = await get_recent_events(limit)
        return {"events": events, "count": len(events)}

    @app.get("/api/v1/alerts/recent")
    async def get_alerts_recent(limit: int = 50):
        """Get recent alerts from database"""
        alerts = await get_recent_alerts(limit)
        return {"alerts": alerts, "count": len(alerts)}

async def startup_sequence():
    """Enhanced startup with database initialization"""
    print(">> Starting JanuSec Enhanced Server")
    print("=" * 50)

    # Initialize database
    print(">> Initializing database...")
    try:
        await init_database()
        db_health = await database_health()
        print(f"OK Database ready: {db_health.get('database', 'unknown')}")

        if db_health.get('status') == 'healthy':
            print(f">> Events in DB: {db_health.get('event_count', 0)}")
            print(f">> Alerts in DB: {db_health.get('alert_count', 0)}")
        else:
            print(f"!! Database status: {db_health.get('status')}")

    except Exception as e:
        print(f"!! Database initialization failed: {e}")
        print(">> Continuing with limited functionality...")

    print("=" * 50)

async def shutdown_sequence():
    """Enhanced shutdown with database cleanup"""
    print("\n>> Shutting down JanuSec Enhanced Server")
    try:
        await shutdown_database()
        print("OK Database connections closed")
    except Exception as e:
        print(f"!! Database shutdown error: {e}")

def main():
    """Main entry point"""
    print("JanuSec Enhanced Server")
    print("Toyota Camry Database Architecture")
    print("Pluggable, reliable, maintainable")
    print()

    # Check database configuration
    db_type = os.getenv("DB_TYPE", "sqlite")
    print(f">> Database type: {db_type}")

    if db_type == "neon":
        if os.getenv("NEON_DATABASE_URL"):
            print(">> Neon PostgreSQL configured")
        else:
            print("!! NEON_DATABASE_URL not set, falling back to SQLite")

    print(f">> Server will start at: http://localhost:8080")
    print(f">> Enhanced dashboard: http://localhost:8080/health")
    print(f">> API docs: http://localhost:8080/docs")
    print()

    try:
        if ORIGINAL_APP_AVAILABLE:
            # Use original app with enhanced database
            uvicorn.run(
                "api.server:app",
                host="0.0.0.0",
                port=8080,
                reload=False,
                log_level="info",
                lifespan="on"
            )
        else:
            # Use simplified app
            uvicorn.run(
                app,
                host="0.0.0.0",
                port=8080,
                reload=False,
                log_level="info"
            )

    except KeyboardInterrupt:
        print("\n>> Server stopped by user")
    except Exception as e:
        print(f"!! Server error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Run startup sequence
    asyncio.run(startup_sequence())

    try:
        main()
    finally:
        # Run shutdown sequence
        asyncio.run(shutdown_sequence())