#!/usr/bin/env python3
"""
Development startup script for the Pragmatic Security Threat Sifting Platform
Author: Security Engineering Team
Version: 1.0.0
"""

import asyncio
import logging
import sys
import os
from pathlib import Path

# Add src directory to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root / "src"))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/platform.log', mode='a')
    ]
)

logger = logging.getLogger(__name__)


async def simulate_events():
    """Simulate some events for testing"""
    import time
    
    sample_events = [
        {
            'id': 'sim-001',
            'timestamp': time.time(),
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'process_name': 'chrome.exe',
            'event_type': 'network_connection'
        },
        {
            'id': 'sim-002',
            'timestamp': time.time(),
            'command_line': 'powershell.exe -e encoded_command_here',
            'process_name': 'powershell.exe',
            'event_type': 'process_start'
        },
        {
            'id': 'sim-003',
            'timestamp': time.time(),
            'src_ip': '185.220.101.1',  # Suspicious IP
            'dst_ip': '10.0.0.1',
            'event_type': 'network_connection'
        }
    ]
    
    return sample_events


async def main():
    """Main startup function"""
    logger.info("=== Pragmatic Security Threat Sifting Platform ===")
    logger.info("Starting development environment...")
    
    try:
        # Create logs directory
        os.makedirs('logs', exist_ok=True)
        
        # Import and initialize orchestrator
        from main import SecurityOrchestrator
        
        config_path = "config/main.yaml"
        orchestrator = SecurityOrchestrator(config_path)
        
        # Initialize the platform
        await orchestrator.initialize()
        
        # Simulate some events for testing
        logger.info("Processing sample events...")
        sample_events = await simulate_events()
        
        for event in sample_events:
            logger.info(f"Processing event: {event['id']}")
            try:
                result = await orchestrator.process_event(event)
                logger.info(f"Event {event['id']} -> {result.verdict} (confidence: {result.confidence:.2f})")
            except Exception as e:
                logger.error(f"Error processing event {event['id']}: {e}")
        
        # Keep running for a bit to show metrics
        logger.info("Platform running... (Ctrl+C to stop)")
        
        # In a real deployment, this would listen for actual events
        # For demo, just run for 10 seconds
        await asyncio.sleep(10)
        
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user")
    except Exception as e:
        logger.error(f"Startup error: {e}", exc_info=True)
    finally:
        # Graceful shutdown
        logger.info("Shutting down platform...")
        try:
            await orchestrator.shutdown()
        except:
            pass
        logger.info("Platform shutdown complete")


if __name__ == "__main__":
    asyncio.run(main())