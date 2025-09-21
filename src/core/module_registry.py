"""
Module Registry - Manages module lifecycle, lazy loading, and health checks
Author: Security Engineering Team
Version: 1.0.0

Handles all module initialization, health monitoring, and lazy loading to keep main.py clean.
Implements circuit breaker pattern for resilient module management.
"""

import asyncio
import logging
import time
from typing import Dict, Any, Optional, Type
from dataclasses import dataclass
from contextlib import asynccontextmanager

from modules.baseline import BaselineModule
from modules.regex_engine import RegexPatternMatcher
from modules.intelligent_router import IntelligentRouter
from modules.threat_intel_cache import ThreatIntelCache
from modules.network_hunter import NetworkThreatHunter
from modules.endpoint_hunter import EndpointHunter
from modules.compliance_mapper import ComplianceMapper
from modules.playbook_executor import PlaybookExecutor
from modules.storage_manager import StorageManager
from modules.governance import GovernanceModule


@dataclass
class ModuleHealth:
    """Health status of a module"""
    name: str
    healthy: bool
    last_check: float
    error_count: int
    last_error: Optional[str] = None


@dataclass 
class CircuitBreakerState:
    """Circuit breaker state for a module"""
    name: str
    state: str  # 'closed', 'open', 'half_open'
    failure_count: int
    last_failure: float
    recovery_timeout: float


class ModuleRegistry:
    """
    Manages module lifecycle, lazy loading, and health checks.
    Implements circuit breaker pattern to prevent cascade failures.
    """

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Module storage
        self.core_modules = {}
        self.analysis_modules = {}
        self.support_modules = {}
        
        # Health tracking
        self.module_health = {}
        self.circuit_breakers = {}
        
        # Performance tracking
        self.module_load_times = {}
        self.module_usage_stats = {}
        
        # Module definitions - core modules always loaded
        self.core_module_definitions = {
            'baseline': BaselineModule,
            'regex_engine': RegexPatternMatcher,
            'router': IntelligentRouter,
            'intel_cache': ThreatIntelCache
        }
        
        # Analysis modules - lazy loaded
        self.analysis_module_definitions = {
            'network_hunter': NetworkThreatHunter,
            'endpoint_hunter': EndpointHunter,
            'compliance_mapper': ComplianceMapper
        }
        
        # Support modules - background services
        self.support_module_definitions = {
            'playbook_executor': PlaybookExecutor,
            'storage_manager': StorageManager,
            'governance': GovernanceModule
        }

    async def initialize(self):
        """Initialize all core modules and prepare lazy loading for others"""
        self.logger.info("Initializing module registry...")
        
        # Initialize core modules (always loaded)
        for name, module_class in self.core_module_definitions.items():
            await self._initialize_module(name, module_class, self.core_modules)
        
        # Initialize support modules
        for name, module_class in self.support_module_definitions.items():
            await self._initialize_module(name, module_class, self.support_modules)
        
        # Prepare circuit breakers for analysis modules
        for name in self.analysis_module_definitions.keys():
            self.circuit_breakers[name] = CircuitBreakerState(
                name=name,
                state='closed',
                failure_count=0,
                last_failure=0,
                recovery_timeout=30.0
            )
        
        self.logger.info(f"Module registry initialized. Core: {len(self.core_modules)}, "
                        f"Support: {len(self.support_modules)}, "
                        f"Analysis (lazy): {len(self.analysis_module_definitions)}")

    async def _initialize_module(self, name: str, module_class: Type, storage: Dict[str, Any]):
        """Initialize a single module with error handling"""
        start_time = time.time()
        
        try:
            self.logger.info(f"Initializing module: {name}")
            
            module_instance = module_class(self.config)
            await module_instance.initialize()
            
            storage[name] = module_instance
            
            # Track performance
            load_time = (time.time() - start_time) * 1000
            self.module_load_times[name] = load_time
            
            # Initialize health tracking
            self.module_health[name] = ModuleHealth(
                name=name,
                healthy=True,
                last_check=time.time(),
                error_count=0
            )
            
            self.logger.info(f"Module {name} initialized successfully in {load_time:.1f}ms")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize module {name}: {e}")
            
            # Store failed module with error state
            self.module_health[name] = ModuleHealth(
                name=name,
                healthy=False,
                last_check=time.time(),
                error_count=1,
                last_error=str(e)
            )
            raise

    async def get_module(self, module_name: str):
        """
        Get module with lazy loading and circuit breaker protection.
        Core and support modules are always available.
        Analysis modules are lazy loaded with circuit breaker protection.
        """
        # Check core modules first
        if module_name in self.core_modules:
            await self._record_module_usage(module_name)
            return self.core_modules[module_name]
        
        # Check support modules
        if module_name in self.support_modules:
            await self._record_module_usage(module_name)
            return self.support_modules[module_name]
        
        # Handle analysis modules with lazy loading
        if module_name in self.analysis_module_definitions:
            return await self._get_analysis_module(module_name)
        
        raise ValueError(f"Unknown module: {module_name}")

    async def _get_analysis_module(self, module_name: str):
        """Get analysis module with circuit breaker protection and lazy loading"""
        # Check if already loaded
        if module_name in self.analysis_modules:
            # Check circuit breaker
            if await self._check_circuit_breaker(module_name):
                await self._record_module_usage(module_name)
                return self.analysis_modules[module_name]
            else:
                raise RuntimeError(f"Module {module_name} circuit breaker is open")
        
        # Lazy load the module
        return await self._lazy_load_module(module_name)

    async def _lazy_load_module(self, module_name: str):
        """Lazy load an analysis module"""
        if module_name not in self.analysis_module_definitions:
            raise ValueError(f"Unknown analysis module: {module_name}")
        
        # Check circuit breaker before loading
        if not await self._check_circuit_breaker(module_name):
            raise RuntimeError(f"Cannot load module {module_name} - circuit breaker open")
        
        try:
            self.logger.info(f"Lazy loading module: {module_name}")
            
            module_class = self.analysis_module_definitions[module_name]
            await self._initialize_module(module_name, module_class, self.analysis_modules)
            
            await self._record_module_usage(module_name)
            return self.analysis_modules[module_name]
            
        except Exception as e:
            await self._record_module_failure(module_name, str(e))
            raise

    async def _check_circuit_breaker(self, module_name: str) -> bool:
        """Check if circuit breaker allows module access"""
        if module_name not in self.circuit_breakers:
            return True
        
        breaker = self.circuit_breakers[module_name]
        current_time = time.time()
        
        if breaker.state == 'closed':
            return True
        elif breaker.state == 'open':
            # Check if recovery timeout has passed
            if current_time - breaker.last_failure > breaker.recovery_timeout:
                breaker.state = 'half_open'
                self.logger.info(f"Circuit breaker for {module_name} transitioning to half-open")
                return True
            return False
        elif breaker.state == 'half_open':
            return True
        
        return False

    async def _record_module_failure(self, module_name: str, error: str):
        """Record module failure and update circuit breaker"""
        # Update health status
        if module_name in self.module_health:
            health = self.module_health[module_name]
            health.healthy = False
            health.error_count += 1
            health.last_error = error
            health.last_check = time.time()
        
        # Update circuit breaker
        if module_name in self.circuit_breakers:
            breaker = self.circuit_breakers[module_name]
            breaker.failure_count += 1
            breaker.last_failure = time.time()
            
            # Open circuit breaker if failure threshold reached
            if breaker.failure_count >= 5:
                breaker.state = 'open'
                self.logger.warning(f"Circuit breaker for {module_name} opened due to failures")

    async def _record_module_usage(self, module_name: str):
        """Record module usage statistics"""
        if module_name not in self.module_usage_stats:
            self.module_usage_stats[module_name] = {
                'usage_count': 0,
                'last_used': 0,
                'avg_response_time': 0
            }
        
        stats = self.module_usage_stats[module_name]
        stats['usage_count'] += 1
        stats['last_used'] = time.time()

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on all modules"""
        healthy_modules = []
        unhealthy_modules = []
        
        # Check all loaded modules
        all_modules = {**self.core_modules, **self.analysis_modules, **self.support_modules}
        
        for name, module in all_modules.items():
            try:
                # Call module health check if available
                if hasattr(module, 'health_check'):
                    is_healthy = await module.health_check()
                else:
                    is_healthy = True
                
                if is_healthy:
                    healthy_modules.append(name)
                    # Update health status
                    if name in self.module_health:
                        health = self.module_health[name]
                        health.healthy = True
                        health.last_check = time.time()
                        # Reset circuit breaker on successful health check
                        if name in self.circuit_breakers:
                            breaker = self.circuit_breakers[name]
                            if breaker.state == 'half_open':
                                breaker.state = 'closed'
                                breaker.failure_count = 0
                else:
                    unhealthy_modules.append(name)
                    await self._record_module_failure(name, "Health check failed")
                    
            except Exception as e:
                unhealthy_modules.append(name)
                await self._record_module_failure(name, f"Health check error: {e}")
        
        return {
            'healthy': len(unhealthy_modules) == 0,
            'healthy_modules': healthy_modules,
            'unhealthy_modules': unhealthy_modules,
            'total_modules': len(all_modules),
            'circuit_breaker_states': {name: cb.state for name, cb in self.circuit_breakers.items()}
        }

    async def get_module_stats(self) -> Dict[str, Any]:
        """Get comprehensive module statistics"""
        return {
            'core_modules': list(self.core_modules.keys()),
            'analysis_modules_loaded': list(self.analysis_modules.keys()),
            'analysis_modules_available': list(self.analysis_module_definitions.keys()),
            'support_modules': list(self.support_modules.keys()),
            'load_times': self.module_load_times,
            'usage_stats': self.module_usage_stats,
            'health_status': {name: health.healthy for name, health in self.module_health.items()},
            'circuit_breakers': {name: cb.state for name, cb in self.circuit_breakers.items()}
        }

    async def unload_module(self, module_name: str):
        """Unload a module (typically analysis modules to free memory)"""
        if module_name in self.core_modules:
            raise ValueError(f"Cannot unload core module: {module_name}")
        
        if module_name in self.support_modules:
            raise ValueError(f"Cannot unload support module: {module_name}")
        
        if module_name in self.analysis_modules:
            module = self.analysis_modules[module_name]
            
            # Call module shutdown if available
            if hasattr(module, 'shutdown'):
                await module.shutdown()
            
            del self.analysis_modules[module_name]
            self.logger.info(f"Unloaded module: {module_name}")

    async def reload_module(self, module_name: str):
        """Reload a module (for configuration updates)"""
        if module_name in self.analysis_modules:
            await self.unload_module(module_name)
        
        # Reset circuit breaker
        if module_name in self.circuit_breakers:
            breaker = self.circuit_breakers[module_name]
            breaker.state = 'closed'
            breaker.failure_count = 0
        
        # Module will be lazy loaded on next access
        self.logger.info(f"Module {module_name} prepared for reload")

    async def shutdown(self):
        """Shutdown all modules gracefully"""
        self.logger.info("Shutting down module registry...")
        
        # Shutdown in reverse order: analysis -> support -> core
        for module_dict in [self.analysis_modules, self.support_modules, self.core_modules]:
            for name, module in module_dict.items():
                try:
                    if hasattr(module, 'shutdown'):
                        await module.shutdown()
                    self.logger.info(f"Module {name} shutdown complete")
                except Exception as e:
                    self.logger.error(f"Error shutting down module {name}: {e}")
        
        self.logger.info("Module registry shutdown complete")