"""
Synthetic Testing Suite for Pragmatic Security Platform
Author: Security Engineering Team
Version: 1.0.0

Comprehensive testing framework using synthetic attack data and real-world threat patterns.
Validates platform performance, accuracy, and reliability before production deployment.
"""

import asyncio
import json
import time
import random
import hashlib
from typing import Dict, List, Any
from dataclasses import dataclass
from pathlib import Path
import numpy as np


@dataclass
class TestScenario:
    """Test scenario with expected outcome"""
    name: str
    description: str
    events: List[Dict[str, Any]]
    expected_verdict: str
    expected_confidence_range: tuple
    expected_factors: List[str]
    max_processing_time_ms: float
    category: str  # 'benign', 'malicious', 'apt', 'false_positive'


@dataclass
class TestResult:
    """Result of a test scenario"""
    scenario_name: str
    success: bool
    actual_verdict: str
    actual_confidence: float
    actual_factors: List[str]
    processing_time_ms: float
    error_message: str = None


class SyntheticTestSuite:
    """
    Comprehensive synthetic testing suite that validates platform capabilities
    using realistic threat scenarios and benign traffic patterns.
    """
    
    def __init__(self):
        self.test_scenarios = []
        self.results = []
        self.performance_metrics = {}
        
    def generate_test_scenarios(self) -> List[TestScenario]:
        """Generate comprehensive test scenarios covering all threat types"""
        
        scenarios = []
        
        # 1. BENIGN TRAFFIC SCENARIOS
        scenarios.extend([
            TestScenario(
                name="legitimate_web_browsing",
                description="Normal user browsing trusted websites",
                events=[{
                    'id': 'test_benign_001',
                    'timestamp': time.time(),
                    'src_ip': '192.168.1.100',
                    'dst_ip': '8.8.8.8',
                    'domain': 'google.com',
                    'process_name': 'chrome.exe',
                    'user': 'john.doe',
                    'event_type': 'dns_query'
                }],
                expected_verdict='benign',
                expected_confidence_range=(0.0, 0.1),
                expected_factors=['baseline:known_benign'],
                max_processing_time_ms=5.0,
                category='benign'
            ),
            
            TestScenario(
                name="internal_file_operations",
                description="Normal file operations by trusted processes",
                events=[{
                    'id': 'test_benign_002',
                    'timestamp': time.time(),
                    'process_name': 'explorer.exe',
                    'file_path': 'C:\\Users\\john\\Documents\\report.docx',
                    'operation': 'file_create',
                    'user': 'john.doe',
                    'event_type': 'file_operation'
                }],
                expected_verdict='benign',
                expected_confidence_range=(0.0, 0.1),
                expected_factors=['baseline:known_benign'],
                max_processing_time_ms=5.0,
                category='benign'
            )
        ])
        
        # 2. MALICIOUS SCENARIOS
        scenarios.extend([
            TestScenario(
                name="powershell_obfuscation",
                description="Obfuscated PowerShell command execution",
                events=[{
                    'id': 'test_malicious_001',
                    'timestamp': time.time(),
                    'process_name': 'powershell.exe',
                    'command_line': 'powershell.exe -e SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0',
                    'parent_process': 'winword.exe',
                    'user': 'victim.user',
                    'event_type': 'process_start'
                }],
                expected_verdict='malicious',
                expected_confidence_range=(0.7, 1.0),
                expected_factors=['attack:T1059.001', 'regex:ps_obfuscation'],
                max_processing_time_ms=50.0,
                category='malicious'
            ),
            
            TestScenario(
                name="known_c2_communication",
                description="Communication with known command and control server",
                events=[{
                    'id': 'test_malicious_002',
                    'timestamp': time.time(),
                    'src_ip': '192.168.1.150',
                    'dst_ip': '185.220.101.1',  # Known malicious IP
                    'dst_port': 443,
                    'protocol': 'TCP',
                    'bytes_sent': 1024,
                    'event_type': 'network_connection'
                }],
                expected_verdict='malicious',
                expected_confidence_range=(0.9, 1.0),
                expected_factors=['baseline:known_bad_ip'],
                max_processing_time_ms=5.0,
                category='malicious'
            ),
            
            TestScenario(
                name="process_injection",
                description="Process injection attempt using Windows APIs",
                events=[{
                    'id': 'test_malicious_003',
                    'timestamp': time.time(),
                    'process_name': 'malware.exe',
                    'api_calls': ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory'],
                    'target_process': 'explorer.exe',
                    'event_type': 'api_call'
                }],
                expected_verdict='malicious',
                expected_confidence_range=(0.6, 0.9),
                expected_factors=['attack:T1055', 'regex:proc_injection'],
                max_processing_time_ms=20.0,
                category='malicious'
            )
        ])
        
        # 3. APT CAMPAIGN SCENARIOS
        scenarios.extend([
            TestScenario(
                name="apt_multi_stage_attack",
                description="Multi-stage APT campaign with persistence and lateral movement",
                events=[
                    # Stage 1: Initial compromise
                    {
                        'id': 'apt_stage_1',
                        'timestamp': time.time(),
                        'process_name': 'winword.exe',
                        'file_path': 'C:\\Users\\victim\\Downloads\\invoice.docm',
                        'event_type': 'file_execution'
                    },
                    # Stage 2: Persistence
                    {
                        'id': 'apt_stage_2', 
                        'timestamp': time.time() + 300,  # 5 minutes later
                        'registry_key': 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                        'registry_value': 'UpdateChecker',
                        'event_type': 'registry_modification'
                    },
                    # Stage 3: Lateral movement
                    {
                        'id': 'apt_stage_3',
                        'timestamp': time.time() + 3600,  # 1 hour later
                        'process_name': 'psexec.exe',
                        'command_line': 'psexec \\\\target-host cmd.exe',
                        'event_type': 'lateral_movement'
                    }
                ],
                expected_verdict='malicious',
                expected_confidence_range=(0.8, 1.0),
                expected_factors=['attack:T1566.001', 'attack:T1547.001', 'attack:T1021.002'],
                max_processing_time_ms=100.0,
                category='apt'
            )
        ])
        
        # 4. FALSE POSITIVE TEST SCENARIOS
        scenarios.extend([
            TestScenario(
                name="admin_powershell_legitimate",
                description="Legitimate PowerShell usage by system administrator",
                events=[{
                    'id': 'test_fp_001',
                    'timestamp': time.time(),
                    'process_name': 'powershell.exe',
                    'command_line': 'Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4624}',
                    'user': 'admin.user',
                    'user_groups': ['Domain Admins', 'IT Security'],
                    'time_of_day': 'business_hours',
                    'event_type': 'process_start'
                }],
                expected_verdict='benign',
                expected_confidence_range=(0.0, 0.3),
                expected_factors=['baseline:admin_context'],
                max_processing_time_ms=20.0,
                category='false_positive'
            )
        ])
        
        # 5. PERFORMANCE STRESS TESTS
        scenarios.extend([
            TestScenario(
                name="high_volume_benign_traffic",
                description="High volume of benign traffic to test throughput",
                events=[{
                    'id': f'stress_test_{i}',
                    'timestamp': time.time() + (i * 0.001),  # 1ms apart
                    'src_ip': f'192.168.1.{i % 255}',
                    'dst_ip': '8.8.8.8',
                    'event_type': 'dns_query'
                } for i in range(1000)],
                expected_verdict='benign',
                expected_confidence_range=(0.0, 0.1),
                expected_factors=['baseline:known_benign'],
                max_processing_time_ms=1000.0,  # Total for all 1000 events
                category='performance'
            )
        ])
        
        self.test_scenarios = scenarios
        return scenarios
    
    async def run_comprehensive_test(self) -> Dict[str, Any]:
        """Run comprehensive test suite and generate detailed report"""
        
        print("🧪 Starting Comprehensive Platform Testing...")
        print("=" * 60)
        
        # Generate test scenarios
        scenarios = self.generate_test_scenarios()
        print(f"Generated {len(scenarios)} test scenarios")
        
        # Initialize platform (mock for testing)
        from main import SecurityOrchestrator
        orchestrator = SecurityOrchestrator()
        await orchestrator.initialize()
        
        # Run tests by category
        results_by_category = {}
        
        for category in ['benign', 'malicious', 'apt', 'false_positive', 'performance']:
            category_scenarios = [s for s in scenarios if s.category == category]
            print(f"\n📊 Testing {category.upper()} scenarios ({len(category_scenarios)} tests)...")
            
            category_results = []
            for scenario in category_scenarios:
                result = await self._run_single_test(orchestrator, scenario)
                category_results.append(result)
                
                # Print immediate feedback
                status = "✅ PASS" if result.success else "❌ FAIL"
                print(f"  {status} {scenario.name}: {result.actual_verdict} "
                      f"({result.actual_confidence:.2f}, {result.processing_time_ms:.1f}ms)")
                
                if not result.success:
                    print(f"    Expected: {scenario.expected_verdict}, Got: {result.actual_verdict}")
                    if result.error_message:
                        print(f"    Error: {result.error_message}")
            
            results_by_category[category] = category_results
        
        # Generate comprehensive report
        report = await self._generate_test_report(results_by_category)
        
        # Save detailed results
        await self._save_test_results(report)
        
        print("\n" + "=" * 60)
        print("🎯 TEST SUMMARY:")
        print(f"✅ Total Tests: {report['total_tests']}")
        print(f"✅ Passed: {report['passed_tests']} ({report['pass_rate']:.1f}%)")
        print(f"❌ Failed: {report['failed_tests']}")
        print(f"⚡ Avg Processing Time: {report['avg_processing_time']:.1f}ms")
        print(f"🎯 Accuracy: {report['accuracy']:.1f}%")
        
        return report
    
    async def _run_single_test(self, orchestrator, scenario: TestScenario) -> TestResult:
        """Run a single test scenario"""
        
        try:
            start_time = time.perf_counter()
            
            # For multi-event scenarios, process each event
            if len(scenario.events) == 1:
                # Single event
                result = await orchestrator.process_event(scenario.events[0])
                processing_time = (time.perf_counter() - start_time) * 1000
                
                # Validate result
                success = self._validate_result(scenario, result, processing_time)
                
                return TestResult(
                    scenario_name=scenario.name,
                    success=success,
                    actual_verdict=result.verdict,
                    actual_confidence=result.confidence,
                    actual_factors=result.factors,
                    processing_time_ms=processing_time
                )
            else:
                # Multi-event scenario (APT)
                results = []
                for event in scenario.events:
                    event_result = await orchestrator.process_event(event)
                    results.append(event_result)
                
                processing_time = (time.perf_counter() - start_time) * 1000
                
                # Use final result for validation
                final_result = results[-1]
                success = self._validate_result(scenario, final_result, processing_time)
                
                return TestResult(
                    scenario_name=scenario.name,
                    success=success,
                    actual_verdict=final_result.verdict,
                    actual_confidence=final_result.confidence,
                    actual_factors=final_result.factors,
                    processing_time_ms=processing_time
                )
                
        except Exception as e:
            return TestResult(
                scenario_name=scenario.name,
                success=False,
                actual_verdict='error',
                actual_confidence=0.0,
                actual_factors=[],
                processing_time_ms=0.0,
                error_message=str(e)
            )
    
    def _validate_result(self, scenario: TestScenario, result, processing_time: float) -> bool:
        """Validate test result against expected outcome"""
        
        # Check verdict
        if result.verdict != scenario.expected_verdict:
            return False
        
        # Check confidence range
        min_conf, max_conf = scenario.expected_confidence_range
        if not (min_conf <= result.confidence <= max_conf):
            return False
        
        # Check processing time
        if processing_time > scenario.max_processing_time_ms:
            return False
        
        # Check for expected factors (at least one should match)
        if scenario.expected_factors:
            factor_match = any(expected in result.factors for expected in scenario.expected_factors)
            if not factor_match:
                return False
        
        return True
    
    async def _generate_test_report(self, results_by_category: Dict[str, List[TestResult]]) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        
        all_results = []
        for results in results_by_category.values():
            all_results.extend(results)
        
        total_tests = len(all_results)
        passed_tests = len([r for r in all_results if r.success])
        failed_tests = total_tests - passed_tests
        
        processing_times = [r.processing_time_ms for r in all_results if r.processing_time_ms > 0]
        avg_processing_time = np.mean(processing_times) if processing_times else 0
        p95_processing_time = np.percentile(processing_times, 95) if processing_times else 0
        
        # Category-specific metrics
        category_metrics = {}
        for category, results in results_by_category.items():
            passed = len([r for r in results if r.success])
            total = len(results)
            category_metrics[category] = {
                'total': total,
                'passed': passed,
                'pass_rate': (passed / total * 100) if total > 0 else 0,
                'avg_time': np.mean([r.processing_time_ms for r in results]) if results else 0
            }
        
        return {
            'timestamp': time.time(),
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'failed_tests': failed_tests,
            'pass_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0,
            'accuracy': (passed_tests / total_tests * 100) if total_tests > 0 else 0,
            'avg_processing_time': avg_processing_time,
            'p95_processing_time': p95_processing_time,
            'category_metrics': category_metrics,
            'detailed_results': {
                category: [
                    {
                        'name': r.scenario_name,
                        'success': r.success,
                        'verdict': r.actual_verdict,
                        'confidence': r.actual_confidence,
                        'time_ms': r.processing_time_ms,
                        'error': r.error_message
                    } for r in results
                ] for category, results in results_by_category.items()
            }
        }
    
    async def _save_test_results(self, report: Dict[str, Any]):
        """Save test results to file"""
        
        # Create results directory
        Path('test_results').mkdir(exist_ok=True)
        
        # Save detailed JSON report
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        json_file = f"test_results/comprehensive_test_{timestamp}.json"
        
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Save summary report
        summary_file = f"test_results/test_summary_{timestamp}.txt"
        
        with open(summary_file, 'w') as f:
            f.write("PRAGMATIC SECURITY PLATFORM - TEST RESULTS\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Test Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Tests: {report['total_tests']}\n")
            f.write(f"Passed: {report['passed_tests']}\n")
            f.write(f"Failed: {report['failed_tests']}\n")
            f.write(f"Pass Rate: {report['pass_rate']:.1f}%\n")
            f.write(f"Average Processing Time: {report['avg_processing_time']:.1f}ms\n")
            f.write(f"95th Percentile Time: {report['p95_processing_time']:.1f}ms\n\n")
            
            f.write("CATEGORY BREAKDOWN:\n")
            f.write("-" * 30 + "\n")
            for category, metrics in report['category_metrics'].items():
                f.write(f"{category.upper()}:\n")
                f.write(f"  Tests: {metrics['total']}\n")
                f.write(f"  Passed: {metrics['passed']}\n")
                f.write(f"  Pass Rate: {metrics['pass_rate']:.1f}%\n")
                f.write(f"  Avg Time: {metrics['avg_time']:.1f}ms\n\n")
        
        print(f"\n📄 Detailed results saved to: {json_file}")
        print(f"📄 Summary report saved to: {summary_file}")


# Load testing framework
class LoadTestFramework:
    """Load testing to validate performance under stress"""
    
    def __init__(self):
        self.events_per_second = 1000
        self.test_duration_seconds = 60
        self.concurrent_connections = 100
    
    async def run_load_test(self) -> Dict[str, Any]:
        """Run load test to validate performance claims"""
        
        print("🚀 Starting Load Test...")
        print(f"Target: {self.events_per_second} events/second for {self.test_duration_seconds} seconds")
        
        # Initialize orchestrator
        from main import SecurityOrchestrator
        orchestrator = SecurityOrchestrator()
        await orchestrator.initialize()
        
        # Generate load
        start_time = time.time()
        events_processed = 0
        processing_times = []
        errors = 0
        
        tasks = []
        for i in range(self.events_per_second * self.test_duration_seconds):
            # Create realistic event
            event = {
                'id': f'load_test_{i}',
                'timestamp': time.time(),
                'src_ip': f'192.168.1.{random.randint(1, 254)}',
                'dst_ip': '8.8.8.8',
                'event_type': 'dns_query'
            }
            
            # Add to task queue
            task = asyncio.create_task(self._process_with_timing(orchestrator, event))
            tasks.append(task)
            
            # Control rate
            if i % self.events_per_second == 0:
                await asyncio.sleep(1)
        
        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                errors += 1
            else:
                events_processed += 1
                processing_times.append(result)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Calculate metrics
        avg_processing_time = np.mean(processing_times) if processing_times else 0
        p95_processing_time = np.percentile(processing_times, 95) if processing_times else 0
        throughput = events_processed / total_time
        error_rate = errors / len(tasks) * 100
        
        return {
            'events_processed': events_processed,
            'total_events': len(tasks),
            'total_time_seconds': total_time,
            'throughput_per_second': throughput,
            'avg_processing_time_ms': avg_processing_time,
            'p95_processing_time_ms': p95_processing_time,
            'error_count': errors,
            'error_rate_percent': error_rate,
            'target_throughput': self.events_per_second,
            'performance_target_met': throughput >= (self.events_per_second * 0.8)  # 80% of target
        }
    
    async def _process_with_timing(self, orchestrator, event):
        """Process event and return timing"""
        start = time.perf_counter()
        try:
            await orchestrator.process_event(event)
            return (time.perf_counter() - start) * 1000  # Return time in ms
        except Exception:
            raise


async def main():
    """Run comprehensive testing suite"""
    
    # Run synthetic tests
    synthetic_suite = SyntheticTestSuite()
    synthetic_report = await synthetic_suite.run_comprehensive_test()
    
    # Run load tests
    load_tester = LoadTestFramework()
    load_report = await load_tester.run_load_test()
    
    print("\n" + "=" * 80)
    print("🏆 FINAL TEST VERDICT:")
    print("=" * 80)
    
    # Overall assessment
    synthetic_pass = synthetic_report['pass_rate'] >= 85  # 85% pass rate minimum
    load_pass = load_report['performance_target_met']
    
    if synthetic_pass and load_pass:
        print("✅ PLATFORM READY FOR PRODUCTION")
        print("✅ All performance targets met")
        print("✅ Accuracy requirements satisfied")
    else:
        print("❌ PLATFORM NEEDS IMPROVEMENT")
        if not synthetic_pass:
            print(f"❌ Synthetic test pass rate: {synthetic_report['pass_rate']:.1f}% (need ≥85%)")
        if not load_pass:
            print(f"❌ Load test failed: {load_report['throughput_per_second']:.0f}/sec (need ≥800/sec)")
    
    return {
        'synthetic_results': synthetic_report,
        'load_test_results': load_report,
        'production_ready': synthetic_pass and load_pass
    }


if __name__ == "__main__":
    # Run the comprehensive test suite
    results = asyncio.run(main())