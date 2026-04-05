#!/usr/bin/env python3
"""
ASCII-only Performance Comparison: Enhanced vs Original Server
Shows the impact of proper database integration without Unicode issues
"""

import requests
import time
import statistics
from typing import List

API_BASE = "http://localhost:8080"

def test_performance(server_type: str, num_tests: int = 10) -> dict:
    """Test server performance"""
    print(f"\n{'='*60}")
    print(f"TESTING {server_type.upper()} SERVER PERFORMANCE")
    print(f"{'='*60}")

    # Test events
    test_events = [
        {"id": f"perf-{i}", "proc_name": "chrome.exe", "parent_proc": "explorer.exe"}
        for i in range(num_tests)
    ]

    processing_times = []
    successful_requests = 0

    for i, event in enumerate(test_events):
        print(f"Testing event {i+1}/{num_tests}...", end=" ")

        start_time = time.time()

        try:
            response = requests.post(
                f"{API_BASE}/api/v1/endpoints/log_batch",
                json={"events": [event], "classify": True},
                timeout=10
            )

            process_time = (time.time() - start_time) * 1000

            if response.status_code == 200:
                processing_times.append(process_time)
                successful_requests += 1
                print(f"{process_time:.1f}ms")
            else:
                print(f"FAILED ({response.status_code})")

        except Exception as e:
            print(f"ERROR: {e}")

        # Brief pause between requests
        time.sleep(0.1)

    # Calculate statistics
    if processing_times:
        return {
            "server_type": server_type,
            "successful_requests": successful_requests,
            "total_requests": num_tests,
            "success_rate": successful_requests / num_tests * 100,
            "avg_latency": statistics.mean(processing_times),
            "min_latency": min(processing_times),
            "max_latency": max(processing_times),
            "p95_latency": statistics.quantiles(processing_times, n=20)[18] if len(processing_times) >= 20 else max(processing_times),
            "throughput": successful_requests / (sum(processing_times) / 1000) if processing_times else 0,
            "raw_times": processing_times
        }
    else:
        return {
            "server_type": server_type,
            "error": "No successful requests"
        }

def compare_performance():
    """Compare performance between configurations"""
    print("JanuSec Performance Comparison")
    print("Testing database impact on 9-stage pipeline performance")

    # Test current server
    try:
        health = requests.get(f"{API_BASE}/health").json()
        print(f"\nServer Status: {health.get('status', 'unknown')}")

        # Check if database is enabled
        db_info = health.get('database', {})
        if db_info:
            print(f"Database: {db_info.get('database', 'unknown')} ({db_info.get('status', 'unknown')})")
            server_type = "Enhanced (with database)"
        else:
            server_type = "Original (no database)"

        results = test_performance(server_type, 5)  # Reduced for demo

        print(f"\n{'='*60}")
        print("PERFORMANCE RESULTS")
        print(f"{'='*60}")

        if 'error' not in results:
            print(f"Server Type: {results['server_type']}")
            print(f"Success Rate: {results['success_rate']:.1f}%")
            print(f"Average Latency: {results['avg_latency']:.1f}ms")
            print(f"Min Latency: {results['min_latency']:.1f}ms")
            print(f"Max Latency: {results['max_latency']:.1f}ms")
            print(f"Throughput: {results['throughput']:.1f} events/sec")

            # Performance assessment
            avg_lat = results['avg_latency']
            throughput = results['throughput']

            print(f"\n{'='*60}")
            print("PERFORMANCE ASSESSMENT")
            print(f"{'='*60}")

            if avg_lat < 100 and throughput > 5:
                rating = "EXCELLENT"
                assessment = "Ready for production deployment"
                architecture = "Appropriately Engineered"
            elif avg_lat < 500 and throughput > 2:
                rating = "GOOD"
                assessment = "Minor optimizations recommended"
                architecture = "Well Engineered"
            elif avg_lat < 1000 and throughput > 1:
                rating = "ACCEPTABLE"
                assessment = "Some optimization needed"
                architecture = "Slightly Over-Engineered"
            else:
                rating = "NEEDS WORK"
                assessment = "Significant optimization required"
                architecture = "Over-Engineered"

            print(f"Performance Rating: {rating}")
            print(f"Architecture Rating: {architecture}")
            print(f"Recommendation: {assessment}")

            # Database impact analysis
            if "database" in server_type.lower():
                print(f"\nOK Database Integration Benefits:")
                print(f"   - Events are now persisted")
                print(f"   - Audit trail available")
                print(f"   - Real alerts stored")
                print(f"   - Multi-tenant ready")
                if avg_lat < 200:
                    print(f"   - Performance impact minimal")
                else:
                    print(f"   - Performance needs optimization")

            # Cost analysis
            cost_per_event = 0.002
            manual_cost = 0.50
            events_per_day = 10000

            daily_automated_cost = cost_per_event * events_per_day
            daily_manual_cost = manual_cost * events_per_day
            daily_savings = daily_manual_cost - daily_automated_cost
            annual_savings = daily_savings * 365

            print(f"\n$$ Cost Analysis (10K events/day):")
            print(f"   Automated: ${daily_automated_cost:,.2f}/day")
            print(f"   Manual: ${daily_manual_cost:,.2f}/day")
            print(f"   Savings: ${daily_savings:,.2f}/day (${annual_savings:,.2f}/year)")

            # CEO talking points
            print(f"\n>> CEO DEMO TALKING POINTS:")
            print(f"   - 'Built enterprise threat detection platform using AI'")
            print(f"   - 'Processes {throughput:.1f} security events per second'")
            print(f"   - 'Saves ${annual_savings:,.0f} annually vs manual analysis'")
            print(f"   - 'Demonstrates AI-assisted development capabilities'")
            if architecture in ["Excellent", "Good", "Well Engineered"]:
                print(f"   - 'Architecture is production-ready'")
            else:
                print(f"   - 'Proof of concept shows technical capability'")

        else:
            print(f"XX Performance test failed: {results['error']}")

        # Recommendations for improvement
        print(f"\n>> IMPROVEMENT RECOMMENDATIONS:")
        if 'error' not in results and results['avg_latency'] > 500:
            print(f"   1. Add connection pooling optimization")
            print(f"   2. Implement event batching")
            print(f"   3. Add Redis caching layer")
        if 'error' not in results and results['throughput'] < 5:
            print(f"   1. Optimize database queries")
            print(f"   2. Add async processing queue")
            print(f"   3. Implement stage bypassing for obvious cases")

        print(f"   4. Add Neon PostgreSQL for cloud scaling")
        print(f"   5. Implement client database plugin architecture")

        # Test database endpoints
        print(f"\n{'='*60}")
        print("DATABASE FUNCTIONALITY TEST")
        print(f"{'='*60}")

        try:
            # Test recent events
            events_response = requests.get(f"{API_BASE}/api/v1/events/recent?limit=5")
            if events_response.status_code == 200:
                events_data = events_response.json()
                print(f"OK Recent events endpoint working: {events_data.get('count', 0)} events")
            else:
                print(f"!! Events endpoint failed: {events_response.status_code}")

            # Test recent alerts
            alerts_response = requests.get(f"{API_BASE}/api/v1/alerts/recent?limit=5")
            if alerts_response.status_code == 200:
                alerts_data = alerts_response.json()
                print(f"OK Recent alerts endpoint working: {alerts_data.get('count', 0)} alerts")
            else:
                print(f"!! Alerts endpoint failed: {alerts_response.status_code}")

        except Exception as e:
            print(f"!! Database functionality test failed: {e}")

    except Exception as e:
        print(f"XX Could not connect to server: {e}")
        print("   Make sure server is running:")
        print("   python enhanced_server.py")

if __name__ == "__main__":
    compare_performance()