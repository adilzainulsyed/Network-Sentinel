"""
Simple test for FastAPI endpoints using direct imports
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from backend.app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

def test_health():
    """Test health endpoint"""
    response = client.get("/health")
    print("Health Check:")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    print()

def test_simulate():
    """Test simulate endpoint"""
    response = client.post(
        "/simulate",
        json={"scenario": "PORT_SCAN", "num_packets": 50}
    )
    print("Simulate PORT_SCAN:")
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Summary: {result['summary']}")
    print(f"Total flows: {result['total_flows']}")
    print(f"Threats detected: {result['threats_detected']}")
    print()

def test_alerts():
    """Test alerts endpoint"""
    response = client.get("/alerts?limit=5")
    print("Recent Alerts:")
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Alert count: {result['count']}")
    if result['alerts']:
        print(f"Sample alert: {result['alerts'][0]}")
    print()

def test_statistics():
    """Test statistics endpoint"""
    response = client.get("/statistics")
    print("Statistics:")
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Total flows analyzed: {result['total_flows_analyzed']}")
    print(f"Threats detected: {result['threats_detected']}")
    print(f"Uptime: {result['uptime_seconds']:.2f} seconds")
    print()

if __name__ == "__main__":
    print("Testing Network-Sentinel API endpoints...")
    print("=" * 50)
    
    test_health()
    test_simulate()
    test_alerts()
    test_statistics()
    
    print("=" * 50)
    print("API testing complete")