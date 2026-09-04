"""
Test FastAPI endpoints
"""

import requests
import json

def test_health():
    """Test health endpoint"""
    try:
        response = requests.get("http://localhost:8000/health")
        print("Health Check:")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
        return True
    except Exception as e:
        print(f"Health check failed: {e}")
        return False

def test_simulate():
    """Test simulate endpoint"""
    try:
        response = requests.post(
            "http://localhost:8000/simulate",
            json={"scenario": "PORT_SCAN", "num_packets": 50}
        )
        print("\nSimulate PORT_SCAN:")
        print(f"Status: {response.status_code}")
        result = response.json()
        print(f"Summary: {result['summary']}")
        print(f"Total flows: {result['total_flows']}")
        print(f"Threats detected: {result['threats_detected']}")
        return True
    except Exception as e:
        print(f"Simulation failed: {e}")
        return False

def test_alerts():
    """Test alerts endpoint"""
    try:
        response = requests.get("http://localhost:8000/alerts?limit=5")
        print("\nRecent Alerts:")
        print(f"Status: {response.status_code}")
        result = response.json()
        print(f"Alert count: {result['count']}")
        if result['alerts']:
            print(f"Sample alert: {result['alerts'][0]}")
        return True
    except Exception as e:
        print(f"Alerts check failed: {e}")
        return False

def test_statistics():
    """Test statistics endpoint"""
    try:
        response = requests.get("http://localhost:8000/statistics")
        print("\nStatistics:")
        print(f"Status: {response.status_code}")
        result = response.json()
        print(f"Total flows analyzed: {result['total_flows_analyzed']}")
        print(f"Threats detected: {result['threats_detected']}")
        print(f"Uptime: {result['uptime_seconds']:.2f} seconds")
        return True
    except Exception as e:
        print(f"Statistics check failed: {e}")
        return False

if __name__ == "__main__":
    print("Testing Network-Sentinel API endpoints...")
    print("=" * 50)
    
    test_health()
    test_simulate()
    test_alerts()
    test_statistics()
    
    print("\n" + "=" * 50)
    print("API testing complete")