import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from backend.app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

# Test DNS_TUNNEL simulation
response = client.post('/simulate', json={'scenario': 'DNS_TUNNEL', 'num_packets': 50})
print('DNS_TUNNEL test:')
print(f'Status: {response.status_code}')
result = response.json()
print(f'Summary: {result["summary"]}')
print(f'Threats: {result["threats_detected"]}')