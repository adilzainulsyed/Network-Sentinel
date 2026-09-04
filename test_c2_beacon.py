import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from backend.app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

# Test C2_BEACON simulation
response = client.post('/simulate', json={'scenario': 'C2_BEACON', 'num_packets': 50})
print('C2_BEACON test:')
print(f'Status: {response.status_code}')
result = response.json()
print(f'Summary: {result["summary"]}')
print(f'Threats: {result["threats_detected"]}')