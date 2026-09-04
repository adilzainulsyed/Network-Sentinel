# Evidence Engine Implementation Summary

## Overview
Implemented a comprehensive Evidence Engine that converts network threat detection results into human-readable evidence based on actual measured feature values.

## Files Changed

### 1. **backend/app/evidence/engine.py** (NEW)
- Created `EvidenceEngine` class with threat-specific evidence rules
- Implemented `AlertGenerator` class for producing human-readable alerts
- Evidence rules for all threat types: SYN_FLOOD, PORT_SCAN, C2_BEACON, DNS_TUNNEL, BENIGN

### 2. **backend/app/evidence/__init__.py** (NEW)
- Package initialization for evidence module

### 3. **detect.py** (MODIFIED)
- Integrated EvidenceEngine and AlertGenerator
- Added evidence-based alert generation
- Enhanced output to show sample alerts with evidence
- Now generates both JSON (with evidence) and CSV alert files

## Evidence Rules by Threat Type

### SYN_FLOOD Evidence
- **High packet rate**: packets_per_second > 1000
- **Abnormal byte rate**: bytes_per_second > 1MB/s  
- **Short flow duration**: flow_duration < 1ms
- **Small packet size**: 40-60 bytes (typical SYN packets)
- **Single destination port**: Focused attack pattern

### PORT_SCAN Evidence
- **High destination port diversity**: dst_port_count > 100
- **Single target host**: dst_host_count == 1
- **High connection rate**: packets_per_second > 500
- **Small packet size**: mean_packet_size < 80 bytes
- **Short flow duration**: flow_duration < 10ms

### C2_BEACON Evidence
- **High repeated connections**: dst_connection_count > 100
- **Single destination host**: dst_host_count == 1
- **Timing regularity**: cv_interarrival < 0.3 (periodic intervals)
- **Consistent inter-arrival time**: mean_interarrival analysis
- **Single destination port**: dst_port_count == 1
- **High connections per host**: Repeated C2 check-ins

### DNS_TUNNEL Evidence
- **Long DNS queries**: dns_query_length > 30 characters
- **Maximum query length**: dns_max_query_length > 40 characters
- **High query entropy**: dns_entropy > 3.5 (encoded data)
- **Unique subdomains**: dns_unique_subdomain_count > 0
- **High subdomain entropy**: dns_subdomain_entropy > 3.0
- **Query frequency**: dns_query_count > 1
- **UDP protocol**: Consistent with DNS traffic

### BENIGN Evidence
- **Normal packet rates**: packets_per_second < 100
- **Normal query lengths**: dns_query_length < 20 characters
- **Low entropy**: dns_entropy < 2.0
- **Moderate port diversity**: dst_port_count between 1-10
- **Normal timing variation**: cv_interarrival > 0.5

## Alert Structure

Each alert contains:
- `alert_id`: Unique identifier (UUID)
- `timestamp`: ISO format timestamp
- `threat_class`: Detected threat type
- `confidence`: Detection confidence score
- `severity`: Calculated severity (critical/high/medium/low/info)
- `evidence`: List of human-readable evidence statements
- `source_ip`, `destination_ip`: Network endpoints
- `source_port`, `destination_port`: Port numbers
- `protocol`: IP protocol number
- `summary`: Human-readable summary

## Test Results

### SYN_FLOOD Detection
**Command**: `python detect.py data/pcaps/syn_flood.pcap`

**Sample Alert**:
```
Alert 1:
  Threat: SYN_FLOOD
  Severity: critical
  Source: 155.240.149.136:63538 -> 10.0.0.5:80
  Summary: SYN_FLOOD detected: High packet rate: 1000000 packets/second (normal < 100) (+4 more indicators)
  Evidence:
    - High packet rate: 1000000 packets/second (normal < 100)
    - High byte rate: 40.0 MB/s (suspicious for SYN flood)
    - Very short flow duration: 0.001ms (characteristic of flood attacks)
    - Small packet size: 40 bytes (typical SYN packet size)
    - Single destination port: 1 (focused attack on specific service)
```

### PORT_SCAN Detection
**Command**: `python detect.py data/pcaps/port_scan.pcap`

**Sample Alert**:
```
Alert 1:
  Threat: PORT_SCAN
  Severity: critical
  Source: 192.168.1.50:56915 -> 10.0.0.5:625
  Summary: PORT_SCAN detected: High destination port diversity: 1986 unique ports (normal < 10) (+4 more indicators)
  Evidence:
    - High destination port diversity: 1986 unique ports (normal < 10)
    - Single target host: 1 (focused scanning activity)
    - High connection rate: 1000000 connections/second (rapid scanning)
    - Small packet size: 40 bytes (characteristic of SYN scanning)
    - Short flow duration: 0.0ms (typical of scan probes)
```

### C2_BEACON Detection
**Command**: `python detect.py data/pcaps/c2_beacon.pcap`

**Sample Alert**:
```
Alert 1:
  Threat: C2_BEACON
  Severity: critical
  Source: 192.168.1.50:17559 -> 185.20.10.5:80
  Summary: C2_BEACON detected: High repeated connections: 1964 to same destination (beaconing pattern) (+4 more indicators)
  Evidence:
    - High repeated connections: 1964 to same destination (beaconing pattern)
    - Single destination host: 1 (consistent C2 server contact)
    - High timing regularity: CV=0.00 (periodic beaconing intervals)
    - Single destination port: 1 (consistent C2 communication channel)
    - High connections per host: 1964 (repeated C2 check-ins)
```

### DNS_TUNNEL Detection
**Command**: `python detect.py data/pcaps/dns_tunnel.pcap`

**Sample Alert**:
```
Alert 1:
  Threat: DNS_TUNNEL
  Severity: critical
  Source: 192.168.1.50:5598 -> 8.8.8.8:53
  Summary: DNS_TUNNEL detected: Long DNS queries: 42 characters avg (normal < 20) (+5 more indicators)
  Evidence:
    - Long DNS queries: 42 characters avg (normal < 20)
    - Maximum query length: 42 characters (suspicious for tunneling)
    - High query entropy: 4.29 (indicates encoded data)
    - Unique subdomains: 1 (random subdomain generation)
    - High subdomain entropy: 3.82 (encoded tunneling data)
    - UDP protocol used (consistent with DNS traffic)
```

### DNS_TUNNEL Test (Parameter Variations)
**Command**: `python detect.py data/pcaps/dns_tunnel_test.pcap`

**Sample Alert**:
```
Alert 1:
  Threat: DNS_TUNNEL
  Severity: critical
  Source: 192.168.1.88:43960 -> 1.1.1.1:53
  Summary: DNS_TUNNEL detected: Long DNS queries: 47 characters avg (normal < 20) (+5 more indicators)
  Evidence:
    - Long DNS queries: 47 characters avg (normal < 20)
    - Maximum query length: 47 characters (suspicious for tunneling)
    - High query entropy: 4.55 (indicates encoded data)
    - Unique subdomains: 1 (random subdomain generation)
    - High subdomain entropy: 4.16 (encoded tunneling data)
    - UDP protocol used (consistent with DNS traffic)
```

### BENIGN Traffic
**Command**: `python detect.py data/pcaps/benign.pcap`

**Result**: No alerts generated (as expected for benign traffic)

## Key Features

1. **Feature-Based Evidence**: All evidence statements are based on actual measured feature values, not hardcoded generic statements
2. **Threshold-Based Rules**: Evidence is generated using meaningful thresholds that distinguish malicious from benign behavior
3. **Contextual Information**: Each evidence statement includes context with normal ranges for comparison
4. **Severity Calculation**: Automatic severity assignment based on threat class and confidence
5. **Human-Readable Output**: Clear, actionable evidence for security analysts
6. **JSON + CSV Output**: Both structured JSON (with full evidence) and simple CSV formats for compatibility

## Command to Verify Evidence Engine

To test the evidence engine with any PCAP file:

```bash
python detect.py data/pcaps/<threat_type>.pcap
```

This will:
1. Detect threats using the existing ML model
2. Generate evidence-based alerts with human-readable explanations
3. Display sample alerts with evidence
4. Save detailed alerts to `data/pcaps/<threat_type>_alerts.json`
5. Save basic alerts to `data/pcaps/<threat_type>_alerts.csv`

## Implementation Notes

- No changes to the ML model or detection architecture
- Evidence engine operates as a post-processing layer
- Reuses existing feature extraction pipeline
- Maintains backward compatibility with existing CSV output
- Evidence rules are modular and easily extensible for new threat types
- All evidence is based on actual feature measurements from the data