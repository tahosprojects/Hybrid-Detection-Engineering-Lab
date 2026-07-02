# Detection Engineering Lab

Extension of my [SOC Home Lab](https://github.com/tahosprojects/soc-home-lab) focused on building, testing, and mapping detections as code.

## Objectives

- Write Sigma rules for common attack techniques and convert them to Splunk SPL
- Build and validate SPL detections against simulated attacks (Atomic Red Team)
- Map all detections to MITRE ATT&CK and visualize coverage with ATT&CK Navigator
- Ingest AWS CloudTrail and GuardDuty logs into Splunk for cloud detection coverage

## Architecture

Builds on the existing 4-VM lab: Windows Server 2022 (AD DC), Windows 10 endpoint, Ubuntu Splunk SIEM, Kali Linux attacker. Adds an AWS log pipeline (CloudTrail → S3 → Splunk).

## Repository Structure
├── sigma-rules/          # Sigma detection rules (YAML)

├── spl-detections/       # Splunk SPL searches

├── attack-mapping/       # ATT&CK Navigator layers and coverage docs

├── aws-integration/      # CloudTrail/GuardDuty ingestion configs

└── docs/                 # Setup notes and validation results

## Status

🚧 In progress — started July 2026

| Phase | Status |
|---|---|
| Sigma rules + SPL conversions | In progress |
| Atomic Red Team validation | Planned |
| ATT&CK coverage mapping | Planned |
| AWS CloudTrail/GuardDuty ingestion | Planned |
