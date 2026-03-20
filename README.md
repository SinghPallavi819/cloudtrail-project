# AWS CloudTrail Threat Detection & Alerting System

## Overview
This project is a Python-based threat detection system that analyzes AWS CloudTrail logs to identify high-risk security events and generate alerts.

The system parses CloudTrail JSON logs, detects suspicious or sensitive API activity, exports results to a structured report, and sends real-time alerts to Slack.

This project simulates a real-world Security Operations Center (SOC) workflow for cloud environments.

---

## Features
- Parses AWS CloudTrail logs (JSON format)
- Detects high-risk IAM and S3-related actions
- Filters out read-only (non-impactful) events
- Extracts:
  - Event name
  - User identity
  - Source IP
  - Timestamp
- Exports findings to CSV report
- Sends real-time alerts to Slack via webhook

---

## High-Risk Events Monitored
Examples include:
- IAM privilege changes:
  - CreateUser
  - CreateAccessKey
  - AttachUserPolicy
- Account access modifications:
  - CreateLoginProfile
  - UpdateLoginProfile
- Logging tampering:
  - StopLogging
  - DeleteTrail
- S3 security changes:
  - PutBucketPolicy
  - DeleteBucketPolicy
  - PutBucketAcl
- KMS key risks:
  - DisableKey
  - ScheduleKeyDeletion

---

## Technologies Used
- Python
- AWS CloudTrail logs
- JSON parsing
- CSV reporting
- Slack Webhooks
- Environment variables (.env)

---

## How It Works
1. Loads AWS CloudTrail logs from a JSON file
2. Iterates through all recorded events
3. Identifies high-risk API calls based on predefined list
4. Filters out read-only events
5. Extracts relevant security details:
   - User type and ARN
   - Source IP address
   - Event timestamp
6. Stores flagged events in a CSV report
7. Sends alert notifications to Slack

---

## Example Detection Logic

```python
if event_name in HIGH_RISK_EVENTS and read_only is False:
