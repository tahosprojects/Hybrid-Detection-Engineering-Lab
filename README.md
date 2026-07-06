# Hybrid Detection Engineering Lab

Cloud attack emulation and detection engineering in AWS. A Kali attacker detonates ATT&CK-mapped techniques against a live AWS account, CloudTrail captures the activity, logs flow into a self-hosted Splunk instance, and custom Sigma rules (converted to SPL) surface the malicious behavior. A Python script then enriches alerts with threat intelligence.

**Stack:** AWS (CloudTrail, S3, SQS) · Terraform · Splunk · Stratus Red Team · Sigma / sigma-cli · Python (boto3, requests) · Kali Linux

**Full write-up:** [Hybrid_Threat_Detection_Writeup.pdf](Hybrid_Threat_Detection_Writeup.pdf) covers the architecture, design decisions, and detection logic in depth.

---

## Overview

My earlier lab work focused on on-prem Windows telemetry (Active Directory, Sysmon, endpoint forensics). This project extends that into the cloud and connects the two. The goal was to treat AWS the way a real SOC does: provision infrastructure as code, generate genuine attacker activity against it, and detect that activity by engineering detections against raw CloudTrail logs, rather than relying on a managed alerting service.

## Architecture

<p align="center"><img src="files/architecture.png" width="620"></p>

CloudTrail records every API call and delivers logs to an S3 bucket. An SQS queue sits between S3 and Splunk: S3 notifies the queue when a new log object lands, and Splunk's AWS add-on pulls from the queue. This decouples ingestion, so if Splunk goes offline the messages wait in the queue instead of being lost, and a dead-letter queue catches anything that repeatedly fails to process.

## 1. Cloud Infrastructure (Terraform)

The AWS side is provisioned entirely with Terraform, so the environment is reproducible and tears down cleanly (which matters under a zero-dollar budget). Terraform builds an S3 bucket for log delivery, a multi-region CloudTrail trail, and an SQS queue with a dead-letter queue and redrive policy. One `terraform apply` builds the footprint; one `terraform destroy` removes it.

## 2. Log Ingestion Pipeline

The Splunk AWS add-on consumes CloudTrail logs through the SQS-based S3 input. Splunk runs headless on Ubuntu, reached from the host over port forwarding.

![CloudTrail logs in Splunk](files/cloudtrail-in-splunk.png)

**On GuardDuty:** I originally planned to use Amazon GuardDuty, but enabling it beyond the trial required a paid tier. Rather than treat that as a blocker, I dropped it deliberately. The point of the project is to demonstrate detection engineering, so running detections natively in Splunk against raw CloudTrail is the stronger showcase.

## 3. Adversary Emulation (Stratus Red Team)

Five ATT&CK-mapped techniques were detonated with Stratus Red Team, spanning the attack lifecycle from initial access to defense evasion:

| Technique | ATT&CK | What it simulates |
|---|---|---|
| Console login without MFA | T1078.004 | Sign-in with valid credentials but no MFA |
| EC2 enumeration from instance | T1580 / T1087 | A burst of discovery API calls mapping the environment |
| Create IAM admin user | T1136.003 | A new IAM user granted AdministratorAccess (persistence) |
| Batch-retrieve secrets | T1555 / T1552 | Bulk credential harvesting from Secrets Manager |
| Stop CloudTrail logging | T1562.008 | Disabling logging to blind detection |

Each was detonated, confirmed in CloudTrail, detected in Splunk, and cleaned up.

<details>
<summary><b>Detection evidence for all five techniques (click to expand)</b></summary>

<br>

**T1078.004:** console login with `MFAUsed = No`
![no-MFA login](files/t1078-console-login-no-mfa.png)

**T1580 / T1087:** a burst of distinct discovery calls from a single identity
![enumeration burst](files/t1580-ec2-enumeration.png)

**T1136.003:** CreateUser followed by an AdministratorAccess policy attachment
![admin user creation](files/t1136-iam-admin-user.png)

**T1555 / T1552:** repeated secret retrieval from one identity
![bulk secrets](files/t1555-batch-secrets.png)

**T1562.008:** StopLogging captured before logging was disabled
![stop logging](files/t1562-stop-logging.png)

</details>

## 4. Detection Engineering (Sigma to SPL)

Each detection was written as a Sigma rule (vendor-agnostic) and converted to Splunk SPL with sigma-cli. Writing in Sigma first keeps the logic portable to any SIEM and forces you to reason about the detection before binding it to one query language. I deliberately used five different detection patterns, because real detection engineering is not one-size-fits-all:

| Detection | Pattern | False-positive handling |
|---|---|---|
| Console login no-MFA | Single-event tripwire | Only benign cause is an account genuinely lacking MFA, itself a finding |
| Enumeration burst | Volume / variety aggregation | AWS service roles filtered out; known inventory tools allowlisted |
| Backdoor admin user | Correlated event sequence | Requires CreateUser + AdministratorAccess within 5 min; onboarding correlated with change tickets |
| Bulk secrets retrieval | Rate / threshold per identity | App and CI/CD service accounts allowlisted |
| Stop logging | Single critical event | Fires immediately; planned maintenance confirmed against change control |

Two problems separated a working detection from a naive one:

- **Service-role noise.** AWS's own service roles constantly issue List and Describe calls. Excluding assumed-role ARNs that begin with `AWSServiceRoleFor` removed the false positives on the enumeration rule.
- **Legitimate-identity misuse.** The admin-creation and secrets techniques ran under a real admin identity, not a separate attacker principal. A compromised admin looks like an admin, so these detections key on the behavior (a suspicious sequence or volume), not on a "bad" identity.

![Sigma to SPL conversion](files/sigma-to-spl.png)

## 5. Alert Enrichment (Python)

Detecting an event is only half the job. A Python script (boto3 and requests) takes IP addresses from CloudTrail activity and scores them against AbuseIPDB, then generates an email alert when a flagged IP appears, so a reviewer gets reputation context attached to the alert instead of looking it up by hand.

![enrichment script](files/enrichment-script.png)

![enrichment output](files/enrichment-output.png)

## Key Decisions & Lessons

- **UTC vs. local time.** Stratus logs in local time while CloudTrail records UTC. Correlating on the wrong clock makes real activity look like it is missing.
- **Detect behavior, not identity.** The most dangerous cloud attacks run under legitimate credentials, so the strongest detections trigger on patterns of activity rather than on who is acting.
- **Decouple ingestion with a queue.** An SQS queue and a dead-letter queue between S3 and Splunk mean log delivery survives an outage instead of silently dropping events.
- **A missing tool can be a design choice.** Dropping GuardDuty for cost became a chance to demonstrate the detection logic directly rather than hide it behind a managed service.

## What This Demonstrates

End-to-end cloud detection engineering: infrastructure as code, a resilient ingestion pipeline, ATT&CK emulation with production tooling, portable detections with real false-positive tuning, and automated enrichment. Built to reflect how a modern SOC actually operates: hybrid, log-driven, and detection-engineering-led.
