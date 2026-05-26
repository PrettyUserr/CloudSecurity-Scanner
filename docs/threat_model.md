# Threat Model — Cloud Misconfiguration Scanner

Author: Ibukun Olaniyan
Date: 26th May, 2025
Version: 1.0  
Project: CloudSecurity-Scanner  



## 1. Overview

This document describes the threat model for the Cloud Misconfiguration Scanner — 
a Python CLI tool that audits AWS accounts for security misconfigurations across 
S3, IAM, and EC2 services.

The purpose of threat modelling is to identify what could go wrong before it does.
This document was written before implementation and will continue to be updated as the project evolves.



## 2. What am i building?

A CLI tool that:
- Connects to an AWS account using read-only IAM credentials
- Scans resources across S3, IAM, and EC2 for known misconfigurations
- Produces a prioritised list of findings with remediation guidance
- Outputs results as terminal output and (later) an HTML report



## 3. What can go wrong? — STRIDE Analysis

STRIDE is a threat modelling framework developed at Microsoft.
Each letter represents a class of threat.


1. Spoofing - Attacker pretends to be someone else. E.g Stolen AWS credentials used to run the scanner as the legitimate user. 
2. Tampering - Attacker modifies data. E.g Scanner output being modified before a security team reads it, hiding real findings.
3. Repudiation - Actions cannot be traced back to their source. E.g Scanner running with no audit log, no record of who scanned what and when.
4. Information Disclosure - Sensitive data being exposed. In this scenario, scanner output file (JSON/HTML) containining resource names and ARNs leaked to wrong person. 
5. Denial of Service -  Tool or service made unavailable. E.g Excessive API calls trigger AWS rate limiting, breaking the scanner mid-run.
6. Elevation of Privilege - Attacker gaining  more access than intended. E.g Scanner IAM role having more permissions than needed. This can be exploited if credentials leak.

## 4. Assets — what are we protecting?

1. AWS credentials (access key + secret). 
Why? Full account access if stolen.
2. Scanner output report.
Why? Contains sensitive resource names and vulnerability details. 
3. IAM role used by scanner must be read-only 
Why? Any write permission is a risk.
4. The scanner codebase itself. 
Why? Malicious code injected here could exfiltrate account data

-

## 5. Attack surface — before this scanner

| Vector | Risk | Likelihood | Impact |

| Public S3 buckets | Data exposed to internet | High | Critical |
| Root account access keys | Full account takeover | Medium | Critical |
| Wildcard IAM policies | Privilege escalation | Medium | High |
| Open security groups (0.0.0.0/0) | Unauthorised network access | High | High |
| Unencrypted EBS volumes | Data exposure if snapshot shared | Low | Medium |

---

## 6. Attack surface — after this scanner

| Vector | Residual Risk | Notes |
|--------|--------------|-------|
| Public S3 buckets | Low | Scanner detects and alerts within minutes of running |
| Root account access keys | Low | Detected on every scan |
| Wildcard IAM policies | Low | All customer-managed policies checked |
| Open security groups | Medium | Not yet implemented — planned Week 3 |
| Unencrypted EBS volumes | Medium | Not yet implemented — planned Week 3 |



## 7. Mitigations I have implemented

- Scanner IAM role uses only `SecurityAudit` + `ReadOnlyAccess`  meaning it cannot modify anything
- Credentials stored in `~/.aws/credentials` and never hardcoded in source code
- `.gitignore` prevents credentials and reports from being pushed to GitHub
- Each check wrapped in `try/except` so thatone failure does not expose other findings



## 8. Limitations and what this scanner does not catch

- Does not scan multi-region — only checks `us-east-1` by default
- Does not detect CloudTrail being disabled (no audit logging)
- Does not check RDS, Lambda, or other services yet
- A sophisticated attacker who has already compromised the account could 
  modify IAM policies to hide findings from this scanner
- False negative rate is unknown for accounts with complex permission boundaries



## 9. Assumptions

- The machine running this scanner is trusted and not compromised
- The IAM credentials used are stored securely and not shared
- AWS API responses are assumed to be truthful — we do not verify them independently



## 10. References

- [STRIDE Threat Modelling — Microsoft](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [AWS IAM Security Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)