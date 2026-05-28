 Limitations — Cloud Misconfiguration Scanner

Author: Ibukun Olaniyan
Date: 27th May 2026


## What this scanner does not currently check

 Gap | Risk | Planned 

 CloudTrail disabled | No audit log of API calls | v1.1 
 Multi-region scanning | Misconfigs in other regions missed | v1.1 
 RDS public accessibility | Database exposed to internet | v1.2 
 Lambda environment variables | Secrets in function config | v1.2 
 S3 bucket policies | Policy-based exposure missed | v1.1 
 GuardDuty disabled | No threat detection active | v1.2 
 MFA not enforced on IAM users | Account takeover risk | v1.1 


## Known false positive sources
- Security groups intentionally open to 0.0.0.0/0 for legitimate public-facing services (e.g. port 443 for a
  web server) will be flagged. Future versions will allow a whitelist configuration file.

- EBS volumes used for temporary scratch work may egitimately be unencrypted. Context is not currently considered in      severity scoring.


## Evasion — what a sophisticated attacker could do
A threat actor who has already compromised the account with sufficient IAM permissions could:
- Modify IAM policies to deny the scanner's read access
- Delete CloudTrail logs before the scanner runs
- Temporarily re-enable public access block to evade detection,then remove it after the scan completes

This scanner is a point-in-time assessment tool, not a continuous monitoring solution. For continuous monitoring, AWS Config Rules or AWS Security Hub should be used alongside this tool.


## Single account limitation
The scanner currently operates against one AWS account per run. Organisations running AWS Organisations with multiple member
accounts are not fully covered. Multi-account support via IAM role assumption is planned for v2.0. Check back for updates.