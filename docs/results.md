 Results — Cloud Misconfiguration Scanner

Author:Ibukun Olaniyan
Date: 27th May 2026
Version: 1.0


## Test Environment

Property  ---    Value 

 AWS Account type --- Free tier sandbox 
 Region scanned --- us-east-1 
 Total resources scanned --- 3 intentional + baseline account 
 Scan duration --- ~5 seconds 


## Findings Summary

Severity --- Count 

 Critical --- 1 
 High --- 0 
 Medium --- 1 
 Low --- 0 
 Total --- 2 



## Findings Detail

Resource -- Type -- Severity -- Finding 

 test-vulnerable-sg -- EC2 Security Group -- CRITICAL -- SSH port 22 open to 0.0.0.0/0 
 vol-0d9d5f2e2687e7eb4 -- EBS Volume -- MEDIUM -- Unencrypted volume at rest 



## False Positive Rate

No false positives were recorded during testing. All findings were intentionally created misconfigurations confirmed by
manual inspection in the AWS Console before scanning.
Estimated false negative rate: moderate — the scanner does not yet cover CloudTrail, RDS, Lambda, or multi-region environments.



## Before vs After Attack Surface

Vector -- Before Scanner -- After Scanner 

 Exposed SSH -- Undetected-- Flagged CRITICAL in <5s 
 Unencrypted storage -- Undetected -- Flagged MEDIUM in <5s 
 Public S3 -- Detected (boto3 version issue patched) -- Flagged CRITICAL 
 Root access keys -- Clean -- Clean-- check passed 
 Wildcard IAM -- Clean -- Clean — check passed 