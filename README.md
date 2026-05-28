# CloudSecurity-Scanner
A Python CLI tool that audits AWS accounts for critical security misconfigurations across S3, IAM, and EC2.
Built as Project 01 of cloud security engineering portfolio.

---

## What it detects

 Check -- Service -- Severity 

 Public access block disabled -- S3 -- CRITICAL 
 Root account access keys present -- IAM -- CRITICAL 
 Wildcard Action: * in policies -- IAM -- HIGH 
 Security group open to 0.0.0.0/0 -- EC2 -- CRITICAL 
 Unencrypted EBS volumes -- EC2 -- MEDIUM 

---

## Installation

```bash
git clone https://github.com/PrettyUserr/CloudSecurity-Scanner.git
cd CloudSecurity-Scanner
python3 -m venv venv
source venv/bin/activate
pip install boto3 rich click jinja2
```

---

## How to use

```bash
aws configure --profile yourprofile

# Run the scanner
python3 cli.py


## Documentation

- [Threat Model](docs/threat_model.md)
- [Methodology](docs/methodology.md)
- [Results](docs/results.md)
- [Limitations](docs/limitations.md)

---

## IAM permissions required

The scanner requires read-only access:
- `SecurityAudit`
- `ReadOnlyAccess`

nNote: Never run this with admin credentials.


## License
MIT License — see LICENSE file.