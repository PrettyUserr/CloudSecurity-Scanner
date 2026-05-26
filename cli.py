from checks.s3_public import check_s3_public_access

PROFILE = "Prtusr"

print("\n🔍 Running cloud misconfiguration scanner...\n")

findings = check_s3_public_access(profile_name=PROFILE)

if not findings:
    print("✅  No S3 public access issues found.")
else:
    for f in findings:
        print(f"{'─' * 55}")
        print(f"  Severity  : {f.severity}")
        print(f"  Resource  : {f.resource_id} ({f.resource_type})")
        print(f"  Issue     : {f.title}")
        print(f"  Why       : {f.description}")
        print(f"  Fix       : {f.remediation}")

print(f"\n{'─' * 55}")
print(f"Scan complete. {len(findings)} finding(s) found.")