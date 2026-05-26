from checks.s3_public import check_s3_public_access
from checks.iam_root_keys import check_root_access_keys
from checks.iam_wildcard_policy import check_wildcard_policies

PROFILE = "Prtusr"

CHECKS = [
    ("S3 Public Access", check_s3_public_access),
    ("IAM Root Keys", check_root_access_keys),
    ("IAM Wildcard Policies", check_wildcard_policies),
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

print("\n🔍 Running cloud misconfiguration scanner...\n")

all_findings = []

for check_name, check_fn in CHECKS:
    print(f"  Running: {check_name}...")
    try:
        results = check_fn(profile_name=PROFILE)
        all_findings.extend(results)
    except Exception as e:
        print(f"  ⚠️  {check_name} failed: {e}")

all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

print(f"\n{'─' * 55}")

if not all_findings:
    print("✅  No issues found across all checks.")
else:
    for f in all_findings:
        severity_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        icon = severity_icons.get(f.severity, "⚪")
        print(f"\n{icon}  [{f.severity}] {f.title}")
        print(f"   Resource : {f.resource_id} ({f.resource_type})")
        print(f"   Why      : {f.description}")
        print(f"   Fix      : {f.remediation}")
        print(f"{'─' * 55}")

print(f"\nScan complete. {len(all_findings)} finding(s) — ", end="")
criticals = sum(1 for f in all_findings if f.severity == "CRITICAL")
highs = sum(1 for f in all_findings if f.severity == "HIGH")
print(f"{criticals} critical, {highs} high.\n")