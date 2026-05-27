import boto3
from core.finding import Finding

def check_s3_public_access(profile_name: str) -> list[Finding]:
    session = boto3.Session(profile_name=profile_name)
    s3 = session.client("s3")
    findings = []

    buckets = s3.list_buckets().get("Buckets", [])

    for bucket in buckets:
        name = bucket["Name"]
        try:
            config = s3.get_public_access_block(Bucket=name)
            block = config["PublicAccessBlockConfiguration"]

            all_blocked = all([
                block.get("BlockPublicAcls"),
                block.get("IgnorePublicAcls"),
                block.get("BlockPublicPolicy"),
                block.get("RestrictPublicBuckets"),
            ])

            if not all_blocked:
                findings.append(Finding(
                    resource_id=name,
                    resource_type="S3 Bucket",
                    severity="CRITICAL",
                    title="S3 bucket public access not fully blocked",
                    description=f"Bucket '{name}' has one or more Public Access Block settings disabled. This can expose files to the entire internet.",
                    remediation="AWS Console → S3 → your bucket → Permissions → Block Public Access → Edit → enable all four toggles."
                ))

        except Exception as e:
            if "NoSuchPublicAccessBlockConfiguration" in str(e):
                findings.append(Finding(
                    resource_id=name,
                    resource_type="S3 Bucket",
                    severity="CRITICAL",
                    title="S3 bucket has no public access block at all",
                    description=f"Bucket '{name}' has no Public Access Block configuration. It may be fully open to the internet.",
                    remediation="AWS Console → S3 → your bucket → Permissions → Block Public Access → Edit → enable all four toggles."
                ))

    return findings

  