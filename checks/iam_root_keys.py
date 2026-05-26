import boto3
from core.finding import Finding

def check_root_access_keys(profile_name: str) -> list[Finding]:
    session = boto3.Session(profile_name=profile_name)
    iam = session.client("iam")
    findings = []

    summary = iam.get_account_summary()
    account_summary = summary["SummaryMap"]

    if account_summary.get("AccountAccessKeysPresent", 0) > 0:
        findings.append(Finding(
            resource_id="root",
            resource_type="IAM Root Account",
            severity="CRITICAL",
            title="Root account has active access keys",
            description=(
                "The root account has programmatic access keys. "
                "If leaked, an attacker gains unrestricted access to your "
                "entire AWS account with no way to revoke their permissions."
            ),
            remediation=(
                "AWS Console → IAM → Security credentials → "
                "Access keys section → Delete all root access keys. "
                "Create an IAM user with only the permissions you need instead."
            )
        ))

    return findings