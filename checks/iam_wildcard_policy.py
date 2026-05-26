import boto3
import json
from core.finding import Finding

def check_wildcard_policies(profile_name: str) -> list[Finding]:
    session = boto3.Session(profile_name=profile_name)
    iam = session.client("iam")
    findings = []

    paginator = iam.get_paginator("list_policies")
    pages = paginator.paginate(Scope="Local")

    for page in pages:
        for policy in page["Policies"]:
            policy_name = policy["PolicyName"]
            policy_arn = policy["Arn"]

            version = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy["DefaultVersionId"]
            )

            statements = version["PolicyVersion"]["Document"]["Statement"]

            if isinstance(statements, dict):
                statements = [statements]

            for statement in statements:
                actions = statement.get("Action", [])
                effect = statement.get("Effect", "")

                if isinstance(actions, str):
                    actions = [actions]

                if effect == "Allow" and "*" in actions:
                    findings.append(Finding(
                        resource_id=policy_arn,
                        resource_type="IAM Policy",
                        severity="HIGH",
                        title=f"Policy '{policy_name}' allows wildcard actions",
                        description=(
                            f"The policy '{policy_name}' contains an Allow statement "
                            f"with Action: '*', granting unrestricted access to all "
                            f"AWS services and actions to whoever holds this policy."
                        ),
                        remediation=(
                            f"AWS Console → IAM → Policies → {policy_name} → Edit. "
                            "Replace the wildcard '*' with only the specific actions "
                            "this policy genuinely needs. Follow least privilege."
                        )
                    ))

    return findings