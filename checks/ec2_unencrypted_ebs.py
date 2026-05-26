import boto3
from core.finding import Finding

def check_unencrypted_ebs(profile_name: str) -> list[Finding]:
    session = boto3.Session(profile_name=profile_name)
    ec2 = session.client("ec2")
    findings = []

    paginator = ec2.get_paginator("describe_volumes")
    pages = paginator.paginate()

    for page in pages:
        for volume in page["Volumes"]:
            volume_id = volume["VolumeId"]
            encrypted = volume["Encrypted"]
            state = volume["State"]
            size_gb = volume["Size"]

            attachments = volume.get("Attachments", [])
            attached_to = (
                attachments[0]["InstanceId"]
                if attachments else "not attached"
            )

            if not encrypted:
                findings.append(Finding(
                    resource_id=volume_id,
                    resource_type="EBS Volume",
                    severity="MEDIUM",
                    title=f"EBS volume {volume_id} is not encrypted",
                    description=(
                        f"EBS volume '{volume_id}' ({size_gb}GB, {state}) "
                        f"attached to '{attached_to}' is not encrypted at rest. "
                        f"If this volume's snapshot is shared accidentally or "
                        f"accessed by an attacker, its contents are readable in plaintext."
                    ),
                    remediation=(
                        "EBS volumes cannot be encrypted in place. To fix: "
                        "create a snapshot of the volume → copy the snapshot "
                        "with encryption enabled → create a new volume from "
                        "the encrypted snapshot → stop the instance → swap "
                        "the volumes → restart. Enable EBS encryption by "
                        "default in EC2 settings to prevent this going forward."
                    )
                ))

    return findings