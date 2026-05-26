import boto3
from core.finding import Finding

DANGEROUS_PORTS = {
    22: "SSH",
    3389: "RDP",
    5432: "PostgreSQL",
    3306: "MySQL",
    27017: "MongoDB",
    6379: "Redis",
}

def check_open_security_groups(profile_name: str) -> list[Finding]:
    session = boto3.Session(profile_name=profile_name)
    ec2 = session.client("ec2")
    findings = []

    response = ec2.describe_security_groups()
    security_groups = response["SecurityGroups"]

    for sg in security_groups:
        sg_id = sg["GroupId"]
        sg_name = sg["GroupName"]

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)

            open_to_internet = any(
                r["CidrIp"] == "0.0.0.0/0"
                for r in rule.get("IpRanges", [])
            )

            open_to_ipv6 = any(
                r["CidrIpv6"] == "::/0"
                for r in rule.get("Ipv6Ranges", [])
            )

            if not (open_to_internet or open_to_ipv6):
                continue

            for port, service in DANGEROUS_PORTS.items():
                if from_port <= port <= to_port:
                    findings.append(Finding(
                        resource_id=sg_id,
                        resource_type="EC2 Security Group",
                        severity="CRITICAL" if port in (22, 3389) else "HIGH",
                        title=f"Security group '{sg_name}' exposes {service} to the internet",
                        description=(
                            f"Security group '{sg_name}' ({sg_id}) allows inbound "
                            f"{service} traffic on port {port} from any IP address "
                            f"(0.0.0.0/0). This exposes your instance to brute force "
                            f"attacks and unauthorised access from anywhere in the world."
                        ),
                        remediation=(
                            f"AWS Console → EC2 → Security Groups → {sg_id} → "
                            f"Inbound rules → Edit → restrict port {port} to your "
                            f"specific IP address only, or remove the rule entirely "
                            f"if this port doesn't need to be open."
                        )
                    ))

    return findings