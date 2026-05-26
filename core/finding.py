from dataclasses import dataclass

@dataclass
class Finding:
    resource_id: str
    resource_type: str
    severity: str
    title: str
    description: str
    remediation: str