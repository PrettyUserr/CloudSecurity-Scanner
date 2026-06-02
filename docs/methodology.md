 Methodology of the Cloud Misconfiguration Scanner

Author: Ibukun Olaniyan
Date:27th May 2026



<!-- Why Python and boto3? -->
Python was chosen for readability and the maturity of its AWS SDK. Boto3 is the official AWS SDK maintained by Amazon and it handles authentication, pagination, and retry logic out of the box. An alternative like Steampipe was considered but rejected because it abstracts too much away from the underlying API calls, which reduces
learning value and makes the tool harder to extend.


 <!-- Why a dataclass for findings? -->
Every check returns a standardised `Finding` dataclass instead of a raw dictionary. This enforces a consistent contract across all checks — resource_id, severity, title, description, remediation. Without this, each check would return a different structure and the reporter would become unmaintainable. This is the same pattern used in production security tools like Prowler and ScoutSuite.


<!-- Why STRIDE for threat modelling? -->
STRIDE was chosen over PASTA or attack trees because it maps directly to the type of threats relevant to a cloud audit tool. Threats like spoofing credentials, tampering with output, information disclosure through report files. STRIDE is also the most widely recognised framework in enterprise security design reviews.


 <!-- Why CRITICAL/HIGH/MEDIUM/LOW over CVSS? -->
Full CVSS scoring requires base, temporal, and environmental metrics that are difficult to automate without infrastructure
context. A four-tier severity model was chosen as a better alternative that communicates urgency clearly without false
precision. CRITICAL is reserved for findings that give an attacker direct account access or data exposure.


 <!-- Why moto for testing? -->
moto intercepts boto3 API calls and returns realistic mock responses without making real AWS API calls. This means the test suite runs In CI/CD with no AWS credentials and zero cost. It also means tests are deterministic meaning they always return the same results regardless of what's in the actual AWS account.


 <!-- Why per-check try/except? -->

Each check is wrapped in a try/except in the runner so one failing
check does not abort the entire scan. In a production environment,
API throttling or permission errors on one service should not prevent
the scanner from completing checks on other services.
