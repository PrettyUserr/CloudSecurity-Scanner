from jinja2 import Environment, FileSystemLoader
from datetime import datetime
import os

def generate_html_report(findings: list, profile: str, output_path: str = "report.html"):
    template_dir = os.path.join(os.path.dirname(__file__))
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("report_template.html")

    rendered = template.render(
        findings=findings,
        profile=profile,
        scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        critical_count=sum(1 for f in findings if f.severity == "CRITICAL"),
        high_count=sum(1 for f in findings if f.severity == "HIGH"),
        medium_count=sum(1 for f in findings if f.severity == "MEDIUM"),
        low_count=sum(1 for f in findings if f.severity == "LOW"),
    )

    with open(output_path, "w") as file:
        file.write(rendered)

    print(f"\n HTML report saved to: {output_path}")
  