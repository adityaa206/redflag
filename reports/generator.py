import os
import datetime
import pandas as pd


def findings_to_dataframe(findings):
    rows = []
    for f in findings:
        rows.append({
            "Title":            f.title,
            "CVE ID":           f.cve_id or "",
            "Host":             f.host or "",
            "Port":             f.port,
            "Service":          f.service or "",
            "Scanner":          str(getattr(f.scanner_source, "value", f.scanner_source)).upper(),
            "CVSS Score":       f.cvss_score,
            "Risk Score":       f.risk_score,
            "Deal Tier":        str(getattr(f.deal_tier, "value", f.deal_tier)).replace("_", " ").title(),
            "Exposure":         str(getattr(f.exposure, "value", f.exposure)).replace("_", " ").title(),
            "Data Sensitivity": str(getattr(f.data_sensitivity, "value", f.data_sensitivity)).replace("_", " ").title(),
            "Exploit Status":   str(getattr(f.exploit_status, "value", f.exploit_status)).replace("_", " ").title(),
            "Evidence":         str(getattr(f.evidence_strength, "value", f.evidence_strength)).replace("_", " ").title(),
            "Description":      f.description,
            "Remediation":      f.remediation,
            "Override Reason":  f.override_reason or "",
            "Discovered At":    f.discovered_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        })
    return pd.DataFrame(rows)


def export_findings_csv(findings, output_dir="data/results"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"redflag_report_{timestamp}.csv")
    findings_to_dataframe(findings).to_csv(output_file, index=False)
    return output_file
