import os
import datetime
import pandas as pd


def findings_to_dataframe(findings):
    rows = []

    for f in findings:
        rows.append({
            "Title": f.title,
            "Host": f.host,
            "Port": f.port,
            "Service": f.service,
            "Risk Score": f.risk_score,
            "Deal Tier": getattr(f.deal_tier, "value", f.deal_tier),
            "Exposure": getattr(f.exposure, "value", f.exposure),
            "Description": f.description,
            "Remediation": f.remediation
        })

    return pd.DataFrame(rows)


def export_findings_csv(findings, output_dir="data/results"):
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"redflag_report_{timestamp}.csv")

    df = findings_to_dataframe(findings)
    df.to_csv(output_file, index=False)

    return output_file