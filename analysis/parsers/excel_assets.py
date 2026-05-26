import pandas as pd
from analysis.schema import DataSensitivity, Finding

_SENSITIVITY_ALIASES = {
    "crown_jewel":  DataSensitivity.CROWN_JEWEL,
    "crown jewel":  DataSensitivity.CROWN_JEWEL,
    "crownjewel":   DataSensitivity.CROWN_JEWEL,
    "regulated":    DataSensitivity.REGULATED,
    "sensitive":    DataSensitivity.SENSITIVE,
    "low":          DataSensitivity.LOW,
    "unknown":      DataSensitivity.UNKNOWN,
}


def parse_asset_excel(excel_file: str) -> dict[str, DataSensitivity]:
    """
    Parse an asset inventory Excel file into an IP → DataSensitivity map.

    Required columns (case-insensitive):
      - IP / Host / IP Address / Hostname
      - Sensitivity / Data Sensitivity / Classification

    Returns empty dict and raises ValueError if required columns are missing.
    """
    try:
        df = pd.read_excel(excel_file, engine="openpyxl")
    except Exception as e:
        raise ValueError(f"Could not read Excel file: {e}")

    df.columns = [str(c).strip().lower().replace(" ", "_") for c in df.columns]

    ip_col = next(
        (c for c in df.columns if c in ("ip", "host", "ip_address", "hostname", "address")),
        None,
    )
    sens_col = next(
        (c for c in df.columns if "sensitiv" in c or "classif" in c or c == "tier"),
        None,
    )

    if not ip_col or not sens_col:
        raise ValueError(
            f"Excel must have an IP/host column and a sensitivity column. "
            f"Found: {list(df.columns)}"
        )

    asset_map: dict[str, DataSensitivity] = {}
    for _, row in df.iterrows():
        ip = str(row[ip_col]).strip()
        if not ip or ip.lower() == "nan":
            continue
        raw = str(row[sens_col]).strip().lower().replace("-", "_").replace(" ", "_")
        asset_map[ip] = _SENSITIVITY_ALIASES.get(raw, DataSensitivity.UNKNOWN)

    return asset_map


def apply_sensitivity_to_findings(
    findings: list[Finding],
    asset_map: dict[str, DataSensitivity],
) -> list[Finding]:
    """
    Stamp data_sensitivity onto findings matched by host IP.
    Only updates findings that are currently UNKNOWN — never downgrades.
    """
    for f in findings:
        if f.host and f.host in asset_map:
            if f.data_sensitivity == DataSensitivity.UNKNOWN:
                f.data_sensitivity = asset_map[f.host]
    return findings
