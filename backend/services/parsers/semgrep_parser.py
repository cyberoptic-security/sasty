SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    "INVENTORY": "INFO",
}


def parse(data: dict) -> list[dict]:
    findings = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        raw_sev = extra.get("severity", "INFO").upper()
        severity = SEVERITY_MAP.get(raw_sev, "INFO")

        check_id = result.get("check_id", "unknown")
        rule_name = check_id.split(".")[-1].replace("-", " ").replace("_", " ").title()

        cwe = metadata.get("cwe", [])
        if isinstance(cwe, str):
            cwe = [cwe]

        owasp = metadata.get("owasp", [])
        if isinstance(owasp, str):
            owasp = [owasp]

        refs = metadata.get("references", [])
        if isinstance(refs, str):
            refs = [refs]

        findings.append(
            {
                "tool": "semgrep",
                "rule_id": check_id,
                "rule_name": rule_name,
                "severity": severity,
                "category": metadata.get("category", "security"),
                "message": extra.get("message", ""),
                "file_path": result.get("path", ""),
                "line_start": result.get("start", {}).get("line"),
                "line_end": result.get("end", {}).get("line"),
                "col_start": result.get("start", {}).get("col"),
                "col_end": result.get("end", {}).get("col"),
                "matched_code": extra.get("lines", "").strip(),
                "fingerprint": extra.get("fingerprint"),
                "cwe": cwe or None,
                "owasp": owasp or None,
                "references": refs or None,
            }
        )
    return findings
