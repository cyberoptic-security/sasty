SEVERITY_MAP = {
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

CONFIDENCE_BOOST = {
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": -1,  # downgrade severity if confidence is low
}


def parse(data: dict) -> list[dict]:
    findings = []
    for result in data.get("results", []):
        test_id = result.get("test_id", "B000")
        test_name = result.get("test_name", "unknown")
        raw_sev = result.get("issue_severity", "MEDIUM").upper()
        confidence = result.get("issue_confidence", "HIGH").upper()
        severity = SEVERITY_MAP.get(raw_sev, "MEDIUM")

        # Downgrade severity for low-confidence findings
        boost = CONFIDENCE_BOOST.get(confidence, 0)
        if boost < 0 and severity == "LOW":
            severity = "INFO"
        elif boost < 0 and severity == "MEDIUM":
            severity = "LOW"

        cwe_data = result.get("issue_cwe", {})
        cwe = None
        if cwe_data and cwe_data.get("id"):
            cwe = [f"CWE-{cwe_data['id']}"]

        findings.append(
            {
                "tool": "bandit",
                "rule_id": f"bandit.{test_id}",
                "rule_name": test_name.replace("_", " ").title(),
                "severity": severity,
                "category": "security",
                "message": result.get("issue_text", ""),
                "file_path": result.get("filename", ""),
                "line_start": result.get("line_number"),
                "line_end": result.get("end_col_offset") and result.get("line_number"),
                "col_start": result.get("col_offset"),
                "col_end": result.get("end_col_offset"),
                "matched_code": (result.get("code") or "").strip(),
                "fingerprint": None,
                "cwe": cwe,
                "owasp": None,
                "references": [result["more_info"]] if result.get("more_info") else None,
            }
        )
    return findings
