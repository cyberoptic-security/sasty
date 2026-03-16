def parse(data: list) -> list[dict]:
    findings = []
    for item in data:
        rule_id = item.get("RuleID", "secret-detected")
        description = item.get("Description", rule_id.replace("-", " ").title())
        commit = item.get("Commit", "").strip()
        author = item.get("Author", "").strip()
        date = item.get("Date", "").strip()

        message = f"Potential secret detected: {description}"

        findings.append(
            {
                "tool": "betterleaks",
                "rule_id": f"betterleaks.{rule_id}",
                "rule_name": description,
                "severity": "HIGH",
                "category": "secrets",
                "message": message,
                "file_path": item.get("File", ""),
                "line_start": item.get("StartLine"),
                "line_end": item.get("EndLine"),
                "col_start": item.get("StartColumn"),
                "col_end": item.get("EndColumn"),
                "matched_code": item.get("Match", ""),
                "fingerprint": item.get("Fingerprint"),
                "commit_hash": commit or None,
                "commit_author": author or None,
                "commit_date": date or None,
                "cwe": ["CWE-798"],
                "owasp": ["A02:2021 - Cryptographic Failures"],
                "references": None,
            }
        )
    return findings
