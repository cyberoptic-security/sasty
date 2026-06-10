def parse(items: list) -> list[dict]:
    """Parse a list of TruffleHog JSON objects (from NDJSON stdout output)."""
    findings = []
    for item in items:
        detector_name = item.get("DetectorName", "secret-detected")
        verified = item.get("Verified", False)

        # Extract location from SourceMetadata
        src_data = item.get("SourceMetadata", {}).get("Data", {})
        git_data = src_data.get("Git", {})
        fs_data = src_data.get("Filesystem", {})

        if git_data:
            file_path = git_data.get("file", "")
            line = git_data.get("line")
            commit = git_data.get("commit", "").strip() or None
            author = git_data.get("email", "").strip() or None
            timestamp = git_data.get("timestamp", "")
            date = timestamp[:10] if timestamp else None
        elif fs_data:
            file_path = fs_data.get("file", "")
            line = fs_data.get("line")
            commit = None
            author = None
            date = None
        else:
            file_path = ""
            line = None
            commit = None
            author = None
            date = None

        # Verified secrets are HIGH, unverified are MEDIUM
        severity = "HIGH" if verified else "MEDIUM"

        raw = item.get("Raw", "") or ""
        redacted = item.get("Redacted", "") or ""
        matched = redacted if redacted else (raw[:80] + "..." if len(raw) > 80 else raw)

        verified_str = "Verified" if verified else "Unverified"
        rule_id = f"trufflehog.{detector_name.lower().replace(' ', '-')}"

        findings.append(
            {
                "tool": "trufflehog",
                "rule_id": rule_id,
                "rule_name": detector_name,
                "severity": severity,
                "category": "secrets",
                "message": f"{verified_str} {detector_name} credential detected",
                "file_path": file_path,
                "line_start": line,
                "line_end": line,
                "col_start": None,
                "col_end": None,
                "matched_code": matched or None,
                "fingerprint": None,
                "commit_hash": commit,
                "commit_author": author,
                "commit_date": date,
                "cwe": ["CWE-798"],
                "owasp": ["A02:2021 - Cryptographic Failures"],
                "references": ["https://github.com/trufflesecurity/trufflehog"],
                "tags": ["verified" if verified else "unverified"],
            }
        )
    return findings
