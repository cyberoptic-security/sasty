SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "UNKNOWN": "INFO",
}


def parse(data: dict) -> list[dict]:
    findings = []
    results = data.get("Results", [])

    for result in results:
        target = result.get("Target", "")
        result_class = result.get("Class", "")

        # Vulnerability findings (dependencies)
        for vuln in result.get("Vulnerabilities") or []:
            vuln_id = vuln.get("VulnerabilityID", "CVE-unknown")
            pkg = vuln.get("PkgName", "")
            installed = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion", "")
            raw_sev = vuln.get("Severity", "UNKNOWN").upper()
            severity = SEVERITY_MAP.get(raw_sev, "INFO")

            title = vuln.get("Title", "")
            desc = vuln.get("Description", "")
            message = f"{pkg}@{installed}" if pkg else vuln_id
            if fixed:
                message += f" (fix available: {fixed})"
            if title:
                message += f"\n\n{title}"
            if desc:
                message += f"\n\n{desc}"

            cwe_ids = vuln.get("CweIDs") or []
            refs = vuln.get("References") or []

            findings.append(
                {
                    "tool": "trivy",
                    "rule_id": f"trivy.{vuln_id}",
                    "rule_name": title or vuln_id,
                    "severity": severity,
                    "category": "vulnerability",
                    "message": message.strip(),
                    "file_path": target,
                    "line_start": None,
                    "line_end": None,
                    "col_start": None,
                    "col_end": None,
                    "matched_code": f"{pkg}@{installed}" if pkg else None,
                    "fingerprint": None,
                    "cwe": cwe_ids or None,
                    "owasp": None,
                    "references": refs[:5] if refs else None,
                }
            )

        # Misconfiguration findings (IaC)
        for misconf in result.get("Misconfigurations") or []:
            misconf_id = misconf.get("ID", "MISC-unknown")
            raw_sev = misconf.get("Severity", "UNKNOWN").upper()
            severity = SEVERITY_MAP.get(raw_sev, "INFO")

            title = misconf.get("Title", "")
            desc = misconf.get("Description", "")
            resolution = misconf.get("Resolution", "")
            message = desc
            if resolution:
                message += f"\n\nResolution: {resolution}"

            refs = misconf.get("References") or []
            cause = misconf.get("CauseMetadata", {})

            findings.append(
                {
                    "tool": "trivy",
                    "rule_id": f"trivy.{misconf_id}",
                    "rule_name": title or misconf_id,
                    "severity": severity,
                    "category": "misconfiguration",
                    "message": message.strip(),
                    "file_path": target,
                    "line_start": cause.get("StartLine"),
                    "line_end": cause.get("EndLine"),
                    "col_start": None,
                    "col_end": None,
                    "matched_code": cause.get("Code", {}).get("Lines", [{}])[0].get("Content") if cause.get("Code", {}).get("Lines") else None,
                    "fingerprint": None,
                    "cwe": None,
                    "owasp": None,
                    "references": refs[:5] if refs else None,
                }
            )

    return findings
