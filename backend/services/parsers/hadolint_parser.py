SEVERITY_MAP = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "info": "LOW",
    "style": "INFO",
}

# Detailed descriptions for common hadolint rules.
# Source: https://github.com/hadolint/hadolint/wiki
RULE_DETAILS: dict[str, str] = {
    "DL3000": "Use absolute WORKDIR. A relative WORKDIR path may behave unexpectedly depending on the base image.",
    "DL3001": "For some bash commands it makes no sense running them in a Docker container like ssh, vim, shutdown, service, ps, free, top, kill, mount, ifconfig.",
    "DL3002": "Last USER should not be root. Running containers as root is a security risk. Switch to a non-root user as the final USER.",
    "DL3003": "Use WORKDIR to switch to a directory instead of proliferating 'cd' commands which are hard to follow and may not persist across RUN layers.",
    "DL3004": "Do not use sudo as it leads to unpredictable behavior. If you need root, use USER root and switch back.",
    "DL3005": "Do not use apt-get upgrade or dist-upgrade. Instead, pin package versions to get reproducible builds.",
    "DL3006": "Always tag the version of an image explicitly in FROM. Using 'latest' or no tag leads to non-reproducible builds.",
    "DL3007": "Using latest is prone to errors if the image will ever update. Pin the version explicitly to a release tag.",
    "DL3008": "Pin versions in apt-get install (e.g., apt-get install package=version). This ensures reproducible builds.",
    "DL3009": "Delete the apt-get lists after installing something. They take up space and are not needed in the image.",
    "DL3010": "Use ADD for extracting archives into an image. COPY does not auto-extract tar files.",
    "DL3011": "Valid UNIX ports range from 0 to 65535. The EXPOSE instruction has an invalid port number.",
    "DL3012": "Provide an email address or URL as maintainer. The MAINTAINER instruction is deprecated; use a LABEL instead.",
    "DL3013": "Pin versions in pip install (e.g., pip install package==version). Use --no-cache-dir to reduce image size.",
    "DL3014": "Use the -y switch to avoid manual input during apt-get install (e.g., apt-get install -y).",
    "DL3015": "Avoid additional packages by specifying --no-install-recommends with apt-get install.",
    "DL3016": "Pin versions in npm install (e.g., npm install package@version). Use --ignore-scripts for security.",
    "DL3017": "Do not use apk upgrade. Pin package versions for reproducible builds.",
    "DL3018": "Pin versions in apk add (e.g., apk add package=version). Use --no-cache to reduce image size.",
    "DL3019": "Use --no-cache with apk add instead of a separate apk cache purge step.",
    "DL3020": "Use COPY instead of ADD for files and folders. ADD has extra features (tar extraction, remote URLs) that are often unnecessary.",
    "DL3021": "COPY with more than 2 arguments requires the last argument to end with /.",
    "DL3022": "COPY --from should reference a previously defined build stage with a name instead of a number.",
    "DL3023": "COPY --from cannot reference its own FROM alias. Use a previous stage or an external image.",
    "DL3024": "FROM aliases (AS name) must be unique across the Dockerfile.",
    "DL3025": "Use arguments JSON notation (CMD [\"cmd\", \"arg\"]) for exec form. Shell form can cause signal handling issues.",
    "DL3026": "Use only an allowed registry in the FROM image. This enforces corporate image policies.",
    "DL3027": "Do not use apt as it does not have a stable CLI interface. Use apt-get or apt-cache instead.",
    "DL3028": "Pin versions in gem install (e.g., gem install package:version). Use --no-document to reduce size.",
    "DL3029": "Do not use --platform flag with FROM unless absolutely necessary. It reduces portability.",
    "DL3030": "Use the --no-cache switch with yum/dnf to keep the image clean.",
    "DL3032": "yum clean all missing after yum install. This wastes space in the image layer.",
    "DL3033": "Pin package versions in yum install for reproducible builds.",
    "DL3034": "Non-interactive switch missing (e.g., -y) for yum install.",
    "DL3035": "Do not use zypper dist-upgrade. Pin versions instead.",
    "DL3036": "Pin package versions in zypper install for reproducible builds.",
    "DL3037": "Non-interactive switch missing for zypper install. Use --non-interactive.",
    "DL3038": "Use the --non-interactive switch with zypper or use zypper clean after install.",
    "DL3040": "dnf clean all missing after dnf install.",
    "DL3041": "Pin package versions in dnf install for reproducible builds.",
    "DL3042": "Avoid use of cache directory with pip install. Use --no-cache-dir.",
    "DL3043": "ONBUILD, FROM, or MAINTAINER instructions are disallowed after ONBUILD.",
    "DL3044": "Do not refer to an environment variable within the same ENV statement where it is defined.",
    "DL3045": "COPY to a relative destination without WORKDIR set. Use absolute paths or set WORKDIR first.",
    "DL3046": "Invalid label key format. Labels should use reverse-DNS notation.",
    "DL3047": "Avoid wget and use ADD or COPY with verified checksums instead.",
    "DL3048": "Invalid label key. Should be lowercase with dots and hyphens only.",
    "DL3049": "Label is missing. Add required labels (e.g., maintainer, version, description).",
    "DL3050": "Superfluous label(s) present. Labels should follow organizational conventions.",
    "DL3051": "Label is empty. Provide a value for all labels.",
    "DL3052": "Label is not a valid URL. If a URL label is expected, provide a valid one.",
    "DL3053": "Label is not a valid time format (RFC 3339).",
    "DL3054": "Label is not a valid SPDX license identifier.",
    "DL3055": "Label is not a valid git hash.",
    "DL3056": "Label is not a valid semantic version.",
    "DL3057": "HEALTHCHECK instruction missing. Add a HEALTHCHECK to verify the container is running correctly.",
    "DL3058": "Label is not a valid email format.",
    "DL3059": "Multiple consecutive RUN instructions. Consider consolidating them to reduce image layers.",
    "DL3060": "yarn cache clean missing after yarn install.",
    "DL4000": "MAINTAINER is deprecated. Use LABEL maintainer=\"name\" instead.",
    "DL4001": "Either use wget or curl but not both. Pick one to reduce image size.",
    "DL4003": "Multiple CMD instructions found. Only the last one takes effect; the others are silently ignored.",
    "DL4004": "Multiple ENTRYPOINT instructions found. Only the last one takes effect.",
    "DL4005": "Use SHELL to change the default shell instead of RUN ln -sf /bin/bash /bin/sh.",
    "DL4006": "Set the SHELL option -o pipefail before a RUN with a pipe in. This ensures pipe failures are caught.",
    "SC1000": "ShellCheck: $ is not used specially and should be escaped as \\$.",
    "SC2046": "ShellCheck: Quote this to prevent word splitting.",
    "SC2086": "ShellCheck: Double quote to prevent globbing and word splitting.",
}


def parse(data: list) -> list[dict]:
    findings = []
    for item in data:
        code = item.get("code", "DL0000")
        level = item.get("level", "warning").lower()
        severity = SEVERITY_MAP.get(level, "MEDIUM")
        short_msg = item.get("message", "")
        rationale = RULE_DETAILS.get(code, "")
        # Use the short description as the rule name (title)
        rule_name = short_msg or code
        # Use the rationale as the message body; fall back to short_msg
        message = rationale if rationale else short_msg
        findings.append(
            {
                "tool": "hadolint",
                "rule_id": f"hadolint.{code}",
                "rule_name": rule_name,
                "severity": severity,
                "category": "dockerfile",
                "message": message,
                "file_path": item.get("file", ""),
                "line_start": item.get("line"),
                "line_end": item.get("line"),
                "col_start": item.get("column"),
                "col_end": item.get("column"),
                "matched_code": None,
                "fingerprint": None,
                "cwe": None,
                "owasp": None,
                "references": [f"https://github.com/hadolint/hadolint/wiki/{code}"],
            }
        )
    return findings
