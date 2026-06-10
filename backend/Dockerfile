FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates jq \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install gitleaks
RUN GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r '.tag_name' | tr -d 'v') \
    && curl -sL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

# Install hadolint
RUN HADOLINT_VERSION=$(curl -s https://api.github.com/repos/hadolint/hadolint/releases/latest | jq -r '.tag_name') \
    && curl -sL "https://github.com/hadolint/hadolint/releases/download/${HADOLINT_VERSION}/hadolint-Linux-x86_64" \
    -o /usr/local/bin/hadolint \
    && chmod +x /usr/local/bin/hadolint

# Install trivy
RUN TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | jq -r '.tag_name' | tr -d 'v') \
    && curl -sL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    | tar xz -C /usr/local/bin trivy \
    && chmod +x /usr/local/bin/trivy

# Install trufflehog
RUN TRUFFLEHOG_VERSION=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | jq -r '.tag_name' | tr -d 'v') \
    && curl -sL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" \
    | tar xz -C /usr/local/bin trufflehog \
    && chmod +x /usr/local/bin/trufflehog

COPY . .

# Directories for persistent data (mounted as volumes in compose)
RUN mkdir -p /app/data /app/tools_bin

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
