FROM kalilinux/kali-rolling

LABEL maintainer="nunenuh"
LABEL description="defense-kit — defensive security toolkit"

# Layer 1: OS audit + network tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    lynis rkhunter chkrootkit \
    nmap net-tools dnsutils tcpdump \
    openssh-client curl wget git \
    python3 python3-pip \
    jq pandoc \
    && rm -rf /var/lib/apt/lists/*

# Layer 2: Code scanning
RUN pip3 install --break-system-packages \
    semgrep bandit pip-audit ssh-audit

# Layer 3: Dependency + container scanning
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Layer 4: Secret scanning
RUN apt-get update && apt-get install -y --no-install-recommends \
    golang-go && \
    go install github.com/gitleaks/gitleaks/v8@latest && \
    mv /root/go/bin/gitleaks /usr/local/bin/ && \
    rm -rf /root/go && \
    apt-get remove -y golang-go && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Layer 5: Container linting
RUN wget -O /usr/local/bin/hadolint \
    https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 && \
    chmod +x /usr/local/bin/hadolint

# Layer 6: File integrity + forensics
RUN apt-get update && apt-get install -y --no-install-recommends \
    aide debsums \
    && rm -rf /var/lib/apt/lists/*

# Layer 7: ClamAV
RUN apt-get update && apt-get install -y --no-install-recommends \
    clamav clamav-daemon \
    && rm -rf /var/lib/apt/lists/* \
    && freshclam || true

# Copy Go binary (pre-built)
COPY defense-kit-cli/bin/defense-kit /usr/local/bin/defense-kit

# Copy templates and policies
COPY defense-kit-cli/templates/ /defense-kit/templates/
COPY policies/ /defense-kit/policies/
COPY tools/ /defense-kit/tools/

# Create directories
RUN mkdir -p /defense-kit/target /defense-kit/outputs

COPY docker/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

WORKDIR /defense-kit
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["bash"]
