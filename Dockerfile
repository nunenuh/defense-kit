FROM kalilinux/kali-rolling

LABEL maintainer="nunenuh"
LABEL description="defense-kit: Defensive security toolkit"

ENV DEBIAN_FRONTEND=noninteractive

# ============================================
# Layer 1: OS audit + network tools
# ============================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    # OS audit
    lynis \
    # Network
    nmap \
    net-tools \
    iputils-ping \
    traceroute \
    tcpdump \
    dnsutils \
    # Firewall
    ufw \
    # SSH
    openssh-client \
    # Utils
    curl \
    wget \
    jq \
    git \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    libffi-dev \
    libssl-dev \
    # Reporting
    pandoc \
    && rm -rf /var/lib/apt/lists/*

# ============================================
# Layer 2: Code scanning (SAST + secrets)
# ============================================
RUN pip3 install --no-cache-dir --break-system-packages --ignore-installed \
    semgrep \
    bandit \
    pip-audit || \
    (pip3 install --no-cache-dir --break-system-packages semgrep && \
     pip3 install --no-cache-dir --break-system-packages bandit && \
     pip3 install --no-cache-dir --break-system-packages pip-audit)

# ============================================
# Layer 3: Dependency + container scanning
# ============================================
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Hadolint — Dockerfile linter
RUN curl -sSL https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 -o /usr/local/bin/hadolint && \
    chmod +x /usr/local/bin/hadolint

# Dockle — container best practices
RUN curl -sSL https://github.com/goodwithtech/dockle/releases/latest/download/dockle_0.4.14_Linux-64bit.tar.gz | \
    tar -xzf - -C /usr/local/bin dockle || true

# ============================================
# Layer 4: Secret scanning
# ============================================
RUN curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/scripts/install.sh | sh -s -- -b /usr/local/bin

RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin || true

# ============================================
# Layer 5: SSH audit
# ============================================
RUN pip3 install --no-cache-dir --break-system-packages ssh-audit || true

# ============================================
# Layer 6: Pre-commit for git hardening
# ============================================
RUN pip3 install --no-cache-dir --break-system-packages pre-commit || true

# ============================================
# defense-kit files
# ============================================
WORKDIR /defense-kit

COPY .claude/ /defense-kit/.claude/
COPY scanners/ /defense-kit/scanners/
COPY hardeners/ /defense-kit/hardeners/
COPY monitors/ /defense-kit/monitors/
COPY policies/ /defense-kit/policies/
COPY tools/ /defense-kit/tools/
COPY README.md CLAUDE.md /defense-kit/

RUN mkdir -p /defense-kit/target /defense-kit/outputs

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["bash"]
