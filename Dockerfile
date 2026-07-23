FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get -y full-upgrade && \
    apt-get -y install --no-install-recommends \
        kali-linux-headless \
        git \
        curl \
        wget \
        python3-pip \
        pipx \
        openvpn \
        netcat-traditional \
        iputils-ping \
        dnsutils \
        seclists \
        sudo \
        ca-certificates \
        gnupg \
        ripgrep \
        chromium \
        chromium-driver \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_24.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update && apt-get -y install --no-install-recommends nodejs \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Ensure npm is present (NodeSource nodejs may not ship npm on every arch/build)
RUN apt-get update && apt-get install -y npm && apt-get clean && rm -rf /var/lib/apt/lists/*

# OpenClaw CLI (used inside kali-ai to talk to the openclaw sidecar)
RUN npm install -g openclaw

RUN useradd -m -s /bin/bash pentest && \
    echo 'pentest:pentest' | chpasswd && \
    usermod -aG sudo pentest && \
    echo 'pentest ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Grant raw-socket capabilities to packet tools. Containers give capabilities to
# root only; without these file caps the unprivileged pentest user cannot run
# SYN scans or packet captures even though the container has cap_add NET_RAW.
# NOTE: /usr/lib/nmap/nmap is the real binary (/usr/bin/nmap is a wrapper script,
# and scripts cannot carry file caps). cap_net_admin must stay within each
# container's bounding set — see cap_add in docker-compose.yml.
RUN for bin in /usr/lib/nmap/nmap /usr/bin/masscan /usr/bin/tcpdump /usr/bin/hping3 /usr/bin/arp-scan /usr/bin/dumpcap; do \
      if [ -f "$bin" ]; then setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$bin" || true; fi; \
    done

USER pentest
WORKDIR /work

# Hermes Agent installer manages its own uv/Python environment under ~/.hermes
RUN curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash

ENV PATH="/home/pentest/.hermes/bin:/home/pentest/.local/bin:${PATH}"

CMD ["/bin/bash"]
