FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Update and install all required packages
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    git \
    curl \
    wget \
    nmap \
    nikto \
    sqlmap \
    dirb \
    metasploit-framework \
    hydra \
    john \
    aircrack-ng \
    masscan \
    dnsutils \
    whois \
    net-tools \
    tcpdump \
    vim \
    sudo \
    libcap2-bin \
    postgresql \
    postgresql-contrib \
    whatweb \
    wapiti \
    wafw00f \
    dnsenum \
    dnsrecon \
    fierce \
    theharvester \
    amass \
    subfinder \
    sublist3r \
    gobuster \
    dirbuster \
    ffuf \
    wfuzz \
    arjun \
    nuclei \
    sslscan \
    sslyze \
    testssl.sh \
    davtest \
    cewl \
    && rm -rf /var/lib/apt/lists/*

# Set capabilities for tools that need them
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap || true && \
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/masscan || true && \
    setcap cap_net_raw+ep /usr/bin/tcpdump || true

WORKDIR /opt

# Clone and install Sn1per
RUN git clone https://github.com/1n3/sn1per.git

WORKDIR /opt/sn1per

# Make install script executable and run it
RUN chmod +x install.sh && \
    bash install.sh || true

# Create necessary directories
RUN mkdir -p /usr/share/sniper/loot && \
    chmod -R 777 /usr/share/sniper

RUN pip3 install --break-system-packages flask flask-cors gunicorn

WORKDIR /app

COPY app.py .
COPY templates/ templates/

EXPOSE 8080

# Create a startup script to handle permissions
RUN echo '#!/bin/bash\n\
service postgresql start 2>/dev/null || true\n\
# Fix nmap permissions\n\
chmod +s /usr/bin/nmap 2>/dev/null || true\n\
# Start the application\n\
exec gunicorn --bind 0.0.0.0:${PORT:-8080} --workers 2 --timeout 300 app:app' > /app/start.sh && \
    chmod +x /app/start.sh

CMD ["/app/start.sh"]