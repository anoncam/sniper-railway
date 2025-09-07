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
    chmod -R 777 /usr/share/sniper && \
    mkdir -p /app/tools

# Install Python packages (cache bust: v5) - Use system Flask 3.1.1
COPY requirements.txt /app/requirements.txt
RUN pip3 install --break-system-packages Flask-CORS==4.0.0 gunicorn==21.2.0

WORKDIR /app

COPY app.py .
COPY templates/ templates/
COPY nmap-wrapper.sh /app/tools/
COPY sniper-wrapper.sh /app/tools/

# Create symlinks to use our wrappers
RUN chmod +x /app/tools/nmap-wrapper.sh /app/tools/sniper-wrapper.sh && \
    mv /usr/bin/nmap /usr/bin/nmap.original 2>/dev/null || true && \
    ln -sf /app/tools/nmap-wrapper.sh /usr/bin/nmap && \
    mv /usr/bin/sniper /usr/bin/sniper.original 2>/dev/null || true && \
    ln -sf /app/tools/sniper-wrapper.sh /usr/bin/sniper

# Fix Sn1per to work in restricted environment
RUN sed -i 's|/usr/lib/nmap/nmap|/usr/bin/nmap|g' /usr/bin/sniper.original 2>/dev/null || true && \
    sed -i 's|sudo nmap|nmap|g' /usr/bin/sniper.original 2>/dev/null || true && \
    sed -i 's|parallel -j|parallel -j 1|g' /usr/bin/sniper.original 2>/dev/null || true

EXPOSE 8080

# Create a startup script to handle permissions and optimize performance
RUN echo '#!/bin/bash\n\
# Start PostgreSQL\n\
service postgresql start 2>/dev/null || true\n\
# Create writable directories\n\
mkdir -p /tmp/sniper-work && chmod 777 /tmp/sniper-work\n\
# Set conservative limits for Railway\n\
ulimit -n 1024 2>/dev/null || true\n\
ulimit -u 100 2>/dev/null || true\n\
# Start the application with simple stable configuration\n\
exec gunicorn --bind 0.0.0.0:${PORT:-8080} --workers 1 --timeout 600 --log-level info app:app' > /app/start.sh && \
    chmod +x /app/start.sh

CMD ["/app/start.sh"]