FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

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
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

RUN git clone https://github.com/1n3/sn1per.git

WORKDIR /opt/sn1per

RUN bash install.sh

RUN pip3 install --break-system-packages flask flask-cors gunicorn

WORKDIR /app

COPY app.py .
COPY templates/ templates/

EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--timeout", "300", "app:app"]