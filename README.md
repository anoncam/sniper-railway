# Sn1per Railway Deployment

Web interface for the Sn1per attack surface management platform, designed for deployment on Railway.

## Features

- Web-based interface for Sn1per scanning tools
- Multiple scan types (Normal, Stealth, Web, Port, OSINT, Recon, Vuln)
- Real-time scan progress monitoring
- Scan history and result downloads
- Containerized deployment with Docker

## Deployment to Railway

1. Fork or clone this repository
2. Connect your GitHub repository to Railway
3. Railway will automatically detect the Dockerfile and deploy the application
4. Access the web interface through the provided Railway URL

## Local Testing

```bash
docker-compose up --build
```

Access the interface at http://localhost:8080

## Security Notice

This tool is for authorized security testing only. Ensure you have explicit permission before scanning any targets. Unauthorized scanning may violate laws and terms of service.

## Scan Types

- **Normal**: Full scan with active tests
- **Stealth**: Passive reconnaissance
- **Web**: Web application focused scanning
- **Port**: Port scanning only
- **Full Port**: Scan all 65535 ports
- **OSINT**: Open source intelligence gathering
- **Recon**: Reconnaissance only
- **Vuln Scan**: Vulnerability scanning

## Environment Variables

- `PORT`: Server port (default: 8080)
- `SECRET_KEY`: Flask session secret key (auto-generated on Railway)