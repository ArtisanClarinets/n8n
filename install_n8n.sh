#!/bin/bash

# ==============================================================================
# n8n Self-Hosted Installer for Ubuntu 22.04 LTS
#
# This script installs Docker, Traefik, PostgreSQL, and n8n in a production-ready
# configuration with automatic SSL/TLS via Let's Encrypt.
# ==============================================================================

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO] $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}[WARN] $1${NC}"
}

log_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# 1. System Prep & Root Check
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Please use sudo."
        exit 1
    fi
}

update_system() {
    log_info "Updating system packages..."
    # Update package list and upgrade packages
    apt-get update && apt-get upgrade -y

    log_info "Installing dependencies..."
    # Install required dependencies for Docker and general system utilities
    apt-get install -y curl wget gnupg git ca-certificates lsb-release
}

install_docker() {
    # Check if Docker is already installed
    if ! command -v docker &> /dev/null; then
        log_info "Docker not found. Installing Docker..."

        # Add Docker's official GPG key:
        mkdir -p /etc/apt/keyrings
        if [ -f /etc/apt/keyrings/docker.gpg ]; then
            rm /etc/apt/keyrings/docker.gpg
        fi
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg

        # Add the repository to Apt sources:
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
          $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
          tee /etc/apt/sources.list.d/docker.list > /dev/null

        apt-get update
        # Install Docker Engine, CLI, containerd, and Compose plugin
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    else
        log_info "Docker is already installed."
    fi

    # Ensure Docker Compose (plugin) is available
    if ! docker compose version &> /dev/null; then
        log_error "Docker Compose plugin not found. Please verify Docker installation."
        exit 1
    fi

    log_info "Docker and Docker Compose are installed successfully."
}

# 2. User Input
get_user_input() {
    echo ""
    echo -e "${YELLOW}Please provide the configuration details:${NC}"

    while [[ -z "$DOMAIN_NAME" ]]; do
        read -p "Enter the Domain Name for n8n (e.g., n8n.example.com): " DOMAIN_NAME
    done

    while [[ -z "$EMAIL_ADDRESS" ]]; do
        read -p "Enter your Email Address (for Let's Encrypt SSL): " EMAIL_ADDRESS
    done
}

# 3. Configuration & Secrets
setup_directories_and_secrets() {
    INSTALL_DIR="/opt/n8n"
    log_info "Creating installation directory at $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"

    # Generate robust secrets
    N8N_ENCRYPTION_KEY=$(openssl rand -hex 16)
    POSTGRES_PASSWORD=$(openssl rand -hex 16)
    POSTGRES_USER="n8n"
    POSTGRES_DB="n8n"

    log_info "Generated N8N_ENCRYPTION_KEY and POSTGRES_PASSWORD."
}

# 4. Docker Setup
create_docker_compose() {
    log_info "Generating docker-compose.yml..."

    # Create the docker-compose.yml file with Traefik, Postgres, and n8n
    cat <<EOF > "$INSTALL_DIR/docker-compose.yml"
services:
  traefik:
    image: traefik:v3.0
    command:
      # Enable Docker provider
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      # Entry points for HTTP and HTTPS
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      # Redirect HTTP to HTTPS
      - "--entrypoints.web.http.redirections.entryPoint.to=websecure"
      - "--entrypoints.web.http.redirections.entryPoint.scheme=https"
      # Let's Encrypt Resolver Configuration (TLS Challenge)
      - "--certificatesresolvers.myresolver.acme.tlschallenge=true"
      - "--certificatesresolvers.myresolver.acme.email=${EMAIL_ADDRESS}"
      - "--certificatesresolvers.myresolver.acme.storage=/letsencrypt/acme.json"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "traefik_data:/letsencrypt"
    networks:
      - n8n-net
    restart: always

  postgres:
    image: postgres:16
    restart: always
    environment:
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_DB=${POSTGRES_DB}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - n8n-net
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -h localhost -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 5s
      timeout: 5s
      retries: 10

  n8n:
    image: n8nio/n8n:latest
    restart: always
    environment:
      - DB_TYPE=postgresdb
      - DB_POSTGRESDB_HOST=postgres
      - DB_POSTGRESDB_PORT=5432
      - DB_POSTGRESDB_DATABASE=${POSTGRES_DB}
      - DB_POSTGRESDB_USER=${POSTGRES_USER}
      - DB_POSTGRESDB_PASSWORD=${POSTGRES_PASSWORD}
      - N8N_ENCRYPTION_KEY=${N8N_ENCRYPTION_KEY}
      - N8N_HOST=${DOMAIN_NAME}
      - N8N_PORT=5678
      - N8N_PROTOCOL=https
      - WEBHOOK_URL=https://${DOMAIN_NAME}/
      - GENERIC_TIMEZONE=UTC
    ports:
      # Expose locally for health checks
      - "127.0.0.1:5678:5678"
    links:
      - postgres
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - n8n_data:/home/node/.n8n
    networks:
      - n8n-net
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.n8n.rule=Host(\`${DOMAIN_NAME}\`)"
      - "traefik.http.routers.n8n.entrypoints=websecure"
      - "traefik.http.routers.n8n.tls=true"
      - "traefik.http.routers.n8n.tls.certresolver=myresolver"
      - "traefik.http.services.n8n.loadbalancer.server.port=5678"

volumes:
  n8n_data:
  postgres_data:
  traefik_data:

networks:
  n8n-net:
EOF
}

# 5. Systemd Integration
setup_systemd() {
    log_info "Creating systemd service at /etc/systemd/system/n8n-compose.service..."

    # Create systemd unit file
    cat <<EOF > /etc/systemd/system/n8n-compose.service
[Unit]
Description=n8n Docker Compose Service
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$INSTALL_DIR
# Start the compose stack
ExecStart=/usr/bin/docker compose up -d --remove-orphans
# Stop the compose stack
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd to recognize the new service
    systemctl daemon-reload
    # Enable the service to start on boot
    systemctl enable n8n-compose.service

    log_info "Starting n8n service..."
    # Start the service immediately
    systemctl start n8n-compose.service
}

# 6. Verification & Health Check
verify_installation() {
    log_info "Waiting for n8n to start (this may take a minute)..."

    # Simple loop to check health
    # Note: n8n usually takes a bit to migrate DB and start
    local retries=30
    local wait=5
    local success=0

    for ((i=1; i<=retries; i++)); do
        # We check localhost:5678/healthz because we mapped it to 127.0.0.1 in compose
        if curl -s -f http://127.0.0.1:5678/healthz > /dev/null 2>&1; then
            success=1
            break
        fi
        echo -n "."
        sleep $wait
    done
    echo ""

    if [[ $success -eq 1 ]]; then
        log_info "n8n is running and healthy!"
    else
        log_error "n8n failed to start within the timeout period."
        log_error "Please check logs with: cd $INSTALL_DIR && docker compose logs"
        exit 1
    fi
}

# 7. Final Output
show_summary() {
    # Clear screen for a clean summary
    clear
    echo -e "${GREEN}======================================================${NC}"
    echo -e "${GREEN}       n8n Installation Completed Successfully!       ${NC}"
    echo -e "${GREEN}======================================================${NC}"
    echo ""
    echo -e "Access your n8n instance at: ${YELLOW}https://${DOMAIN_NAME}${NC}"
    echo ""
    echo -e "Initial Setup:"
    echo -e "  Open the URL above and follow the on-screen instructions to create the first user."
    echo ""
    echo -e "${RED}IMPORTANT SECRETS (Save these!):${NC}"
    echo -e "  Encryption Key (N8N_ENCRYPTION_KEY): ${YELLOW}${N8N_ENCRYPTION_KEY}${NC}"
    echo -e "  Postgres User: ${YELLOW}${POSTGRES_USER}${NC}"
    echo -e "  Postgres Password: ${YELLOW}${POSTGRES_PASSWORD}${NC}"
    echo ""
    echo -e "Configuration Directory: ${INSTALL_DIR}"
    echo -e "Service Status: systemctl status n8n-compose"
    echo ""
}

# Main Execution Flow
check_root
get_user_input
update_system
install_docker
setup_directories_and_secrets
create_docker_compose
setup_systemd
verify_installation
show_summary
