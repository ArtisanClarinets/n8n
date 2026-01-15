#!/bin/bash

# ==============================================================================
# n8n Self-Hosted Installer for Ubuntu 22.04 LTS (Enterprise Grade)
#
# Architecture: Docker Compose (n8n, Postgres, Ollama) + Host Nginx
#
# Standards: Fortune-500 Level (Hardened, Idempotent, Resilient)
# Features:
# - Hardware Pre-flight checks
# - Retry logic for network operations
# - Hardened Nginx SSL/TLS config
# - Structured audit logging
# - Self-healing firewall and service states
# ==============================================================================

set -e
set -o pipefail

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global Variables
INSTALL_DIR="/opt/n8n"
ENV_FILE="$INSTALL_DIR/.env"
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"
SERVICE_FILE="/etc/systemd/system/n8n-compose.service"
LOG_FILE="/var/log/n8n_install.log"

# --- Logging & Error Handling ---

log() {
    local level=$1
    local msg=$2
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${msg}" | tee -a "$LOG_FILE"
}

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; log "INFO" "$1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; log "SUCCESS" "$1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; log "WARN" "$1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; log "ERROR" "$1"; }

error_handler() {
    local line_no=$1
    local command=$2
    log_error "Failed at line $line_no: $command"
    log_info "Check audit log at $LOG_FILE for details."
}
trap 'error_handler $LINENO "$BASH_COMMAND"' ERR

run_with_retry() {
    local n=1
    local max=5
    local delay=5
    while true; do
        "$@" && break || {
            if [[ $n -lt $max ]]; then
                ((n++))
                log_warn "Command failed. Attempt $n/$max:"
                sleep $delay;
            else
                log_error "The command has failed after $max attempts."
                return 1
            fi
        }
    done
}

# --- Pre-flight Checks ---

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Please use sudo."
        exit 1
    fi
}

check_system_resources() {
    log_info "Performing hardware pre-flight checks..."

    # RAM Check (Min 4GB recommended for Ollama+n8n)
    local total_mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local total_mem_gb=$((total_mem_kb / 1024 / 1024))

    if [[ $total_mem_gb -lt 4 ]]; then
        log_warn "Detected < 4GB RAM ($total_mem_gb GB). AI workloads (Ollama) may be unstable."
        read -p "Continue anyway? (y/N): " CONFIRM
        [[ "${CONFIRM,,}" != "y" ]] && exit 1
    fi

    # Disk Check (Min 10GB free)
    local free_disk_gb=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
    if [[ $free_disk_gb -lt 10 ]]; then
        log_error "Insufficient disk space. Need 10GB+, found ${free_disk_gb}GB."
        exit 1
    fi

    log_success "Hardware checks passed."
}

# --- Installation Steps ---

update_system() {
    log_info "Updating system packages..."
    run_with_retry apt-get update -q
    run_with_retry apt-get upgrade -y -q -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

    log_info "Installing system dependencies..."
    run_with_retry apt-get install -y -q curl wget gnupg git ca-certificates lsb-release ufw nginx certbot python3-certbot-nginx acl
}

setup_firewall() {
    log_info "Configuring UFW firewall..."
    # Ensure we don't lock ourselves out
    ufw allow OpenSSH
    ufw allow 80/tcp
    ufw allow 443/tcp

    # Check if UFW is already enabled to avoid disrupting active connections unnecessarily
    if ! ufw status | grep -q "Status: active"; then
        echo "y" | ufw enable
        log_success "Firewall enabled and rules applied."
    else
        log_info "Firewall is already active. Rules updated."
    fi
}

install_docker() {
    if ! command -v docker &> /dev/null; then
        log_info "Docker not found. Installing Docker..."

        mkdir -p /etc/apt/keyrings
        if [ -f /etc/apt/keyrings/docker.gpg ]; then
            rm /etc/apt/keyrings/docker.gpg
        fi
        run_with_retry curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg

        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
          $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
          tee /etc/apt/sources.list.d/docker.list > /dev/null

        run_with_retry apt-get update -q
        run_with_retry apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    else
        log_info "Docker is already installed."
    fi

    if ! docker compose version &> /dev/null; then
        log_error "Docker Compose plugin not found. Please verify Docker installation."
        exit 1
    fi
}

# --- Configuration ---

validate_domain() {
    [[ "$1" =~ ^([a-zA-Z0-9](([a-zA-Z0-9-]){0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]
}

validate_email() {
    [[ "$1" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
}

get_user_input() {
    # If secrets exist, we assume configuration is done to prevent overwriting
    if [[ -f "$ENV_FILE" ]]; then
        log_warn "Existing configuration found at $ENV_FILE."
        read -p "Do you want to overwrite it? THIS WILL GENERATE NEW SECRETS AND MAY BREAK DB ACCESS. (y/N): " OVERWRITE
        if [[ "${OVERWRITE,,}" != "y" ]]; then
            log_info "Skipping configuration generation. Using existing settings."
            source "$ENV_FILE"
            SKIP_CONFIG=true
            return
        fi
    fi

    echo ""
    log_info "Please provide the configuration details:"

    while true; do
        read -p "Enter the Domain Name for n8n (e.g., n8n.example.com): " DOMAIN_NAME
        if validate_domain "$DOMAIN_NAME"; then
            break
        else
            log_warn "Invalid domain format. Please try again."
        fi
    done

    while true; do
        read -p "Enter your Email Address (for Let's Encrypt SSL): " EMAIL_ADDRESS
        if validate_email "$EMAIL_ADDRESS"; then
            break
        else
            log_warn "Invalid email format. Please try again."
        fi
    done

    read -p "Enter Port for n8n to listen on (default: 5678): " N8N_PORT
    N8N_PORT=${N8N_PORT:-5678}

    SKIP_CONFIG=false
}

setup_configuration() {
    if [[ "$SKIP_CONFIG" == "true" ]]; then
        return
    fi

    log_info "Creating installation directory at $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"

    # Generate robust secrets
    N8N_ENCRYPTION_KEY=$(openssl rand -hex 32)
    POSTGRES_PASSWORD=$(openssl rand -hex 32)
    POSTGRES_USER="n8n"
    POSTGRES_DB="n8n"

    log_info "Generating secure .env file..."
    cat <<EOF > "$ENV_FILE"
# n8n Environment Configuration
# Generated on $(date)

DOMAIN_NAME=${DOMAIN_NAME}
SSL_EMAIL=${EMAIL_ADDRESS}
N8N_PORT=${N8N_PORT}

# Secrets
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=${POSTGRES_DB}

N8N_ENCRYPTION_KEY=${N8N_ENCRYPTION_KEY}

# Database Connection (Internal)
DB_TYPE=postgresdb
DB_POSTGRESDB_HOST=postgres
DB_POSTGRESDB_PORT=5432
EOF

    # Set strict permissions (600) so only root can read secrets
    chmod 600 "$ENV_FILE"
    log_success "Secrets generated and stored securely in $ENV_FILE."
}

create_docker_compose() {
    # Always recreate docker-compose to ensure it matches the latest template
    # (Environment variables handle the dynamic parts)

    log_info "Generating docker-compose.yml..."

    cat <<EOF > "$COMPOSE_FILE"
services:
  postgres:
    image: postgres:16-alpine
    restart: always
    environment:
      - POSTGRES_USER=\${POSTGRES_USER}
      - POSTGRES_PASSWORD=\${POSTGRES_PASSWORD}
      - POSTGRES_DB=\${POSTGRES_DB}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - n8n-net
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -h localhost -U \${POSTGRES_USER} -d \${POSTGRES_DB}"]
      interval: 5s
      timeout: 5s
      retries: 10
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  n8n:
    image: n8nio/n8n:latest
    restart: always
    environment:
      - DB_TYPE=postgresdb
      - DB_POSTGRESDB_HOST=postgres
      - DB_POSTGRESDB_PORT=5432
      - DB_POSTGRESDB_DATABASE=\${POSTGRES_DB}
      - DB_POSTGRESDB_USER=\${POSTGRES_USER}
      - DB_POSTGRESDB_PASSWORD=\${POSTGRES_PASSWORD}
      - N8N_ENCRYPTION_KEY=\${N8N_ENCRYPTION_KEY}
      - N8N_HOST=\${DOMAIN_NAME}
      - N8N_PORT=5678
      - N8N_PROTOCOL=https
      - WEBHOOK_URL=https://\${DOMAIN_NAME}/
      - GENERIC_TIMEZONE=UTC
    ports:
      - "127.0.0.1:\${N8N_PORT}:5678"
    links:
      - postgres
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - n8n_data:/home/node/.n8n
    networks:
      - n8n-net
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  ollama:
    image: ollama/ollama:latest
    restart: always
    volumes:
      - ollama_data:/root/.ollama
    networks:
      - n8n-net
    # Uncomment to enable GPU support (requires NVIDIA Container Toolkit)
    # deploy:
    #   resources:
    #     reservations:
    #       devices:
    #         - driver: nvidia
    #           count: 1
    #           capabilities: [gpu]
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  n8n_data:
  postgres_data:
  ollama_data:

networks:
  n8n-net:
EOF
}

setup_systemd() {
    log_info "Configuring systemd service..."

    cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=n8n Docker Compose Service
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/docker compose up -d --remove-orphans
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$(basename "$SERVICE_FILE")"

    log_info "Starting n8n service via systemd..."
    systemctl start "$(basename "$SERVICE_FILE")"
}

setup_nginx_ssl() {
    log_info "Configuring Nginx (Enterprise Hardened)..."

    # Ensure webroot exists for Certbot
    mkdir -p /var/www/certbot

    NGINX_CONF="/etc/nginx/sites-available/$DOMAIN_NAME"

    # Hardened Nginx Config
    cat <<EOF > "$NGINX_CONF"
server {
    listen 80;
    server_name $DOMAIN_NAME;

    # Redirect all HTTP to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN_NAME;

    # SSL Certificates (Placeholder for Certbot)
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

    # TLS Hardening
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000" always;

    # Security Headers
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    # n8n Proxy
    location / {
        proxy_pass http://127.0.0.1:${N8N_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;

        # Increase body size for file uploads
        client_max_body_size 50M;
    }
}
EOF

    ln -sf "$NGINX_CONF" "/etc/nginx/sites-enabled/"
    rm -f /etc/nginx/sites-enabled/default

    # Test and reload
    nginx -t || { log_error "Nginx configuration failed."; exit 1; }
    systemctl reload nginx

    log_info "Obtaining SSL certificate with Certbot..."
    # --nginx plugin automatically edits the config to add SSL
    run_with_retry certbot --nginx -d "$DOMAIN_NAME" --non-interactive --agree-tos --email "$EMAIL_ADDRESS" --redirect

    # Use webroot authenticator (more robust) and nginx installer
    if certbot run -a webroot -i nginx -w /var/www/certbot -d "$DOMAIN_NAME" --non-interactive --agree-tos --email "$EMAIL_ADDRESS" --redirect; then
        log_success "SSL configured successfully."
    else
        log_error "Certbot failed to obtain SSL certificate."
        log_warn "Please check that your Domain Name ($DOMAIN_NAME) points to this server's IP."
        log_warn "Ensure that ports 80 and 443 are open in your firewall (and cloud provider firewall)."
        exit 1
    fi
}

verify_installation() {
    log_info "Waiting for n8n to start (this may take up to 60 seconds)..."

    local retries=30
    local wait=2
    local success=0

    for ((i=1; i<=retries; i++)); do
        # Check health endpoint on local loopback
        if curl -s -f http://127.0.0.1:${N8N_PORT}/healthz > /dev/null 2>&1; then
            success=1
            break
        fi
        sleep $wait
    done

    if [[ $success -eq 1 ]]; then
        log_success "n8n is running and healthy!"
    else
        log_error "n8n failed to start within the timeout period."
        log_error "Please check logs with: cd $INSTALL_DIR && docker compose logs"
        exit 1
    fi
}

show_summary() {
    # Load env variables for display if we skipped config
    if [[ "$SKIP_CONFIG" == "true" ]]; then
        source "$ENV_FILE"
    fi

    clear
    echo -e "${GREEN}======================================================${NC}"
    echo -e "${GREEN}    n8n Enterprise Installation Completed (Docker)    ${NC}"
    echo -e "${GREEN}======================================================${NC}"
    echo ""
    echo -e "Access your n8n instance at: ${YELLOW}https://${DOMAIN_NAME}${NC}"
    echo ""
    echo -e "Initial Setup:"
    echo -e "  1. Open the URL above."
    echo -e "  2. Follow the on-screen instructions to create the first user."
    echo ""
    echo -e "${RED}IMPORTANT SECRETS:${NC}"
    echo -e "  Your secrets are stored securely in: ${YELLOW}${ENV_FILE}${NC}"
    echo -e "  To view them, run: ${BLUE}cat ${ENV_FILE}${NC}"
    echo ""
    echo -e "Encryption Key (Save this!): ${YELLOW}${N8N_ENCRYPTION_KEY}${NC}"
    echo ""
    echo -e "Service Management:"
    echo -e "  Status:  ${BLUE}systemctl status n8n-compose${NC}"
    echo -e "  Logs:    ${BLUE}cd $INSTALL_DIR && docker compose logs -f${NC}"
    echo -e "  Stop:    ${BLUE}systemctl stop n8n-compose${NC}"
    echo ""
    echo -e "Installation Log: ${LOG_FILE}"
}

# Main Execution Flow
check_root
check_system_resources
get_user_input
update_system
setup_firewall
install_docker
setup_configuration
create_docker_compose
setup_systemd
setup_nginx_ssl
verify_installation
show_summary
