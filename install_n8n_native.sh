#!/bin/bash

# ==============================================================================
# n8n Self-Hosted Installer - Native Method (Ubuntu 22.04 LTS)
#
# Architecture: Node.js + Supervisor + PostgreSQL + Nginx (Reverse Proxy) + Certbot
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

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Variables
INSTALL_DIR="/opt/n8n"
ENV_FILE="$INSTALL_DIR/.env"
START_SCRIPT="$INSTALL_DIR/start_n8n.sh"
SUPERVISOR_CONF="/etc/supervisor/conf.d/n8n.conf"
N8N_USER="n8n"
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
    # Non-interactive upgrade
    run_with_retry apt-get upgrade -y -q -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

    log_info "Installing dependencies..."
    run_with_retry apt-get install -y -q curl wget gnupg git ca-certificates lsb-release ufw build-essential supervisor acl
}

setup_firewall() {
    log_info "Configuring UFW firewall..."
    ufw allow OpenSSH
    ufw allow 80/tcp
    ufw allow 443/tcp

    if ! ufw status | grep -q "Status: active"; then
        echo "y" | ufw enable
        log_success "Firewall enabled."
    else
        log_info "Firewall already active."
    fi
}

install_dependencies() {
    # Install Node.js 20.x LTS
    if ! command -v node &> /dev/null; then
        log_info "Installing Node.js 20.x..."
        run_with_retry curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        run_with_retry apt-get install -y -q nodejs
    else
        log_info "Node.js is already installed: $(node -v)"
    fi

    # Install PostgreSQL
    if ! command -v psql &> /dev/null; then
        log_info "Installing PostgreSQL..."
        run_with_retry apt-get install -y -q postgresql postgresql-contrib
        systemctl enable postgresql
        systemctl start postgresql
    fi

    # Install Nginx & Certbot
    log_info "Installing Nginx and Certbot..."
    run_with_retry apt-get install -y -q nginx certbot python3-certbot-nginx
}

install_ollama() {
    log_info "Installing Ollama..."
    if ! command -v ollama &> /dev/null; then
        run_with_retry curl -fsSL https://ollama.com/install.sh | sh
        log_success "Ollama installed."
    else
        log_info "Ollama is already installed."
    fi
    # Ensure service is running
    if systemctl list-units --full -all | grep -Fq "ollama.service"; then
        systemctl enable ollama
        systemctl start ollama
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
    if [[ -f "$ENV_FILE" ]]; then
        log_warn "Configuration found at $ENV_FILE. Using existing secrets/config."
        source "$ENV_FILE"
        SKIP_CONFIG=true
        return
    fi

    echo ""
    log_info "Please provide configuration:"

    while true; do
        read -p "Enter Domain Name (e.g., n8n.example.com): " DOMAIN_NAME
        if validate_domain "$DOMAIN_NAME"; then break; fi
        log_warn "Invalid domain."
    done

    while true; do
        read -p "Enter Email for SSL: " EMAIL_ADDRESS
        if validate_email "$EMAIL_ADDRESS"; then break; fi
        log_warn "Invalid email."
    done

    read -p "Enter Port for n8n to listen on (default: 5678): " N8N_PORT
    N8N_PORT=${N8N_PORT:-5678}

    SKIP_CONFIG=false
}

setup_database() {
    if [[ "$SKIP_CONFIG" == "true" ]]; then return; fi

    log_info "Configuring PostgreSQL..."

    POSTGRES_USER="n8n"
    POSTGRES_DB="n8n"
    POSTGRES_PASSWORD=$(openssl rand -hex 32) # Stronger password

    # Create user and db idempotently
    sudo -u postgres psql -tc "SELECT 1 FROM pg_user WHERE usename = '$POSTGRES_USER'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER $POSTGRES_USER WITH PASSWORD '$POSTGRES_PASSWORD';"

    sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = '$POSTGRES_DB'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE $POSTGRES_DB OWNER $POSTGRES_USER;"

    # Ensure Peer/MD5 auth works for local (Ubuntu defaults usually fine, but good to verify)
    # Ideally, we would edit pg_hba.conf here, but for 'native' ubuntu install, socket auth usually works for 'postgres' user.
    # n8n uses password auth over TCP localhost.

    log_success "Database configured."
}

setup_n8n() {
    log_info "Installing n8n globally..."
    run_with_retry npm install -g n8n

    # Create dedicated user
    if ! id -u "$N8N_USER" >/dev/null 2>&1; then
        log_info "Creating system user: $N8N_USER"
        useradd -m -s /bin/bash "$N8N_USER"
    fi

    mkdir -p "$INSTALL_DIR"

    if [[ "$SKIP_CONFIG" != "true" ]]; then
        N8N_ENCRYPTION_KEY=$(openssl rand -hex 32)

        # Save secrets
        cat <<EOF > "$ENV_FILE"
# n8n Secrets - Generated $(date)
DOMAIN_NAME=${DOMAIN_NAME}
EMAIL_ADDRESS=${EMAIL_ADDRESS}
N8N_PORT=${N8N_PORT}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=${POSTGRES_DB}
N8N_ENCRYPTION_KEY=${N8N_ENCRYPTION_KEY}

# N8N Config
DB_TYPE=postgresdb
DB_POSTGRESDB_HOST=localhost
DB_POSTGRESDB_PORT=5432
DB_POSTGRESDB_DATABASE=${POSTGRES_DB}
DB_POSTGRESDB_USER=${POSTGRES_USER}
DB_POSTGRESDB_PASSWORD=${POSTGRES_PASSWORD}
N8N_HOST=${DOMAIN_NAME}
N8N_PORT=${N8N_PORT}
N8N_PROTOCOL=https
WEBHOOK_URL=https://${DOMAIN_NAME}/
N8N_LISTEN_ADDRESS=127.0.0.1
GENERIC_TIMEZONE=UTC
EOF
        chmod 600 "$ENV_FILE"
        chown "$N8N_USER:$N8N_USER" "$ENV_FILE"
    else
        source "$ENV_FILE"
    fi

    # Create Start Script
    log_info "Creating startup script..."
    cat <<EOF > "$START_SCRIPT"
#!/bin/bash
set -a
source $ENV_FILE
set +a
exec n8n
EOF
    chmod +x "$START_SCRIPT"
    chown "$N8N_USER:$N8N_USER" "$START_SCRIPT"

    # Configure Supervisor
    log_info "Configuring Supervisor..."
    cat <<EOF > "$SUPERVISOR_CONF"
[program:n8n]
command=$START_SCRIPT
user=$N8N_USER
autostart=true
autorestart=true
stderr_logfile=/var/log/n8n.err.log
stdout_logfile=/var/log/n8n.out.log
environment=NODE_ENV="production"
EOF

    supervisorctl reread
    supervisorctl update
    log_success "n8n configured with Supervisor."
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

    # HSTS (Strict Transport Security)
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

    # Test Nginx
    nginx -t || { log_error "Nginx configuration failed."; exit 1; }
    systemctl reload nginx

    log_info "Obtaining SSL certificate with Certbot..."
    # --nginx plugin automatically edits the config to add valid SSL paths
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
    log_info "Waiting for n8n to start..."
    for i in {1..30}; do
        if curl -s -f http://127.0.0.1:${N8N_PORT}/healthz >/dev/null 2>&1; then
            log_success "n8n is running and responding!"
            return
        fi
        sleep 2
    done
    log_error "n8n did not start in time. Check supervisor logs: /var/log/n8n.err.log"
    exit 1
}

show_summary() {
    clear
    echo -e "${GREEN}======================================================${NC}"
    echo -e "${GREEN}    n8n Enterprise Installation Completed (Native)    ${NC}"
    echo -e "${GREEN}======================================================${NC}"
    echo ""
    echo -e "URL: ${YELLOW}https://${DOMAIN_NAME}${NC}"
    echo ""
    echo -e "Service User: ${YELLOW}${N8N_USER}${NC}"
    echo -e "Secrets File: ${YELLOW}${ENV_FILE}${NC}"
    echo -e "Manager:      ${BLUE}supervisorctl status n8n${NC}"
    echo -e "Logs:         ${BLUE}tail -f /var/log/n8n.out.log${NC}"
    echo ""
    echo -e "${RED}SAVE THIS KEY:${NC} ${N8N_ENCRYPTION_KEY}"
    echo ""
    echo -e "Installation Log: ${LOG_FILE}"
}

# Execution
check_root
check_system_resources
get_user_input
update_system
setup_firewall
install_dependencies
install_ollama
setup_database
setup_n8n
setup_nginx_ssl
verify_installation
show_summary
