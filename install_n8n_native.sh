#!/bin/bash

# ==============================================================================
# n8n Self-Hosted Installer - Native Method (Ubuntu 22.04 LTS)
#
# Architecture: Node.js + Supervisor + PostgreSQL + Nginx (Reverse Proxy) + Certbot
#
# This script installs n8n directly on the OS ("bare metal") without Docker.
# It uses Supervisor for process management and Nginx for SSL termination.
# ==============================================================================

set -e

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

# Logging
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    if [ $? -ne 0 ]; then
        log_error "Script failed. Check permissions and logs."
    fi
}
trap cleanup EXIT

# 1. System Prep & Root Check
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Please use sudo."
        exit 1
    fi
}

update_system() {
    log_info "Updating system packages..."
    apt-get update -q && apt-get upgrade -y -q
    apt-get install -y -q curl wget gnupg git ca-certificates lsb-release ufw build-essential supervisor
}

setup_firewall() {
    log_info "Configuring UFW firewall..."
    ufw allow OpenSSH
    ufw allow 80/tcp
    ufw allow 443/tcp

    if ! ufw status | grep -q "Status: active"; then
        echo "y" | ufw enable
        log_success "Firewall enabled."
    fi
}

# 2. Install Node.js & Postgres & Nginx
install_dependencies() {
    # Install Node.js 20.x LTS
    if ! command -v node &> /dev/null; then
        log_info "Installing Node.js 20.x..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y -q nodejs
    else
        log_info "Node.js is already installed: $(node -v)"
    fi

    # Install PostgreSQL
    if ! command -v psql &> /dev/null; then
        log_info "Installing PostgreSQL..."
        apt-get install -y -q postgresql postgresql-contrib
    fi

    # Install Nginx & Certbot
    log_info "Installing Nginx and Certbot..."
    apt-get install -y -q nginx certbot python3-certbot-nginx
}

install_ollama() {
    log_info "Installing Ollama..."
    if ! command -v ollama &> /dev/null; then
        curl -fsSL https://ollama.com/install.sh | sh
        log_success "Ollama installed successfully."
    else
        log_info "Ollama is already installed."
    fi
}

# 3. User Input
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

# 4. Database Setup
setup_database() {
    if [[ "$SKIP_CONFIG" == "true" ]]; then return; fi

    log_info "Configuring PostgreSQL..."

    POSTGRES_USER="n8n"
    POSTGRES_DB="n8n"
    POSTGRES_PASSWORD=$(openssl rand -hex 16)

    # Create user and db if they don't exist
    sudo -u postgres psql -tc "SELECT 1 FROM pg_user WHERE usename = '$POSTGRES_USER'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER $POSTGRES_USER WITH PASSWORD '$POSTGRES_PASSWORD';"

    sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = '$POSTGRES_DB'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE $POSTGRES_DB OWNER $POSTGRES_USER;"

    log_success "Database configured."
}

# 5. App Setup (n8n + Supervisor)
setup_n8n() {
    log_info "Installing n8n globally..."
    npm install -g n8n

    # Create dedicated user
    if ! id -u "$N8N_USER" >/dev/null 2>&1; then
        log_info "Creating system user: $N8N_USER"
        useradd -m -s /bin/bash "$N8N_USER"
    fi

    mkdir -p "$INSTALL_DIR"

    if [[ "$SKIP_CONFIG" != "true" ]]; then
        N8N_ENCRYPTION_KEY=$(openssl rand -hex 16)

        # Save secrets
        cat <<EOF > "$ENV_FILE"
# n8n Secrets
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

# 6. Nginx & SSL
setup_nginx_ssl() {
    log_info "Configuring Nginx..."

    # Ensure webroot exists for Certbot
    mkdir -p /var/www/certbot

    NGINX_CONF="/etc/nginx/sites-available/$DOMAIN_NAME"

    # Basic HTTP config with ACME Challenge Support
    cat <<EOF > "$NGINX_CONF"
server {
    listen 80;
    server_name $DOMAIN_NAME;

    # ACME Challenge for Certbot (Webroot Method)
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        proxy_pass http://127.0.0.1:${N8N_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;

        # Security Headers
        add_header X-Frame-Options SAMEORIGIN;
        add_header X-Content-Type-Options nosniff;
    }
}
EOF

    ln -sf "$NGINX_CONF" "/etc/nginx/sites-enabled/"
    rm -f /etc/nginx/sites-enabled/default

    # Test and reload
    if ! nginx -t; then
        log_error "Nginx configuration test failed. Please check the config."
        exit 1
    fi
    systemctl reload nginx

    log_info "Obtaining SSL certificate with Certbot..."

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

# 7. Verification
verify_installation() {
    log_info "Waiting for n8n to start..."
    for i in {1..30}; do
        if curl -s -f http://127.0.0.1:${N8N_PORT}/healthz >/dev/null 2>&1; then
            log_success "n8n is running!"
            return
        fi
        sleep 2
    done
    log_error "n8n did not start in time. Check supervisor logs: /var/log/n8n.err.log"
    exit 1
}

# 8. Summary
show_summary() {
    clear
    echo -e "${GREEN}======================================================${NC}"
    echo -e "${GREEN}    n8n Native Installation Completed Successfully!   ${NC}"
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
}

# Execution
check_root
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
