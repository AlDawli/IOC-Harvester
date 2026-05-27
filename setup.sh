#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# IOC Harvester — Setup Script
# Installs dependencies, creates virtualenv, and initialises config.
# Usage: bash setup.sh [--dev] [--docker] [--no-venv]
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Banner ────────────────────────────────────────────────────
echo -e "${BOLD}"
cat <<'EOF'
╔══════════════════════════════════════════════╗
║          IOC HARVESTER  —  Setup             ║
║   Threat Intelligence Aggregator v1.0.0      ║
╚══════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# ── Parse arguments ───────────────────────────────────────────
MODE_DEV=false
MODE_DOCKER=false
NO_VENV=false
for arg in "$@"; do
    case $arg in
        --dev)    MODE_DEV=true ;;
        --docker) MODE_DOCKER=true ;;
        --no-venv) NO_VENV=true ;;
        -h|--help)
            echo "Usage: bash setup.sh [--dev] [--docker] [--no-venv]"
            echo "  --dev      Install development dependencies (pytest, ruff, mypy)"
            echo "  --docker   Set up Docker environment instead of Python venv"
            echo "  --no-venv  Install globally (not recommended)"
            exit 0 ;;
        *) warn "Unknown argument: $arg" ;;
    esac
done

# ── System checks ─────────────────────────────────────────────
info "Checking system requirements …"

if $MODE_DOCKER; then
    command -v docker >/dev/null 2>&1 || error "Docker not found. Install from https://docs.docker.com/get-docker/"
    command -v docker compose >/dev/null 2>&1 || \
        docker compose version >/dev/null 2>&1 || \
        error "Docker Compose not found."
    success "Docker $(docker --version | cut -d' ' -f3 | tr -d ',')"
else
    # Python check
    PY=$(command -v python3.12 || command -v python3.11 || command -v python3 || true)
    [[ -z "$PY" ]] && error "Python 3.11+ not found. Install from https://python.org"

    PY_VER=$($PY -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
    [[ $PY_MAJOR -lt 3 || ($PY_MAJOR -eq 3 && $PY_MINOR -lt 11) ]] && \
        error "Python 3.11+ required (found $PY_VER)"
    success "Python $PY_VER ($PY)"
fi

# ── Docker path ───────────────────────────────────────────────
if $MODE_DOCKER; then
    info "Building Docker image …"
    docker compose build

    info "Creating output directory …"
    mkdir -p output

    if [[ ! -f .env ]]; then
        info "Creating .env from .env.example …"
        if [[ -f .env.example ]]; then
            cp .env.example .env
        else
            cat > .env <<'ENVEOF'
# IOC Harvester — Environment Variables
# Copy to .env and fill in your API keys.

OTX_API_KEY=
THREATFOX_API_KEY=
LOG_LEVEL=INFO
OUTPUT_DIR=/app/output
ENVEOF
        fi
        warn "Edit .env and add your API keys, then run: docker compose run --rm ioc-harvester"
    fi

    echo ""
    success "Docker setup complete!"
    echo ""
    echo -e "  ${BOLD}Quick start:${NC}"
    echo "    docker compose run --rm ioc-harvester"
    echo ""
    echo -e "  ${BOLD}Scheduled mode:${NC}"
    echo "    docker compose --profile scheduled up -d"
    exit 0
fi

# ── Python virtualenv setup ───────────────────────────────────
VENV_DIR=".venv"

if ! $NO_VENV; then
    if [[ ! -d "$VENV_DIR" ]]; then
        info "Creating virtual environment in $VENV_DIR …"
        $PY -m venv "$VENV_DIR"
    fi
    # shellcheck disable=SC1090
    source "$VENV_DIR/bin/activate"
    PY="$VENV_DIR/bin/python"
    PIP="$VENV_DIR/bin/pip"
    success "Virtual environment activated"
else
    PIP=$(command -v pip3 || command -v pip)
    warn "Installing globally (--no-venv flag set)"
fi

# ── Install dependencies ──────────────────────────────────────
info "Upgrading pip …"
$PIP install --quiet --upgrade pip

if $MODE_DEV; then
    info "Installing package with development dependencies …"
    $PIP install --quiet -e ".[dev]"
    success "Dev dependencies installed (pytest, ruff, mypy, respx)"
else
    info "Installing package …"
    $PIP install --quiet -e .
fi
success "ioc-harvester installed"

# ── Configuration ─────────────────────────────────────────────
if [[ ! -f config.yml ]]; then
    info "Generating default config.yml …"
    "$VENV_DIR/bin/ioc-harvester" init --output config.yml 2>/dev/null || \
        $PY -c "from ioc_harvester.config import DEFAULT_CONFIG_YAML; open('config.yml','w').write(DEFAULT_CONFIG_YAML)"
    success "config.yml created"
else
    warn "config.yml already exists — skipping"
fi

# ── Output directory ──────────────────────────────────────────
mkdir -p output/{sigma,firewall}
success "Output directories created: output/, output/sigma/, output/firewall/"

# ── Run tests (dev mode only) ─────────────────────────────────
if $MODE_DEV; then
    info "Running test suite …"
    "$VENV_DIR/bin/pytest" tests/ -v --tb=short 2>&1 | tail -20
fi

# ── Done ──────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}Setup complete!${NC}"
echo ""
echo -e "  ${BOLD}Activate venv:${NC}"
echo "    source .venv/bin/activate"
echo ""
echo -e "  ${BOLD}Add API keys to config.yml:${NC}"
echo "    otx:       api_key: YOUR_OTX_KEY"
echo "    threatfox: api_key: YOUR_THREATFOX_KEY"
echo ""
echo -e "  ${BOLD}Run the harvester:${NC}"
echo "    ioc-harvester run -c config.yml"
echo ""
echo -e "  ${BOLD}View available sources:${NC}"
echo "    ioc-harvester sources"
echo ""
