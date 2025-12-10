#!/bin/bash
# Security Hardening Agentless - Automated Setup Script for Linux Server
# This script automates the setup process described in README.md

set -e

echo "🚀 Security Hardening Agentless - Setup Script"
echo "================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check if running as root (not recommended but check)
if [ "$EUID" -eq 0 ]; then 
   echo -e "${YELLOW}⚠️  Warning: Running as root. Consider using a non-root user.${NC}"
   read -p "Continue anyway? (y/N): " -n 1 -r
   echo
   if [[ ! $REPLY =~ ^[Yy]$ ]]; then
       exit 1
   fi
fi

# Step 1: Check Python
echo -e "\n${BLUE}[1/6]${NC} Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 is not installed.${NC}"
    echo "Please install Python 3.9 or higher:"
    echo "  Ubuntu/Debian: sudo apt install python3 python3-pip python3-venv"
    echo "  CentOS/RHEL: sudo dnf install python39 python39-pip"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo -e "${GREEN}✅ Python $PYTHON_VERSION found${NC}"

# Step 2: Check Docker
echo -e "\n${BLUE}[2/6]${NC} Checking Docker installation..."
if command -v docker &> /dev/null; then
    echo -e "${GREEN}✅ Docker found${NC}"
    DOCKER_AVAILABLE=true
    
    if command -v docker-compose &> /dev/null || docker compose version &> /dev/null 2>/dev/null; then
        echo -e "${GREEN}✅ Docker Compose found${NC}"
        COMPOSE_AVAILABLE=true
    else
        echo -e "${YELLOW}⚠️  Docker Compose not found.${NC}"
        COMPOSE_AVAILABLE=false
    fi
else
    echo -e "${YELLOW}⚠️  Docker not found. MongoDB setup will be skipped.${NC}"
    echo "   You can install Docker later and run: docker compose up -d mongodb"
    DOCKER_AVAILABLE=false
    COMPOSE_AVAILABLE=false
fi

# Step 3: Setup Python Virtual Environment
echo -e "\n${BLUE}[3/6]${NC} Setting up Python virtual environment..."
cd backend
if [ -d ".venv" ]; then
    echo -e "${YELLOW}⚠️  Virtual environment already exists.${NC}"
    read -p "Remove and recreate? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf .venv
        echo -e "${GREEN}✅ Old virtual environment removed${NC}"
    fi
fi

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo -e "${GREEN}✅ Virtual environment created${NC}"
fi

source .venv/bin/activate

# Step 4: Install Dependencies
echo -e "\n${BLUE}[4/6]${NC} Installing Python dependencies..."
pip install --upgrade pip --quiet
pip install -r requirements.txt
echo -e "${GREEN}✅ Dependencies installed${NC}"

# Step 5: Setup MongoDB
if [ "$COMPOSE_AVAILABLE" = true ]; then
    echo -e "\n${BLUE}[5/6]${NC} Setting up MongoDB with Docker Compose..."
    cd ..
    
    # Check if MongoDB container is already running
    if docker ps | grep -q security_hardening_mongodb; then
        echo -e "${YELLOW}⚠️  MongoDB container is already running.${NC}"
        read -p "Restart MongoDB? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            docker compose down mongodb
            docker compose up -d mongodb
        fi
    else
        docker compose up -d mongodb
    fi
    
    echo -e "${GREEN}✅ MongoDB container started${NC}"
    echo -e "${YELLOW}⏳ Waiting for MongoDB to be ready...${NC}"
    
    # Wait for MongoDB to be healthy
    MAX_RETRIES=30
    RETRY_COUNT=0
    while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
        if docker compose exec -T mongodb mongosh --eval "db.runCommand('ping').ok" --quiet > /dev/null 2>&1; then
            echo -e "${GREEN}✅ MongoDB is ready!${NC}"
            break
        fi
        RETRY_COUNT=$((RETRY_COUNT + 1))
        echo -n "."
        sleep 2
    done
    echo ""
    
    if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
        echo -e "${RED}❌ MongoDB did not start in time.${NC}"
        echo "   Check logs: docker compose logs mongodb"
        exit 1
    fi
else
    echo -e "\n${BLUE}[5/6]${NC} Skipping MongoDB setup (Docker not available)"
    echo -e "${YELLOW}⚠️  Please install MongoDB manually or install Docker/Docker Compose.${NC}"
    echo "   Connection string: mongodb://localhost:27017/"
fi

# Step 6: Create .env file (optional)
cd "$SCRIPT_DIR"
echo -e "\n${BLUE}[6/6]${NC} Creating configuration files..."
if [ ! -f .env ]; then
    cat > .env << EOF
# MongoDB Configuration
MONGODB_URL=mongodb://localhost:27017/

# FastAPI Configuration
API_HOST=0.0.0.0
API_PORT=8080
API_RELOAD=false

# Environment
ENVIRONMENT=production
EOF
    echo -e "${GREEN}✅ .env file created${NC}"
else
    echo -e "${YELLOW}⚠️  .env file already exists. Skipping...${NC}"
fi

# Make scripts executable
chmod +x setup.sh 2>/dev/null || true
find scripts -name "*.sh" -type f -exec chmod +x {} \; 2>/dev/null || true

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ Setup completed successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BLUE}📚 Next Steps:${NC}"
echo ""
echo -e "1. ${GREEN}Activate virtual environment:${NC}"
echo "   cd backend && source .venv/bin/activate"
echo ""
echo -e "2. ${GREEN}Run the API server:${NC}"
echo "   uvicorn main:app --host 0.0.0.0 --port 8080"
echo ""
echo -e "3. ${GREEN}Access API documentation:${NC}"
echo "   http://$(hostname -I | awk '{print $1}'):8080/docs"
echo "   or http://localhost:8080/docs"
echo ""
echo -e "4. ${GREEN}(Optional) Setup as systemd service:${NC}"
echo "   See README.md for systemd service configuration"
echo ""
echo -e "${YELLOW}💡 Tip: Check README.md for detailed documentation${NC}"
echo ""

