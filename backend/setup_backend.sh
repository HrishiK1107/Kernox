#!/bin/bash
# Kernox Backend — Setup Script
# Creates venv, installs deps, and seeds a test endpoint for the agent.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "═══════════════════════════════════════════════"
echo "  Kernox Backend Setup"
echo "═══════════════════════════════════════════════"

# ── 1. Create virtual environment ──────────────────────────
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
else
    echo "Virtual environment already exists."
fi

# ── 2. Install dependencies ────────────────────────────────
echo "Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "✅ Dependencies installed"

# ── 3. Create .env if missing ──────────────────────────────
if [ ! -f ".env" ]; then
    cp .env.example .env 2>/dev/null || cat > .env << 'EOF'
APP_ENV=development
APP_NAME=Kernox Backend
API_V1_PREFIX=/api/v1
MAX_REQUEST_SIZE=1048576
EOF
    echo "✅ Created .env"
fi

# ── 4. Seed test endpoint ─────────────────────────────────
echo "Seeding test endpoint..."
python3 -c "
import sys
sys.path.insert(0, '.')
from app.db.session import SessionLocal, engine
from app.db.base import Base
from app.models.endpoint import Endpoint

# Create tables
Base.metadata.create_all(bind=engine)

db = SessionLocal()
try:
    # Check if test endpoint already exists
    existing = db.query(Endpoint).filter_by(endpoint_id='kernox-test-agent').first()
    if existing:
        print('✅ Test endpoint already exists (endpoint_id=kernox-test-agent)')
        print(f'   secret_hash: {existing.secret_hash}')
    else:
        endpoint = Endpoint(
            endpoint_id='kernox-test-agent',
            hostname='localhost',
            secret_hash='kernox-dev-secret',
            is_active=True,
        )
        db.add(endpoint)
        db.commit()
        print('✅ Test endpoint created:')
        print(f'   endpoint_id:  kernox-test-agent')
        print(f'   secret_hash:  kernox-dev-secret')
        print(f'   hostname:     localhost')
finally:
    db.close()
"

echo ""
echo "═══════════════════════════════════════════════"
echo "  ✅ Backend setup complete!"
echo ""
echo "  Start the backend:"
echo "    cd $SCRIPT_DIR"
echo "    source venv/bin/activate"
echo "    uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo "  Start the agent (in another terminal):"
echo "    cd $(dirname $SCRIPT_DIR)"
echo "    sudo KERNOX_ENDPOINT_ID=kernox-test-agent \\"
echo "         KERNOX_HMAC_SECRET=kernox-dev-secret \\"
echo "         KERNOX_BACKEND_URL=http://localhost:8000 \\"
echo "         python3 -m agent.main"
echo "═══════════════════════════════════════════════"
