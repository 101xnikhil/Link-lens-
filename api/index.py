import sys
from pathlib import Path

# Add backend directory to sys.path so app modules are resolvable
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "backend"))

from app.main import app
from app.database.session import init_db

# Initialize database schema immediately on serverless start
try:
    init_db()
except Exception as e:
    print(f"Serverless init_db notice: {e}")
