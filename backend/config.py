import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "cloudwatch.db"

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
SECRET_SALT = os.getenv("SECRET_SALT", "cloudwatch-default-salt-change-me")

DATABASE_URL = f"sqlite:///{DB_PATH}"

SEVERITY_DEDUCTIONS = {
    "Critical": 15,
    "High": 8,
    "Medium": 3,
    "Low": 1,
    "Info": 0,
}

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
