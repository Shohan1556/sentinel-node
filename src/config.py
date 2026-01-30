"""
Configuration module for SentinelNode.

Loads configuration from environment variables and provides default values.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Application configuration
CONFIG = {
    "log_path": "data/raw/sample_auth.log",
    "threshold": 5,
    "alert_output": "data/processed/alerts.csv"
}

# Database configuration (loaded from environment variables)
DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "database": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "ssl_mode": os.getenv("DB_SSL_MODE", "require")
}

def is_db_configured() -> bool:
    """
    Check if database configuration is complete.
    
    Returns:
        bool: True if all required database credentials are present
    """
    required_keys = ["host", "database", "user", "password"]
    return all(DB_CONFIG.get(key) for key in required_keys)
