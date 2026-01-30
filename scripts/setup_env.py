#!/usr/bin/env python3
"""
Setup script to create .env file with database credentials.
Run this once to configure database access.
"""

import os

def create_env_file():
    """Create .env file with Neon DB credentials."""
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    
    # Database credentials
    env_content = """# Database Configuration for SentinelNode
# PostgreSQL Database Connection (Neon DB)

DB_HOST=ep-winter-hat-a7r2rw12-pooler.ap-southeast-2.aws.neon.tech
DB_PORT=5432
DB_NAME=neondb
DB_USER=neondb_owner
DB_PASSWORD=npg_oOQ93NukcpiB
DB_SSL_MODE=require
"""
    
    try:
        with open(env_path, 'w') as f:
            f.write(env_content)
        print(f"✓ Created .env file at: {env_path}")
        print("\nDatabase credentials configured successfully!")
        print("\nYou can now run:")
        print("  python scripts/test_db_insert.py  # Test database connection")
        print("  python main.py                     # Run the main application")
        return True
    except Exception as e:
        print(f" Error creating .env file: {e}")
        return False

if __name__ == "__main__":
    create_env_file()
