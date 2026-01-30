#!/usr/bin/env python3
"""
Database insertion test script for SentinelNode.

This script tests the database connection and alert insertion functionality.
"""

import sys
import os
from datetime import datetime

# Add parent directory to path to import src modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.db_connector import DatabaseConnector, create_db_connector_from_env
from src.config import DB_CONFIG, is_db_configured
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def print_header(text):
    """Print a formatted header."""
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)


def test_database_connection():
    """
    Test database connection and alert insertion.
    
    Returns:
        bool: True if all tests pass, False otherwise
    """
    print_header("SentinelNode Database Test Script")
    
    # Check if database is configured
    if not is_db_configured():
        print("\n❌ Error: Database configuration incomplete!")
        print("\nMissing environment variables. Please ensure the following are set:")
        print("  - DB_HOST")
        print("  - DB_NAME")
        print("  - DB_USER")
        print("  - DB_PASSWORD")
        print("\nCreate a .env file based on .env.example and try again.")
        return False
    
    print("\n✓ Database configuration found")
    print(f"  Host: {DB_CONFIG['host']}")
    print(f"  Database: {DB_CONFIG['database']}")
    print(f"  User: {DB_CONFIG['user']}")
    print(f"  SSL Mode: {DB_CONFIG['ssl_mode']}")
    
    # Initialize database connector
    print_header("Step 1: Initializing Database Connection")
    
    try:
        db = DatabaseConnector(
            host=DB_CONFIG["host"],
            port=DB_CONFIG["port"],
            database=DB_CONFIG["database"],
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"],
            ssl_mode=DB_CONFIG["ssl_mode"]
        )
        print("✓ Database connector initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize database connector: {e}")
        return False
    
    # Test connection
    print_header("Step 2: Testing Database Connection")
    
    if db.test_connection():
        print("✓ Database connection test successful")
    else:
        print("❌ Database connection test failed")
        db.close()
        return False
    
    # Insert mock alert
    print_header("Step 3: Inserting Mock Alert")
    
    try:
        mock_timestamp = datetime.now()
        mock_ip = "192.168.1.100"
        
        print(f"\nInserting test alert:")
        print(f"  Timestamp: {mock_timestamp}")
        print(f"  IP Address: {mock_ip}")
        print(f"  Event Type: brute_force")
        print(f"  Status: new")
        
        alert_id = db.insert_alert(
            timestamp=mock_timestamp,
            ip_address=mock_ip,
            event_type="brute_force",
            status="new",
            machine_ip="10.0.0.1",
            machine_name="sentinel-server-01",
            browser="SSH Client"
        )
        
        if alert_id:
            print(f"\n✓ Alert inserted successfully with ID: {alert_id}")
        else:
            print("\n❌ Failed to insert alert (no ID returned)")
            db.close()
            return False
            
    except Exception as e:
        print(f"\n❌ Error inserting alert: {e}")
        db.close()
        return False
    
    # Verify insertion by querying
    print_header("Step 4: Verifying Alert Insertion")
    
    try:
        alerts = db.get_alerts(limit=5)
        
        if alerts:
            print(f"\n✓ Successfully retrieved {len(alerts)} alert(s) from database")
            print("\nMost recent alerts:")
            
            for i, alert in enumerate(alerts[:3], 1):
                print(f"\n  Alert #{i}:")
                print(f"    ID: {alert['id']}")
                print(f"    Timestamp: {alert['timestamp']}")
                print(f"    IP Address: {alert['ip_address']}")
                print(f"    Event Type: {alert['event_type']}")
                print(f"    Status: {alert['status']}")
                
                if alert.get('machine_name'):
                    print(f"    Machine: {alert['machine_name']}")
        else:
            print("\n⚠ Warning: No alerts found in database")
            
    except Exception as e:
        print(f"\n❌ Error querying alerts: {e}")
        db.close()
        return False
    
    # Test status update
    print_header("Step 5: Testing Alert Status Update")
    
    try:
        if alert_id:
            success = db.update_alert_status(alert_id, "acknowledged")
            
            if success:
                print(f"✓ Successfully updated alert {alert_id} status to 'acknowledged'")
            else:
                print(f"⚠ Warning: Failed to update alert status")
                
    except Exception as e:
        print(f"❌ Error updating alert status: {e}")
    
    # Clean up
    print_header("Test Complete")
    db.close()
    print("\n✓ Database connection closed")
    print("\n" + "=" * 60)
    print("  All tests passed successfully! ✓")
    print("=" * 60)
    
    return True


def main():
    """Main entry point."""
    try:
        success = test_database_connection()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
