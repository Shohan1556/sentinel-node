"""
Database connector module for SentinelNode.

This module provides PostgreSQL database connectivity with SSL support
for storing security alerts in a centralized database.
"""

import os
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
import psycopg2
from psycopg2 import pool, sql
from psycopg2.extras import RealDictCursor

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseConnector:
    """
    Manages PostgreSQL database connections and operations for alert storage.
    
    Attributes:
        connection_pool: PostgreSQL connection pool for efficient connection management
    """
    
    def __init__(
        self,
        host: str,
        port: int,
        database: str,
        user: str,
        password: str,
        ssl_mode: str = "require",
        min_connections: int = 1,
        max_connections: int = 5
    ):
        """
        Initialize database connector with connection pooling.
        
        Args:
            host: Database host address
            port: Database port number
            database: Database name
            user: Database username
            password: Database password
            ssl_mode: SSL mode (require, prefer, disable)
            min_connections: Minimum number of connections in pool
            max_connections: Maximum number of connections in pool
            
        Raises:
            psycopg2.Error: If connection pool creation fails
        """
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.ssl_mode = ssl_mode
        self.connection_pool: Optional[pool.SimpleConnectionPool] = None
        
        try:
            logger.info(f"Initializing database connection pool to {host}:{port}/{database}")
            self.connection_pool = psycopg2.pool.SimpleConnectionPool(
                min_connections,
                max_connections,
                host=host,
                port=port,
                database=database,
                user=user,
                password=password,
                sslmode=ssl_mode
            )
            
            if self.connection_pool:
                logger.info("Database connection pool created successfully")
                self._initialize_schema()
            else:
                raise Exception("Failed to create connection pool")
                
        except psycopg2.Error as e:
            logger.error(f"Database connection error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during database initialization: {e}")
            raise
    
    def _initialize_schema(self) -> None:
        """
        Create alerts table if it doesn't exist.
        
        Raises:
            psycopg2.Error: If table creation fails
        """
        create_table_query = """
        CREATE TABLE IF NOT EXISTS alerts (
            id SERIAL PRIMARY KEY,
            detection_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            source_ip INET NOT NULL,
            event_type TEXT DEFAULT 'SSH-BruteForce',
            dataset_source TEXT DEFAULT 'CICIDS2017',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        """
        
        create_index_query = """
        CREATE INDEX IF NOT EXISTS idx_alerts_detection_time ON alerts(detection_time);
        CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
        """
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Create table
            cursor.execute(create_table_query)
            logger.info("Alerts table verified/created successfully")
            
            # Create indexes for better query performance
            cursor.execute(create_index_query)
            logger.info("Database indexes created successfully")
            
            conn.commit()
            cursor.close()
            
        except psycopg2.Error as e:
            logger.error(f"Error initializing database schema: {e}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                self.release_connection(conn)
    
    def get_connection(self):
        """
        Get a connection from the pool.
        
        Returns:
            psycopg2.connection: Database connection
            
        Raises:
            Exception: If connection pool is not initialized
        """
        if not self.connection_pool:
            raise Exception("Connection pool is not initialized")
        return self.connection_pool.getconn()
    
    def release_connection(self, conn) -> None:
        """
        Release a connection back to the pool.
        
        Args:
            conn: Database connection to release
        """
        if self.connection_pool and conn:
            self.connection_pool.putconn(conn)
    
    def insert_alert(
        self,
        source_ip: str,
        detection_time: datetime,
        event_type: str = "SSH-BruteForce",
        dataset_source: str = "CICIDS2017"
    ) -> Optional[int]:
        """
        Insert a new alert into the database using parameterized queries.
        
        Args:
            source_ip: IP address of the attacker
            detection_time: When the event was detected
            event_type: Type of security event (default 'SSH-BruteForce')
            dataset_source: Source of the dataset (default 'CICIDS2017')
            
        Returns:
            int: ID of inserted alert, or None if insertion failed
        """
        insert_query = """
        INSERT INTO alerts (
            detection_time, source_ip, event_type, dataset_source
        )
        VALUES (%s, %s, %s, %s)
        RETURNING id;
        """
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                insert_query,
                (detection_time, source_ip, event_type, dataset_source)
            )
            
            alert_id = cursor.fetchone()[0]
            conn.commit()
            cursor.close()
            
            logger.info(f"Alert inserted successfully with ID: {alert_id}")
            return alert_id
            
        except psycopg2.Error as e:
            logger.error(f"Error inserting alert: {e}")
            if conn:
                conn.rollback()
            return None
        finally:
            if conn:
                self.release_connection(conn)
    
    def get_alerts(
        self,
        limit: int = 100,
        status: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve alerts from the database with optional filtering.
        
        Args:
            limit: Maximum number of alerts to retrieve
            status: Filter by alert status
            ip_address: Filter by IP address
            
        Returns:
            List of alert dictionaries
        """
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        
        if status:
            query += " AND status = %s"
            params.append(status)
        
        if ip_address:
            query += " AND ip_address = %s"
            params.append(ip_address)
        
        query += " ORDER BY timestamp DESC LIMIT %s"
        params.append(limit)
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            cursor.execute(query, params)
            alerts = cursor.fetchall()
            cursor.close()
            
            return [dict(alert) for alert in alerts]
            
        except psycopg2.Error as e:
            logger.error(f"Error retrieving alerts: {e}")
            return []
        finally:
            if conn:
                self.release_connection(conn)
    
    def update_alert_status(self, alert_id: int, new_status: str) -> bool:
        """
        Update the status of an existing alert.
        
        Args:
            alert_id: ID of the alert to update
            new_status: New status value
            
        Returns:
            bool: True if update successful, False otherwise
        """
        update_query = "UPDATE alerts SET status = %s WHERE id = %s"
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(update_query, (new_status, alert_id))
            conn.commit()
            cursor.close()
            
            logger.info(f"Alert {alert_id} status updated to '{new_status}'")
            return True
            
        except psycopg2.Error as e:
            logger.error(f"Error updating alert status: {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                self.release_connection(conn)
    
    def close(self) -> None:
        """
        Close all connections in the pool.
        """
        if self.connection_pool:
            self.connection_pool.closeall()
            logger.info("Database connection pool closed")
    
    def test_connection(self) -> bool:
        """
        Test database connectivity.
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            logger.info("Database connection test successful")
            return True
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            return False
        finally:
            if conn:
                self.release_connection(conn)


def create_db_connector_from_env() -> Optional[DatabaseConnector]:
    """
    Create a DatabaseConnector instance from environment variables.
    
    Returns:
        DatabaseConnector instance if all required env vars are present,
        None otherwise
    """
    required_vars = ["DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME"]
    
    # Check if all required variables are present
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        logger.warning(
            f"Database configuration incomplete. Missing: {', '.join(missing_vars)}. "
            "Database persistence will be disabled."
        )
        return None
    
    try:
        connector = DatabaseConnector(
            host=os.getenv("DB_HOST"),
            port=int(os.getenv("DB_PORT", "5432")),
            database=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            ssl_mode=os.getenv("DB_SSL_MODE", "require")
        )
        return connector
    except Exception as e:
        logger.error(f"Failed to create database connector: {e}")
        return None
