"""
Enhanced Database Connector for SentinelNode.

Implements normalized 3-table schema for production-grade detection:
- events: Core detection records with severity tiers
- ip_profiles: Behavioral baseline tracking per IP
- attack_evidence: Audit trail with raw flow metrics
"""

import os
import logging
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime
import psycopg2
from psycopg2 import pool, sql
from psycopg2.extras import RealDictCursor, Json
import ipaddress

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseConnector:
    """
    Manages PostgreSQL database connections with normalized schema.
    
    Schema:
        - events: Detection records with severity/confidence
        - ip_profiles: Behavioral baselines per IP
        - attack_evidence: Audit trail with JSONB metrics
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
        max_connections: int = 10
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
            min_connections: Minimum connections in pool
            max_connections: Maximum connections in pool
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
        Create normalized schema with 3 tables if they don't exist.
        
        Tables:
            - events: Core detection records
            - ip_profiles: Behavioral baselines
            - attack_evidence: Audit trail
        """
        schema_queries = """
        -- Events table: core detection records
        CREATE TABLE IF NOT EXISTS events (
            id SERIAL PRIMARY KEY,
            event_type VARCHAR(50) NOT NULL,
            severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
            confidence_score FLOAT CHECK (confidence_score BETWEEN 0.0 AND 1.0),
            detection_time TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        
        -- IP profiles: behavioral baseline tracking
        CREATE TABLE IF NOT EXISTS ip_profiles (
            ip_address INET PRIMARY KEY,
            first_seen TIMESTAMPTZ NOT NULL,
            last_seen TIMESTAMPTZ NOT NULL,
            baseline_pps FLOAT DEFAULT 0.0,
            reputation_score INT DEFAULT 50 CHECK (reputation_score BETWEEN 0 AND 100),
            total_events INT DEFAULT 0,
            last_updated TIMESTAMPTZ DEFAULT NOW()
        );
        
        -- Attack evidence: audit trail with raw metrics
        CREATE TABLE IF NOT EXISTS attack_evidence (
            id SERIAL PRIMARY KEY,
            event_id INT REFERENCES events(id) ON DELETE CASCADE,
            src_ip INET NOT NULL,
            dst_ip INET,
            pattern_type VARCHAR(30),
            raw_metrics JSONB,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        
        -- Performance indexes
        CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
        CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
        CREATE INDEX IF NOT EXISTS idx_events_detection_time ON events(detection_time);
        CREATE INDEX IF NOT EXISTS idx_ip_profiles_reputation ON ip_profiles(reputation_score);
        CREATE INDEX IF NOT EXISTS idx_attack_evidence_event_id ON attack_evidence(event_id);
        CREATE INDEX IF NOT EXISTS idx_attack_evidence_src_ip ON attack_evidence(src_ip);
        """
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Execute schema creation
            cursor.execute(schema_queries)
            logger.info("Database schema verified/created successfully")
            
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
        """Get a connection from the pool."""
        if not self.connection_pool:
            raise Exception("Connection pool is not initialized")
        return self.connection_pool.getconn()
    
    def release_connection(self, conn) -> None:
        """Release a connection back to the pool."""
        if self.connection_pool and conn:
            self.connection_pool.putconn(conn)
    
    def insert_event(
        self,
        event_type: str,
        severity: str,
        confidence_score: float,
        detection_time: datetime
    ) -> Optional[int]:
        """
        Insert a new event into the database.
        
        Args:
            event_type: Type of event (e.g., 'ssh_bruteforce', 'ddos_syn')
            severity: Severity level ('low', 'medium', 'high', 'critical')
            confidence_score: Confidence score (0.0-1.0)
            detection_time: When the event was detected
            
        Returns:
            Event ID if successful, None otherwise
        """
        query = """
        INSERT INTO events (event_type, severity, confidence_score, detection_time)
        VALUES (%s, %s, %s, %s)
        RETURNING id;
        """
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(query, (event_type, severity, confidence_score, detection_time))
            event_id = cursor.fetchone()[0]
            
            conn.commit()
            cursor.close()
            
            logger.debug(f"Event inserted successfully with ID: {event_id}")
            return event_id
            
        except psycopg2.Error as e:
            logger.error(f"Error inserting event: {e}")
            if conn:
                conn.rollback()
            return None
        finally:
            if conn:
                self.release_connection(conn)
    
    def upsert_ip_profile(
        self,
        ip_address: str,
        first_seen: datetime,
        last_seen: datetime,
        baseline_pps: float = 0.0,
        reputation_score: int = 50
    ) -> bool:
        """
        Insert or update IP profile for behavioral baseline tracking.
        
        Args:
            ip_address: IP address to track
            first_seen: First time this IP was seen
            last_seen: Last time this IP was seen
            baseline_pps: Baseline packets per second
            reputation_score: Reputation score (0-100)
            
        Returns:
            True if successful, False otherwise
        """
        # Validate IP address
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            logger.error(f"Invalid IP address: {ip_address}")
            return False
        
        query = """
        INSERT INTO ip_profiles (ip_address, first_seen, last_seen, baseline_pps, reputation_score, last_updated)
        VALUES (%s, %s, %s, %s, %s, NOW())
        ON CONFLICT (ip_address) 
        DO UPDATE SET 
            last_seen = EXCLUDED.last_seen,
            baseline_pps = EXCLUDED.baseline_pps,
            reputation_score = EXCLUDED.reputation_score,
            last_updated = NOW();
        """
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(query, (ip_address, first_seen, last_seen, baseline_pps, reputation_score))
            conn.commit()
            cursor.close()
            
            logger.debug(f"IP profile upserted for {ip_address}")
            return True
            
        except psycopg2.Error as e:
            logger.error(f"Error upserting IP profile: {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                self.release_connection(conn)
    
    def insert_attack_evidence(
        self,
        event_id: int,
        src_ip: str,
        pattern_type: str,
        raw_metrics: Dict[str, Any],
        dst_ip: Optional[str] = None
    ) -> Optional[int]:
        """
        Insert attack evidence for audit trail.
        
        Args:
            event_id: Reference to events table
            src_ip: Source IP address
            pattern_type: Type of pattern detected
            raw_metrics: Raw flow metrics as dictionary
            dst_ip: Destination IP (optional)
            
        Returns:
            Evidence ID if successful, None otherwise
        """
        query = """
        INSERT INTO attack_evidence (event_id, src_ip, dst_ip, pattern_type, raw_metrics)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id;
        """
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(query, (event_id, src_ip, dst_ip, pattern_type, Json(raw_metrics)))
            evidence_id = cursor.fetchone()[0]
            
            conn.commit()
            cursor.close()
            
            logger.debug(f"Attack evidence inserted with ID: {evidence_id}")
            return evidence_id
            
        except psycopg2.Error as e:
            logger.error(f"Error inserting attack evidence: {e}")
            if conn:
                conn.rollback()
            return None
        finally:
            if conn:
                self.release_connection(conn)
    
    def get_ip_baseline(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get baseline profile for an IP address.
        
        Args:
            ip_address: IP address to query
            
        Returns:
            Dictionary with baseline data or None if not found
        """
        query = "SELECT * FROM ip_profiles WHERE ip_address = %s"
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            cursor.execute(query, (ip_address,))
            result = cursor.fetchone()
            cursor.close()
            
            return dict(result) if result else None
            
        except psycopg2.Error as e:
            logger.error(f"Error getting IP baseline: {e}")
            return None
        finally:
            if conn:
                self.release_connection(conn)
    
    def update_ip_reputation(self, ip_address: str, delta: int) -> bool:
        """
        Update IP reputation score by delta.
        
        Args:
            ip_address: IP address to update
            delta: Change in reputation (positive or negative)
            
        Returns:
            True if successful, False otherwise
        """
        query = """
        UPDATE ip_profiles 
        SET reputation_score = GREATEST(0, LEAST(100, reputation_score + %s)),
            last_updated = NOW()
        WHERE ip_address = %s
        """
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(query, (delta, ip_address))
            conn.commit()
            cursor.close()
            
            logger.debug(f"IP reputation updated for {ip_address} by {delta}")
            return True
            
        except psycopg2.Error as e:
            logger.error(f"Error updating IP reputation: {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                self.release_connection(conn)
    
    def increment_ip_event_count(self, ip_address: str) -> bool:
        """
        Increment total event count for an IP.
        
        Args:
            ip_address: IP address to update
            
        Returns:
            True if successful, False otherwise
        """
        query = """
        UPDATE ip_profiles 
        SET total_events = total_events + 1,
            last_updated = NOW()
        WHERE ip_address = %s
        """
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(query, (ip_address,))
            conn.commit()
            cursor.close()
            
            return True
            
        except psycopg2.Error as e:
            logger.error(f"Error incrementing event count: {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                self.release_connection(conn)
    
    def get_recent_events(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
        event_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve recent events with optional filtering.
        
        Args:
            limit: Maximum number of events to retrieve
            severity: Filter by severity level
            event_type: Filter by event type
            
        Returns:
            List of event dictionaries
        """
        query = "SELECT * FROM events WHERE 1=1"
        params = []
        
        if severity:
            query += " AND severity = %s"
            params.append(severity)
        
        if event_type:
            query += " AND event_type = %s"
            params.append(event_type)
        
        query += " ORDER BY detection_time DESC LIMIT %s"
        params.append(limit)
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            cursor.execute(query, params)
            events = cursor.fetchall()
            cursor.close()
            
            return [dict(event) for event in events]
            
        except psycopg2.Error as e:
            logger.error(f"Error retrieving events: {e}")
            return []
        finally:
            if conn:
                self.release_connection(conn)
    
    def get_top_attacking_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get top attacking IPs by event count.
        
        Args:
            limit: Number of top IPs to return
            
        Returns:
            List of dictionaries with IP stats
        """
        query = """
        SELECT 
            ae.src_ip,
            COUNT(*) as event_count,
            AVG(e.confidence_score) as avg_confidence,
            MAX(e.detection_time) as last_seen,
            ip.reputation_score
        FROM attack_evidence ae
        JOIN events e ON ae.event_id = e.id
        LEFT JOIN ip_profiles ip ON ae.src_ip = ip.ip_address
        GROUP BY ae.src_ip, ip.reputation_score
        ORDER BY event_count DESC
        LIMIT %s
        """
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            cursor.execute(query, (limit,))
            results = cursor.fetchall()
            cursor.close()
            
            return [dict(row) for row in results]
            
        except psycopg2.Error as e:
            logger.error(f"Error getting top attacking IPs: {e}")
            return []
        finally:
            if conn:
                self.release_connection(conn)
    
    def get_severity_distribution(self) -> Dict[str, int]:
        """
        Get distribution of events by severity.
        
        Returns:
            Dictionary mapping severity to count
        """
        query = """
        SELECT severity, COUNT(*) as count
        FROM events
        GROUP BY severity
        """
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(query)
            results = cursor.fetchall()
            cursor.close()
            
            return {row[0]: row[1] for row in results}
            
        except psycopg2.Error as e:
            logger.error(f"Error getting severity distribution: {e}")
            return {}
        finally:
            if conn:
                self.release_connection(conn)
    
    def close(self) -> None:
        """Close all connections in the pool."""
        if self.connection_pool:
            self.connection_pool.closeall()
            logger.info("Database connection pool closed")
    
    def test_connection(self) -> bool:
        """
        Test database connectivity.
        
        Returns:
            True if connection successful, False otherwise
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
        DatabaseConnector instance if configured, None otherwise
    """
    from dotenv import load_dotenv
    load_dotenv()
    
    required_vars = ["DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME"]
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
