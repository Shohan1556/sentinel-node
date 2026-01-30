"""
Data loader module for SentinelNode.

Responsible for loading and filtering network flow data from CICIDS2017 CSV files.
"""

import pandas as pd
import logging
import os
from datetime import datetime
from typing import Optional, Dict, List, Generator

logger = logging.getLogger(__name__)

class CICIDS2017Loader:
    """
    Loader for CICIDS2017 network traffic dataset CSVs.
    """
    
    # Column mapping based on standard CICIDS2017 header format
    REQUIRED_COLUMNS = [
        " Source IP", 
        " Destination Port", 
        " Protocol", 
        " Timestamp", 
        " Label"
    ]
    
    def __init__(self, file_path: str):
        """
        Initialize the loader with the path to the CSV file.
        
        Args:
            file_path: Path to the CICIDS2017 CSV file
        """
        self.file_path = file_path
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Dataset file not found: {file_path}")
            
    def load_and_filter(self, 
                       filter_protocol: int = 6, 
                       filter_port: int = 22, 
                       target_label: Optional[str] = "SSH-BruteForce",
                       chunk_size: int = 100000) -> Generator[pd.DataFrame, None, None]:
        """
        Load CSV in chunks and filter for SSH brute-force traffic.
        
        Args:
            filter_protocol: Protocol number to keep (default 6 for TCP)
            filter_port: Destination port to keep (default 22 for SSH)
            target_label: specific label to filter for (e.g., "SSH-BruteForce"). 
                          If None, returns all records matching protocol/port.
            chunk_size: Number of rows to process at a time
            
        Yields:
            pd.DataFrame: Filtered chunk of data containing relevant columns
        """
        logger.info(f"Processing dataset: {self.file_path}")
        
        try:
            # First verify headers
            header_df = pd.read_csv(self.file_path, nrows=0)
            available_columns = header_df.columns.tolist()
            
            # Check for required columns (handling potential whitespace in headers)
            # The dataset often has leading spaces in column names
            clean_cols = {col: col.strip() for col in available_columns}
            mapped_cols = {col.strip(): col for col in available_columns}
            
            missing_cols = []
            normalized_req_cols = [c.strip() for c in self.REQUIRED_COLUMNS]
            
            for req_col in normalized_req_cols:
                if req_col not in mapped_cols:
                    missing_cols.append(req_col)
            
            if missing_cols:
                raise ValueError(f"Missing required columns: {missing_cols}")

            # Define column renaming for cleaner internal usage
            rename_map = {
                mapped_cols['Source IP']: 'source_ip',
                mapped_cols['Destination Port']: 'dest_port',
                mapped_cols['Protocol']: 'protocol',
                mapped_cols['Timestamp']: 'timestamp',
                mapped_cols['Label']: 'label'
            }
            
            # Use columns that map to our needs
            use_cols = list(rename_map.keys())
            
            # Process in chunks to handle large files efficiently
            chunk_iterator = pd.read_csv(
                self.file_path,
                usecols=use_cols,
                chunksize=chunk_size,
                low_memory=False
            )
            
            total_records = 0
            filtered_records = 0
            
            for chunk in chunk_iterator:
                # Rename columns
                chunk = chunk.rename(columns=rename_map)
                
                # Apply filters
                # Protocol 6 is TCP
                mask = (chunk['protocol'] == filter_protocol) & \
                       (chunk['dest_port'] == filter_port)
                
                if target_label:
                    mask = mask & (chunk['label'] == target_label)
                
                filtered_chunk = chunk[mask].copy()
                
                if not filtered_chunk.empty:
                    # Parse timestamps
                    # Format is typically day/Month/Year Hour:Minute, e.g., 03/07/2017 12:48
                    filtered_chunk['timestamp'] = pd.to_datetime(
                        filtered_chunk['timestamp'], 
                        format='%d/%m/%Y %H:%M',
                        errors='coerce'
                    )
                    
                    # Drop rows where timestamp parsing failed
                    filtered_chunk = filtered_chunk.dropna(subset=['timestamp'])
                    
                    filtered_records += len(filtered_chunk)
                    yield filtered_chunk[['source_ip', 'timestamp', 'label']]
                
                total_records += len(chunk)
                
            logger.info(f"Data loading complete. Filtered {filtered_records} records from {total_records} total.")
            
        except Exception as e:
            logger.error(f"Error loading dataset: {e}")
            raise
