"""
Unit tests for CICIDS2017 Data Loader.
"""

import pytest
import pandas as pd
import os
from src.data_loader import CICIDS2017Loader

class TestCICIDS2017Loader:
    
    @pytest.fixture
    def sample_csv(self, tmp_path):
        """Create a sample CICIDS2017 CSV file."""
        csv_path = tmp_path / "sample_dataset.csv"
        
        # Create valid header and data
        data = {
            " Source IP": ["192.168.10.1", "192.168.10.5", "192.168.10.1"],
            " Destination Port": [22, 22, 80],
            " Protocol": [6, 6, 6],
            " Timestamp": ["03/07/2017 01:00", "03/07/2017 01:05", "03/07/2017 01:10"],
            " Label": ["SSH-BruteForce", "BENIGN", "BENIGN"]
        }
        
        df = pd.DataFrame(data)
        df.to_csv(csv_path, index=False)
        return str(csv_path)

    def test_load_and_filter_ssh_brute_force(self, sample_csv):
        """Test filtering for SSH-BruteForce."""
        loader = CICIDS2017Loader(sample_csv)
        
        chunks = list(loader.load_and_filter(target_label="SSH-BruteForce"))
        combined_df = pd.concat(chunks)
        
        assert len(combined_df) == 1
        assert combined_df.iloc[0]['source_ip'] == "192.168.10.1"
        assert combined_df.iloc[0]['label'] == "SSH-BruteForce"

    def test_load_and_filter_benign(self, sample_csv):
        """Test filtering for BENIGN."""
        loader = CICIDS2017Loader(sample_csv)
        
        chunks = list(loader.load_and_filter(target_label="BENIGN"))
        combined_df = pd.concat(chunks)
        
        # Only one BENIGN record matches port 22 and protocol 6 in our sample
        assert len(combined_df) == 1
        assert combined_df.iloc[0]['source_ip'] == "192.168.10.5"

    def test_protocol_port_filter(self, sample_csv):
        """Test that protocol and port filters work."""
        loader = CICIDS2017Loader(sample_csv)
        
        # Filter for HTTP (Port 80)
        chunks = list(loader.load_and_filter(filter_port=80, target_label=None))
        combined_df = pd.concat(chunks)
        
        assert len(combined_df) == 1
        assert combined_df.iloc[0]['source_ip'] == "192.168.10.1"

    def test_timestamp_parsing(self, sample_csv):
        """Test timestamp parsing correctness."""
        loader = CICIDS2017Loader(sample_csv)
        chunks = list(loader.load_and_filter(target_label="SSH-BruteForce"))
        combined_df = pd.concat(chunks)
        
        assert pd.api.types.is_datetime64_any_dtype(combined_df['timestamp'])
        dt = combined_df.iloc[0]['timestamp']
        assert dt.day == 3
        assert dt.month == 7
        assert dt.year == 2017
