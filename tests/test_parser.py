import pytest
from src.log_parser import LogParser

def test_parser_initialization():
    parser = LogParser("/data/raw/sample_auth.log")
    assert parser.log_path == "/data/raw/sample_auth.log"

def test_parse_placeholder():
    parser = LogParser("/data/raw/sample_auth.log")
    assert parser.parse() is None
