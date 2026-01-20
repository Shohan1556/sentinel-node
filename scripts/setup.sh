#!/bin/bash
echo "Setting up LogSentinel environment..."
python3 -m venv venv
source venv/bin/activate
pip install requirements.txt
echo "Setup complete......."