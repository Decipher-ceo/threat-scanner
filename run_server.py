#!/home/decipher/Desktop/ThreatScanner/phishing_line/venv/bin/python3
"""
Simple launcher script for ThreatScanner backend
Run this from the phishing_line directory: python3 run_server.py
"""
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.app import app

if __name__ == "__main__":
    print("=" * 50)
    print("ThreatScanner Backend Server")
    print("=" * 50)
    print("Server starting on http://0.0.0.0:5000")
    print("Dashboard: http://127.0.0.1:5000")
    print("Press Ctrl+C to stop")
    app.run(host="0.0.0.0", port=5000, debug=True)
