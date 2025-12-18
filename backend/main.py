"""
Main entry point for ThreatScanner backend
This file imports and runs the Flask app from app.py

Run from the phishing_line directory:
    python3 -m backend.main
    OR
    python3 backend/main.py
"""
import sys
import os

# Get the directory containing this file
current_dir = os.path.dirname(os.path.abspath(__file__))
# Get the parent directory (phishing_line)
parent_dir = os.path.dirname(current_dir)

# Add parent directory to path for imports
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Now import using absolute import
from backend.app import app

def start():
    """Start the Flask server"""
    print("=" * 50)
    print("ThreatScanner Backend Server")
    print("=" * 50)
    print("Server starting on http://0.0.0.0:5000")
    print("Dashboard: http://127.0.0.1:5000")
    print("API Base: http://127.0.0.1:5000/api")
    print("Press Ctrl+C to stop")
    print("=" * 50)
    app.run(host="0.0.0.0", port=5000, debug=True)

if __name__ == "__main__":
    start()
