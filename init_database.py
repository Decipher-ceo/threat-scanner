#!/usr/bin/env python3
"""
Database initialization script.
Creates all database tables defined in models.py

Run this script from the phishing_line directory:
    python3 init_database.py
"""
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.db import engine
from backend.models import Base

def init_database():
    """Create all database tables"""
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("✓ Database tables created successfully!")
    print(f"Database location: {engine.url}")

if __name__ == "__main__":
    init_database()

