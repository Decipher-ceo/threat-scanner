#!/usr/bin/env python3
"""
Database initialization script.
Creates all database tables defined in models.py and creates a default admin user.

Run this from the phishing_line directory:
    python3 -m backend.init_db
"""
from .db import engine, SessionLocal
from .models import Base, User

def init_database():
    """Create all database tables and default admin user"""
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("✓ Database tables created successfully!")
    print(f"Database location: {engine.url}")
    
    # Create default admin user if it doesn't exist
    db = SessionLocal()
    try:
        admin_user = db.query(User).filter(User.username == "admin").first()
        if not admin_user:
            admin_user = User(
                username="admin",
                email="admin@threatscanner.com",
                is_admin=True
            )
            admin_user.set_password("admin123")  # Change this password in production!
            db.add(admin_user)
            db.commit()
            print("✓ Default admin user created!")
            print("  Username: admin")
            print("  Password: admin123")
            print("  ⚠️  Please change the admin password after first login!")
        else:
            print("✓ Admin user already exists")
    except Exception as e:
        print(f"⚠️  Error creating admin user: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    init_database()
