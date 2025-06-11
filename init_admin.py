#!/usr/bin/env python3
"""
Initialize the first super admin user for ChromaDB Admin Panel
Run this script after starting the application for the first time
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database import SessionLocal, engine
from app.models import Base, User

def create_super_admin():
    """Create the first super admin user"""
    
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        # Check if any users exist
        existing_users = db.query(User).count()
        
        if existing_users > 0:
            print("Users already exist in the database.")
            print("Current users:")
            users = db.query(User).all()
            for user in users:
                role = "Super Admin" if user.is_super_admin else "User"
                print(f"  - {user.username} ({user.email}) - {role}")
            return
        
        print("Creating first super admin user...")
        
        # Get user input
        username = input("Enter username for super admin: ").strip()
        if not username:
            print("Username cannot be empty!")
            return
        
        email = input("Enter email for super admin: ").strip()
        if not email:
            print("Email cannot be empty!")
            return
        
        password = input("Enter password for super admin: ").strip()
        if not password:
            print("Password cannot be empty!")
            return
        
        # Create super admin user
        admin_user = User(
            username=username,
            email=email,
            is_super_admin=True,
            can_search=True,
            can_create=True,
            can_add=True,
            can_admin=True,
            is_active=True
        )
        admin_user.set_password(password)
        
        db.add(admin_user)
        db.commit()
        
        print(f"\n✅ Super admin user '{username}' created successfully!")
        print(f"You can now login at http://localhost:8080/auth/login")
        print(f"Username: {username}")
        print(f"Email: {email}")
        
    except Exception as e:
        print(f"❌ Error creating super admin: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    create_super_admin() 