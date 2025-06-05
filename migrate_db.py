#!/usr/bin/env python3
"""
Standalone database migration script for ChromaDB Admin multi-instance support.
Run this script to migrate your database schema.
"""

import os
import sys

# Add the app directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from app.database_migration import migrate_database

if __name__ == "__main__":
    print("🚀 ChromaDB Admin - Database Migration Script")
    print("=" * 50)
    
    # Confirm migration
    response = input("⚠️  This will recreate all database tables. Continue? (y/N): ")
    if response.lower() != 'y':
        print("❌ Migration cancelled.")
        sys.exit(1)
    
    try:
        migrate_database()
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        sys.exit(1) 