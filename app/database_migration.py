"""
Database migration script for multi-instance ChromaDB support
This script handles the migration from single-instance to multi-instance schema.
"""

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import OperationalError
import os
from .config import settings
from .models import Base, ChromaDBInstance, User, UserInstancePermission

def migrate_database():
    """
    Migrate the database schema to support multi-instance ChromaDB.
    
    WARNING: This will drop and recreate all tables, losing existing data.
    In production, you should use proper migrations with Alembic.
    """
    print("🔄 Starting database migration for multi-instance support...")
    
    # Create engine
    engine = create_engine(settings.DATABASE_URL)
    
    try:
        # Drop all existing tables
        print("⚠️  Dropping existing tables...")
        Base.metadata.drop_all(bind=engine)
        
        # Create all tables with new schema
        print("✅ Creating tables with new multi-instance schema...")
        Base.metadata.create_all(bind=engine)
        
        # Create a sample ChromaDB instance
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db = SessionLocal()
        
        try:
            # Check if we need to create a default instance
            existing_instances = db.query(ChromaDBInstance).count()
            if existing_instances == 0:
                print("📝 Creating default ChromaDB instance...")
                default_instance = ChromaDBInstance(
                    name="default",
                    url="http://chromadb:8000",
                    description="Default ChromaDB instance",
                    is_default=True,
                    is_active=True
                )
                db.add(default_instance)
                db.commit()
                print(f"✅ Created default instance: {default_instance.name}")
                
                # If there are existing users, give them permissions on the default instance
                users = db.query(User).all()
                for user in users:
                    if not user.is_super_admin:  # Super admins get automatic access
                        permission = UserInstancePermission(
                            user_id=user.id,
                            instance_id=default_instance.id,
                            can_search=True,
                            can_create=True,
                            can_add=True,
                            can_manage=False
                        )
                        db.add(permission)
                        print(f"✅ Granted permissions to user {user.username} on default instance")
                
                db.commit()
            
        finally:
            db.close()
        
        print("🎉 Database migration completed successfully!")
        print("💡 You can now:")
        print("   - Access the application at http://localhost:8080")
        print("   - Login with your existing credentials")
        print("   - Manage multiple ChromaDB instances via the web interface")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        raise

    # Run database migrations for security updates
    migrations = [
        {
            "version": "001_add_session_fingerprint",
            "description": "Add fingerprint column to user_sessions table",
            "sql": """
                ALTER TABLE user_sessions 
                ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(32);
            """
        }
    ]
    
    print("🔄 Running database migrations...")
    
    for migration in migrations:
        try:
            with engine.connect() as conn:
                print(f"  - Running {migration['version']}: {migration['description']}")
                conn.execute(text(migration['sql']))
                conn.commit()
                print(f"  ✅ {migration['version']} completed successfully")
        except OperationalError as e:
            if "already exists" in str(e).lower() or "duplicate column" in str(e).lower():
                print(f"  ⏭️  {migration['version']} already applied")
            else:
                print(f"  ❌ {migration['version']} failed: {e}")
        except Exception as e:
            print(f"  ❌ {migration['version']} failed: {e}")
    
    print("✅ Database migrations completed")

if __name__ == "__main__":
    migrate_database() 