import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    # Database Configuration
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        "postgresql://chromadb:password@postgres:5432/chromadb_admin"
    )
    
    # ChromaDB Configuration
    CHROMADB_URL: str = os.getenv("CHROMADB_URL", "http://chromadb:8000")
    CHROMADB_TOKEN: str = os.getenv("CHROMADB_TOKEN", "1234567890-change-in-production")
    
    # Security Configuration
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    
    # Initial Admin User Configuration (for automatic setup)
    INITIAL_ADMIN_USERNAME: str = os.getenv("INITIAL_ADMIN_USERNAME", "")
    INITIAL_ADMIN_EMAIL: str = os.getenv("INITIAL_ADMIN_EMAIL", "")
    INITIAL_ADMIN_PASSWORD: str = os.getenv("INITIAL_ADMIN_PASSWORD", "")
    CREATE_INITIAL_ADMIN: bool = os.getenv("CREATE_INITIAL_ADMIN", "false").lower() in ("true", "1", "yes")

settings = Settings()