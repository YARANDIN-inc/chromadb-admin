import os
from dotenv import load_dotenv, find_dotenv
import secrets

load_dotenv(os.getenv("DOTENV_PATH", find_dotenv()) or ".env", override=True)

print(os.getenv("DOTENV_PATH", find_dotenv()) or ".env")

class Settings:
    # Database Configuration
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        "postgresql://chromadb:password@postgres:5432/chromadb_admin"
    )
    
    # ChromaDB Configuration
    CHROMADB_URL: str = os.getenv("CHROMADB_URL", "http://chromadb:8000")
    CHROMADB_TOKEN: str = os.getenv("CHROMADB_TOKEN", "")  # No default token for security
    
    # Security Configuration
    SECRET_KEY: str = os.getenv("SECRET_KEY", "")

    CSRF_SECRET_KEY: str = os.getenv("CSRF_SECRET_KEY", "")

    # Initial Admin User Configuration (for automatic setup)
    INITIAL_ADMIN_USERNAME: str = os.getenv("INITIAL_ADMIN_USERNAME", "")
    INITIAL_ADMIN_EMAIL: str = os.getenv("INITIAL_ADMIN_EMAIL", "")
    INITIAL_ADMIN_PASSWORD: str = os.getenv("INITIAL_ADMIN_PASSWORD", "")
    CREATE_INITIAL_ADMIN: bool = os.getenv("CREATE_INITIAL_ADMIN", "false").lower() in ("true", "1", "yes")

    PASSWORD_VALIDATION_ENABLED: bool = os.getenv("PASSWORD_VALIDATION_ENABLED", "true").lower() in ("true", "1", "yes")
    
    def __post_init__(self):
        # Validate security settings
        if not self.CSRF_SECRET_KEY:
            print("⚠️  ERROR: CSRF_SECRET_KEY must be set.")
            raise ValueError("CSRF_SECRET_KEY must be set.")

        if not self.SECRET_KEY:
            print("⚠️  WARNING: SECRET_KEY not set. Generating a random key for this session.")
            print("⚠️  Set SECRET_KEY environment variable for production use.")
            self.SECRET_KEY = secrets.token_urlsafe(32)
        elif len(self.SECRET_KEY) < 32:
            print("⚠️  WARNING: SECRET_KEY is too short. Use at least 32 characters.")
            
        if not self.CHROMADB_TOKEN:
            print("⚠️  INFO: CHROMADB_TOKEN not set. Authentication to ChromaDB will be disabled.")

settings = Settings()
settings.__post_init__()