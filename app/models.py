from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, JSON, ForeignKey, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from passlib.context import CryptContext
import secrets
import re

Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Input validation patterns
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{3,50}$')

class ChromaDBInstance(Base):
    __tablename__ = "chromadb_instances"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    url = Column(String(255), nullable=False)
    token = Column(String(255), nullable=True)  # Optional authentication token
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    is_default = Column(Boolean, default=False)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    collections = relationship("Collection", back_populates="instance")
    user_permissions = relationship("UserInstancePermission", back_populates="instance")
    query_logs = relationship("QueryLog", back_populates="instance")

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_super_admin = Column(Boolean, default=False)
    
    # Global permissions (for admin functions)
    can_admin = Column(Boolean, default=False)  # Can manage users and instances
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_login = Column(DateTime(timezone=True))
    
    # Relationships
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    created_collections = relationship("Collection", back_populates="created_by")
    query_logs = relationship("QueryLog", back_populates="user")
    instance_permissions = relationship("UserInstancePermission", back_populates="user", cascade="all, delete-orphan")
    
    def verify_password(self, password: str) -> bool:
        if not password:
            return False
        return pwd_context.verify(password, self.hashed_password)
    
    def set_password(self, password: str):
        if not self.validate_password(password):
            raise ValueError("Password does not meet security requirements")
        self.hashed_password = pwd_context.hash(password)
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """Validate username format"""
        if not username:
            return False
        return bool(USERNAME_PATTERN.match(username))
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        if not email:
            return False
        return bool(EMAIL_PATTERN.match(email))
    
    @staticmethod
    def validate_password(password: str) -> bool:
        """Validate password strength"""
        if not password or len(password) < 8:
            return False
        
        # Check for at least one lowercase, uppercase, digit, and special character
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        return has_lower and has_upper and has_digit and has_special
    
    def get_instance_permissions(self, instance_id: int):
        """Get user permissions for a specific instance"""
        for perm in self.instance_permissions:
            if perm.instance_id == instance_id:
                return perm
        return None
    
    def has_instance_permission(self, instance_id: int, permission: str) -> bool:
        """Check if user has specific permission for an instance"""
        if self.is_super_admin:
            return True
        
        perm = self.get_instance_permissions(instance_id)
        if not perm:
            return False
        
        return getattr(perm, f"can_{permission}", False)

class UserInstancePermission(Base):
    __tablename__ = "user_instance_permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    instance_id = Column(Integer, ForeignKey("chromadb_instances.id"), nullable=False)
    
    # Instance-level permissions
    can_search = Column(Boolean, default=True)   # Can search documents
    can_create = Column(Boolean, default=False)  # Can create/delete collections
    can_add = Column(Boolean, default=False)     # Can add documents
    can_manage = Column(Boolean, default=False)  # Can manage instance settings
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    user = relationship("User", back_populates="instance_permissions")
    instance = relationship("ChromaDBInstance", back_populates="user_permissions")
    
    # Ensure one permission record per user per instance
    __table_args__ = (UniqueConstraint('user_id', 'instance_id', name='unique_user_instance'),)

class UserSession(Base):
    __tablename__ = "user_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    session_token = Column(String(255), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_active = Column(Boolean, default=True)
    fingerprint = Column(String(32), nullable=True)  # For basic session hijacking protection
    
    user = relationship("User", back_populates="sessions")
    
    @classmethod
    def generate_token(cls) -> str:
        return secrets.token_urlsafe(32)

class Collection(Base):
    __tablename__ = "collections"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), index=True)
    instance_id = Column(Integer, ForeignKey("chromadb_instances.id"), nullable=False)
    collection_metadata = Column(JSON, default=dict)
    document_count = Column(Integer, default=0)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    created_by = relationship("User", back_populates="created_collections")
    instance = relationship("ChromaDBInstance", back_populates="collections")
    
    # Ensure collection names are unique per instance
    __table_args__ = (UniqueConstraint('name', 'instance_id', name='unique_collection_per_instance'),)

class QueryLog(Base):
    __tablename__ = "query_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    instance_id = Column(Integer, ForeignKey("chromadb_instances.id"), nullable=False)
    collection_name = Column(String(100))
    query_type = Column(String(50))  # 'query', 'add', 'delete'
    query_text = Column(Text)
    results_count = Column(Integer, default=0)
    execution_time = Column(Integer, default=0)  # in milliseconds
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user = relationship("User", back_populates="query_logs")
    instance = relationship("ChromaDBInstance", back_populates="query_logs")

class SystemMetrics(Base):
    __tablename__ = "system_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    metric_name = Column(String(100))
    metric_value = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now()) 