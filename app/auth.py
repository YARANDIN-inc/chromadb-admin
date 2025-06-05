from fastapi import Depends, HTTPException, status, Request, Cookie
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime, timedelta
import functools
import hashlib
import time

from .database import get_db
from .models import User, UserSession, ChromaDBInstance

# Simple in-memory rate limiting (in production, use Redis)
failed_login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 300  # 5 minutes

class AuthManager:
    @staticmethod
    def get_client_ip(request: Request) -> str:
        """Get client IP address for rate limiting"""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host
    
    @staticmethod
    def is_rate_limited(ip_address: str) -> bool:
        """Check if IP is rate limited for failed login attempts"""
        now = time.time()
        
        # Clean old entries
        expired_ips = [ip for ip, (count, timestamp) in failed_login_attempts.items() 
                      if now - timestamp > LOCKOUT_DURATION]
        for ip in expired_ips:
            del failed_login_attempts[ip]
        
        if ip_address in failed_login_attempts:
            count, timestamp = failed_login_attempts[ip_address]
            if count >= MAX_LOGIN_ATTEMPTS and now - timestamp < LOCKOUT_DURATION:
                return True
        return False
    
    @staticmethod
    def record_failed_login(ip_address: str):
        """Record a failed login attempt"""
        now = time.time()
        if ip_address in failed_login_attempts:
            count, _ = failed_login_attempts[ip_address]
            failed_login_attempts[ip_address] = (count + 1, now)
        else:
            failed_login_attempts[ip_address] = (1, now)
    
    @staticmethod
    def clear_failed_login(ip_address: str):
        """Clear failed login attempts for successful login"""
        if ip_address in failed_login_attempts:
            del failed_login_attempts[ip_address]
    
    @staticmethod
    def get_current_user(request: Request, session_token: Optional[str] = Cookie(None), db: Session = Depends(get_db)) -> Optional[User]:
        """Get current user from session token"""
        if not session_token:
            return None
        
        # Validate session token format
        if len(session_token) != 43:  # token_urlsafe(32) generates 43 chars
            return None
        
        # Get session from database
        session = db.query(UserSession).filter(
            UserSession.session_token == session_token,
            UserSession.is_active == True,
            UserSession.expires_at > datetime.utcnow()
        ).first()
        
        if not session:
            return None
        
        # Validate session fingerprint (basic session hijacking protection)
        user_agent = request.headers.get("user-agent", "")
        client_ip = AuthManager.get_client_ip(request)
        expected_fingerprint = hashlib.sha256(f"{user_agent}{client_ip}".encode()).hexdigest()[:16]
        
        if hasattr(session, 'fingerprint') and session.fingerprint != expected_fingerprint:
            # Session potentially hijacked, deactivate it
            session.is_active = False
            db.commit()
            return None
        
        user = db.query(User).filter(
            User.id == session.user_id,
            User.is_active == True
        ).first()
        
        return user
    
    @staticmethod
    def require_auth(request: Request, session_token: Optional[str] = Cookie(None), db: Session = Depends(get_db)) -> User:
        """Require authentication - raises exception if not authenticated"""
        user = AuthManager.get_current_user(request, session_token, db)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required"
            )
        return user
    
    @staticmethod
    def require_instance_permission(instance_id: int, permission: str):
        """Decorator to require specific permission for a ChromaDB instance"""
        def decorator(func):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                # Extract user and db from kwargs
                user = None
                db = None
                for key, value in kwargs.items():
                    if isinstance(value, User):
                        user = value
                    elif isinstance(value, Session):
                        db = value
                
                if not user or not db:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required"
                    )
                
                # Check if instance exists and is active
                instance = db.query(ChromaDBInstance).filter(
                    ChromaDBInstance.id == instance_id,
                    ChromaDBInstance.is_active == True
                ).first()
                
                if not instance:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="ChromaDB instance not found"
                    )
                
                # Check permission
                if not user.has_instance_permission(instance_id, permission):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Permission '{permission}' required for instance '{instance.name}'"
                    )
                
                return await func(*args, **kwargs)
            return wrapper
        return decorator
    
    @staticmethod
    def check_instance_permission(user: User, instance_id: int, permission: str, db: Session) -> bool:
        """Check if user has permission for a specific instance"""
        if user.is_super_admin:
            return True
        
        # Check if instance exists and is active
        instance = db.query(ChromaDBInstance).filter(
            ChromaDBInstance.id == instance_id,
            ChromaDBInstance.is_active == True
        ).first()
        
        if not instance:
            return False
        
        return user.has_instance_permission(instance_id, permission)
    
    @staticmethod
    def get_user_accessible_instances(user: User, db: Session) -> List[ChromaDBInstance]:
        """Get all ChromaDB instances the user has access to"""
        if user.is_super_admin:
            return db.query(ChromaDBInstance).filter(ChromaDBInstance.is_active == True).all()
        
        # Get instances where user has any permission
        accessible_instances = []
        for instance in db.query(ChromaDBInstance).filter(ChromaDBInstance.is_active == True).all():
            if user.get_instance_permissions(instance.id):
                accessible_instances.append(instance)
        
        return accessible_instances
    
    @staticmethod
    def create_session(user: User, db: Session, request: Request = None) -> str:
        """Create a new session for user"""
        # Deactivate old sessions (only keep one active session per user)
        db.query(UserSession).filter(
            UserSession.user_id == user.id,
            UserSession.is_active == True
        ).update({UserSession.is_active: False})
        
        # Create session fingerprint for basic hijacking protection
        fingerprint = ""
        if request:
            user_agent = request.headers.get("user-agent", "")
            client_ip = AuthManager.get_client_ip(request)
            fingerprint = hashlib.sha256(f"{user_agent}{client_ip}".encode()).hexdigest()[:16]
        
        # Create new session
        session_token = UserSession.generate_token()
        expires_at = datetime.utcnow() + timedelta(days=7)  # 7 days
        
        session = UserSession(
            user_id=user.id,
            session_token=session_token,
            expires_at=expires_at
        )
        
        # Add fingerprint if available
        if fingerprint:
            session.fingerprint = fingerprint
        
        db.add(session)
        db.commit()
        
        # Update last login
        user.last_login = datetime.utcnow()
        db.commit()
        
        return session_token
    
    @staticmethod
    def logout(session_token: str, db: Session) -> bool:
        """Logout user by deactivating session"""
        session = db.query(UserSession).filter(
            UserSession.session_token == session_token
        ).first()
        
        if session:
            session.is_active = False
            db.commit()
            return True
        return False

# Dependency functions
def get_current_user_optional(request: Request, session_token: Optional[str] = Cookie(None), db: Session = Depends(get_db)) -> Optional[User]:
    """Optional authentication dependency"""
    return AuthManager.get_current_user(request, session_token, db)

def get_current_user_required(request: Request, session_token: Optional[str] = Cookie(None), db: Session = Depends(get_db)) -> User:
    """Required authentication dependency"""
    return AuthManager.require_auth(request, session_token, db)

def require_super_admin(user: User = Depends(get_current_user_required)) -> User:
    """Require super admin role"""
    if not user.is_super_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin access required"
        )
    return user

def require_admin_permission(user: User = Depends(get_current_user_required)) -> User:
    """Require admin permission"""
    if not (user.can_admin or user.is_super_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin permission required"
        )
    return user

def require_any_instance_access(user: User = Depends(get_current_user_required), db: Session = Depends(get_db)) -> User:
    """Require user to have access to at least one ChromaDB instance"""
    if user.is_super_admin:
        return user
    
    accessible_instances = AuthManager.get_user_accessible_instances(user, db)
    if not accessible_instances:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No access to any ChromaDB instances"
        )
    return user 