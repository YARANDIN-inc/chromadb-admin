from fastapi import Depends, HTTPException, status, Request, Cookie
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime, timedelta
import functools

from .database import get_db
from .models import User, UserSession

class AuthManager:
    @staticmethod
    def get_current_user(request: Request, session_token: Optional[str] = Cookie(None), db: Session = Depends(get_db)) -> Optional[User]:
        """Get current user from session token"""
        if not session_token:
            return None
        
        # Get session from database
        session = db.query(UserSession).filter(
            UserSession.session_token == session_token,
            UserSession.is_active == True,
            UserSession.expires_at > datetime.utcnow()
        ).first()
        
        if not session:
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
    def require_permission(permission: str):
        """Decorator to require specific permission"""
        def decorator(func):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                # Extract user from kwargs (should be injected by require_auth)
                user = None
                for key, value in kwargs.items():
                    if isinstance(value, User):
                        user = value
                        break
                
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required"
                    )
                
                # Check permission
                if permission == 'admin' and not (user.can_admin or user.is_super_admin):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Admin permission required"
                    )
                elif permission == 'create' and not (user.can_create or user.is_super_admin):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Create permission required"
                    )
                elif permission == 'add' and not (user.can_add or user.is_super_admin):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Add documents permission required"
                    )
                elif permission == 'search' and not (user.can_search or user.is_super_admin):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Search permission required"
                    )
                
                return await func(*args, **kwargs)
            return wrapper
        return decorator
    
    @staticmethod
    def create_session(user: User, db: Session) -> str:
        """Create a new session for user"""
        # Deactivate old sessions
        db.query(UserSession).filter(
            UserSession.user_id == user.id,
            UserSession.is_active == True
        ).update({UserSession.is_active: False})
        
        # Create new session
        session_token = UserSession.generate_token()
        expires_at = datetime.utcnow() + timedelta(days=7)  # 7 days
        
        session = UserSession(
            user_id=user.id,
            session_token=session_token,
            expires_at=expires_at
        )
        
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