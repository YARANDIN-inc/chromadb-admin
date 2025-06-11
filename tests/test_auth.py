import pytest
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.auth import (
    AuthManager, get_current_user_optional, get_current_user_required,
    require_super_admin, require_admin_permission, require_any_instance_access,
    failed_login_attempts, MAX_LOGIN_ATTEMPTS, LOCKOUT_DURATION
)
from app.models import User, UserSession, ChromaDBInstance, UserInstancePermission


class TestAuthManager:
    """Test AuthManager functionality"""
    
    def test_get_client_ip_forwarded(self):
        """Test getting client IP from X-Forwarded-For header"""
        mock_request = Mock()
        mock_request.headers.get.return_value = "192.168.1.1, 10.0.0.1"
        mock_request.client.host = "127.0.0.1"
        
        ip = AuthManager.get_client_ip(mock_request)
        assert ip == "192.168.1.1"
    
    def test_get_client_ip_direct(self):
        """Test getting client IP directly"""
        mock_request = Mock()
        mock_request.headers.get.return_value = None
        mock_request.client.host = "127.0.0.1"
        
        ip = AuthManager.get_client_ip(mock_request)
        assert ip == "127.0.0.1"
    
    def test_rate_limiting_flow(self):
        """Test rate limiting functionality"""
        ip = "192.168.1.1"
        
        # Initially not rate limited
        assert AuthManager.is_rate_limited(ip) is False
        
        # Record failed attempts
        for i in range(MAX_LOGIN_ATTEMPTS - 1):
            AuthManager.record_failed_login(ip)
            assert AuthManager.is_rate_limited(ip) is False
        
        # One more should trigger rate limiting
        AuthManager.record_failed_login(ip)
        assert AuthManager.is_rate_limited(ip) is True
        
        # Clear should remove rate limiting
        AuthManager.clear_failed_login(ip)
        assert AuthManager.is_rate_limited(ip) is False
    
    def test_rate_limiting_expiry(self):
        """Test rate limiting expiry"""
        ip = "192.168.1.1"
        
        # Trigger rate limiting
        for i in range(MAX_LOGIN_ATTEMPTS):
            AuthManager.record_failed_login(ip)
        
        assert AuthManager.is_rate_limited(ip) is True
        
        # Mock time to simulate expiry
        current_time = time.time()
        with patch('app.auth.time.time', return_value=current_time + LOCKOUT_DURATION + 1):
            assert AuthManager.is_rate_limited(ip) is False
    
    @patch('app.auth.hashlib.sha256')
    def test_get_current_user_valid_session(self, mock_sha256, db_session: Session, sample_user: User):
        """Test getting current user with valid session"""
        # Create session
        session = UserSession(
            user_id=sample_user.id,
            session_token=UserSession.generate_token(),
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active=True,
            fingerprint="test_fingerprint"
        )
        db_session.add(session)
        db_session.commit()
        
        # Mock request
        mock_request = Mock()
        mock_request.headers.get.return_value = "test-user-agent"
        mock_request.client.host = "127.0.0.1"
        
        # Mock fingerprint calculation
        mock_hash = Mock()
        mock_hash.hexdigest.return_value = "test_fingerprint" + "0" * 16
        mock_sha256.return_value = mock_hash
        
        user = AuthManager.get_current_user(mock_request, session.session_token, db_session)
        assert user is not None
        assert user.id == sample_user.id
    
    def test_get_current_user_no_token(self, db_session: Session):
        """Test getting current user without token"""
        mock_request = Mock()
        
        user = AuthManager.get_current_user(mock_request, None, db_session)
        assert user is None
    
    def test_get_current_user_invalid_token_format(self, db_session: Session):
        """Test getting current user with invalid token format"""
        mock_request = Mock()
        
        user = AuthManager.get_current_user(mock_request, "invalid_token", db_session)
        assert user is None
    
    def test_get_current_user_expired_session(self, db_session: Session, sample_user: User):
        """Test getting current user with expired session"""
        # Create expired session
        session = UserSession(
            user_id=sample_user.id,
            session_token=UserSession.generate_token(),
            expires_at=datetime.utcnow() - timedelta(days=1),  # Expired
            is_active=True
        )
        db_session.add(session)
        db_session.commit()
        
        mock_request = Mock()
        user = AuthManager.get_current_user(mock_request, session.session_token, db_session)
        assert user is None
    
    def test_get_current_user_inactive_session(self, db_session: Session, sample_user: User):
        """Test getting current user with inactive session"""
        # Create inactive session
        session = UserSession(
            user_id=sample_user.id,
            session_token=UserSession.generate_token(),
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active=False  # Inactive
        )
        db_session.add(session)
        db_session.commit()
        
        mock_request = Mock()
        user = AuthManager.get_current_user(mock_request, session.session_token, db_session)
        assert user is None
    
    def test_get_current_user_inactive_user(self, db_session: Session):
        """Test getting current user with inactive user"""
        # Create inactive user
        user = User(
            username="inactive_user",
            email="inactive@example.com",
            is_active=False
        )
        user.set_password("Test123!@#")
        db_session.add(user)
        db_session.commit()
        
        # Create session for inactive user
        session = UserSession(
            user_id=user.id,
            session_token=UserSession.generate_token(),
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active=True
        )
        db_session.add(session)
        db_session.commit()
        
        mock_request = Mock()
        mock_request.headers = {"User-Agent": "test-agent"}
        mock_request.client.host = "127.0.0.1"
        
        result_user = AuthManager.get_current_user(mock_request, session.session_token, db_session)
        assert result_user is None
    
    def test_require_auth_with_user(self, db_session: Session, sample_user: User):
        """Test require_auth with valid user"""
        session = UserSession(
            user_id=sample_user.id,
            session_token=UserSession.generate_token(),
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active=True
        )
        db_session.add(session)
        db_session.commit()
        
        with patch.object(AuthManager, 'get_current_user', return_value=sample_user):
            mock_request = Mock()
            user = AuthManager.require_auth(mock_request, session.session_token, db_session)
            assert user == sample_user
    
    def test_require_auth_without_user(self, db_session: Session):
        """Test require_auth without valid user"""
        with patch.object(AuthManager, 'get_current_user', return_value=None):
            mock_request = Mock()
            with pytest.raises(HTTPException) as exc_info:
                AuthManager.require_auth(mock_request, "invalid_token", db_session)
            assert exc_info.value.status_code == 401
    
    def test_check_instance_permission_super_admin(self, db_session: Session, super_admin_user: User, sample_instance: ChromaDBInstance):
        """Test instance permission check for super admin"""
        result = AuthManager.check_instance_permission(
            super_admin_user, sample_instance.id, "any_permission", db_session
        )
        assert result is True
    
    def test_check_instance_permission_with_permission(self, db_session: Session, sample_user: User, sample_instance: ChromaDBInstance):
        """Test instance permission check with valid permission"""
        # Create permission
        permission = UserInstancePermission(
            user_id=sample_user.id,
            instance_id=sample_instance.id,
            can_search=True
        )
        db_session.add(permission)
        db_session.commit()
        db_session.refresh(sample_user)
        
        result = AuthManager.check_instance_permission(
            sample_user, sample_instance.id, "search", db_session
        )
        assert result is True
        
        result = AuthManager.check_instance_permission(
            sample_user, sample_instance.id, "create", db_session
        )
        assert result is False
    
    def test_check_instance_permission_no_permission(self, db_session: Session, sample_user: User, sample_instance: ChromaDBInstance):
        """Test instance permission check without permission"""
        result = AuthManager.check_instance_permission(
            sample_user, sample_instance.id, "search", db_session
        )
        assert result is False
    
    def test_check_instance_permission_inactive_instance(self, db_session: Session, sample_user: User):
        """Test instance permission check for inactive instance"""
        # Create inactive instance
        instance = ChromaDBInstance(
            name="inactive-instance",
            url="http://localhost:8002",
            is_active=False
        )
        db_session.add(instance)
        db_session.commit()
        
        result = AuthManager.check_instance_permission(
            sample_user, instance.id, "search", db_session
        )
        assert result is False
    
    def test_get_user_accessible_instances_super_admin(self, db_session: Session, super_admin_user: User, sample_instance: ChromaDBInstance):
        """Test getting accessible instances for super admin"""
        instances = AuthManager.get_user_accessible_instances(super_admin_user, db_session)
        assert len(instances) == 1
        assert instances[0].id == sample_instance.id
    
    def test_get_user_accessible_instances_with_permissions(self, db_session: Session, sample_user: User, sample_instance: ChromaDBInstance):
        """Test getting accessible instances with permissions"""
        # Initially no access
        instances = AuthManager.get_user_accessible_instances(sample_user, db_session)
        assert len(instances) == 0
        
        # Create permission
        permission = UserInstancePermission(
            user_id=sample_user.id,
            instance_id=sample_instance.id,
            can_search=True
        )
        db_session.add(permission)
        db_session.commit()
        db_session.refresh(sample_user)
        
        instances = AuthManager.get_user_accessible_instances(sample_user, db_session)
        assert len(instances) == 1
        assert instances[0].id == sample_instance.id
    
    def test_create_session(self, db_session: Session, sample_user: User):
        """Test creating a session"""
        mock_request = Mock()
        mock_request.headers.get.return_value = "test-user-agent"
        mock_request.client.host = "127.0.0.1"
        
        session_token = AuthManager.create_session(sample_user, db_session, mock_request)
        
        assert session_token is not None
        assert len(session_token) == 43
        
        # Check session was created in database
        session = db_session.query(UserSession).filter(
            UserSession.session_token == session_token
        ).first()
        assert session is not None
        assert session.user_id == sample_user.id
        assert session.is_active is True
    
    def test_create_session_deactivates_old_sessions(self, db_session: Session, sample_user: User):
        """Test creating session deactivates old sessions"""
        # Create old session
        old_session = UserSession(
            user_id=sample_user.id,
            session_token=UserSession.generate_token(),
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active=True
        )
        db_session.add(old_session)
        db_session.commit()
        
        mock_request = Mock()
        mock_request.headers.get.return_value = "test-user-agent"
        mock_request.client.host = "127.0.0.1"
        
        # Create new session
        new_token = AuthManager.create_session(sample_user, db_session, mock_request)
        
        # Check old session is deactivated
        db_session.refresh(old_session)
        assert old_session.is_active is False
        
        # Check new session is active
        new_session = db_session.query(UserSession).filter(
            UserSession.session_token == new_token
        ).first()
        assert new_session.is_active is True


class TestAuthDependencies:
    """Test authentication dependency functions"""
    
    def test_get_current_user_optional_with_user(self, db_session: Session, sample_user: User):
        """Test optional user dependency with valid user"""
        mock_request = Mock()
        session_token = "valid_token"
        
        with patch.object(AuthManager, 'get_current_user', return_value=sample_user):
            user = get_current_user_optional(mock_request, session_token, db_session)
            assert user == sample_user
    
    def test_get_current_user_optional_without_user(self, db_session: Session):
        """Test optional user dependency without user"""
        mock_request = Mock()
        session_token = None
        
        with patch.object(AuthManager, 'get_current_user', return_value=None):
            user = get_current_user_optional(mock_request, session_token, db_session)
            assert user is None
    
    def test_get_current_user_required_with_user(self, db_session: Session, sample_user: User):
        """Test required user dependency with valid user"""
        mock_request = Mock()
        session_token = "valid_token"
        
        with patch.object(AuthManager, 'get_current_user', return_value=sample_user):
            user = get_current_user_required(mock_request, session_token, db_session)
            assert user == sample_user
    
    def test_get_current_user_required_without_user(self, db_session: Session):
        """Test required user dependency without user"""
        mock_request = Mock()
        session_token = None
        
        with patch.object(AuthManager, 'get_current_user', return_value=None):
            with pytest.raises(HTTPException) as exc_info:
                get_current_user_required(mock_request, session_token, db_session)
            assert exc_info.value.status_code == 401
    
    def test_require_super_admin_with_super_admin(self, super_admin_user: User):
        """Test super admin requirement with super admin user"""
        user = require_super_admin(super_admin_user)
        assert user == super_admin_user
    
    def test_require_super_admin_with_regular_user(self, sample_user: User):
        """Test super admin requirement with regular user"""
        with pytest.raises(HTTPException) as exc_info:
            require_super_admin(sample_user)
        assert exc_info.value.status_code == 403
    
    def test_require_admin_permission_with_admin(self, admin_user: User):
        """Test admin permission requirement with admin user"""
        user = require_admin_permission(admin_user)
        assert user == admin_user
    
    def test_require_admin_permission_with_super_admin(self, super_admin_user: User):
        """Test admin permission requirement with super admin"""
        user = require_admin_permission(super_admin_user)
        assert user == super_admin_user
    
    def test_require_admin_permission_with_regular_user(self, sample_user: User):
        """Test admin permission requirement with regular user"""
        with pytest.raises(HTTPException) as exc_info:
            require_admin_permission(sample_user)
        assert exc_info.value.status_code == 403
    
    def test_require_any_instance_access_with_super_admin(self, db_session: Session, super_admin_user: User):
        """Test instance access requirement with super admin"""
        user = require_any_instance_access(super_admin_user, db_session)
        assert user == super_admin_user
    
    def test_require_any_instance_access_with_permissions(self, db_session: Session, sample_user: User, sample_instance: ChromaDBInstance):
        """Test instance access requirement with permissions"""
        # Create permission
        permission = UserInstancePermission(
            user_id=sample_user.id,
            instance_id=sample_instance.id,
            can_search=True
        )
        db_session.add(permission)
        db_session.commit()
        db_session.refresh(sample_user)
        
        user = require_any_instance_access(sample_user, db_session)
        assert user == sample_user
    
    def test_require_any_instance_access_without_permissions(self, db_session: Session, sample_user: User):
        """Test instance access requirement without permissions"""
        with pytest.raises(HTTPException) as exc_info:
            require_any_instance_access(sample_user, db_session)
        assert exc_info.value.status_code == 403


class TestRateLimiting:
    """Test rate limiting functionality in isolation"""
    
    def setup_method(self):
        """Clear rate limiting cache before each test"""
        failed_login_attempts.clear()
    
    def teardown_method(self):
        """Clear rate limiting cache after each test"""
        failed_login_attempts.clear()
    
    def test_rate_limiting_multiple_ips(self):
        """Test rate limiting with multiple IPs"""
        ip1 = "192.168.1.1"
        ip2 = "192.168.1.2"
        
        # Rate limit first IP
        for i in range(MAX_LOGIN_ATTEMPTS):
            AuthManager.record_failed_login(ip1)
        
        assert AuthManager.is_rate_limited(ip1) is True
        assert AuthManager.is_rate_limited(ip2) is False
        
        # Second IP should still work
        AuthManager.record_failed_login(ip2)
        assert AuthManager.is_rate_limited(ip2) is False
    
    def test_rate_limiting_cleanup(self):
        """Test rate limiting cleanup of expired entries"""
        ip1 = "192.168.1.1"
        ip2 = "192.168.1.2"
        
        current_time = time.time()
        
        # Rate limit ip1 at current time
        with patch('app.auth.time.time', return_value=current_time):
            for i in range(MAX_LOGIN_ATTEMPTS):
                AuthManager.record_failed_login(ip1)
            assert AuthManager.is_rate_limited(ip1) is True
        
        # Rate limit ip2 at a later time
        later_time = current_time + 100  # 100 seconds later
        with patch('app.auth.time.time', return_value=later_time):
            for i in range(MAX_LOGIN_ATTEMPTS):
                AuthManager.record_failed_login(ip2)
            assert AuthManager.is_rate_limited(ip2) is True
        
        # Now, move time forward to expire ip1 but not ip2
        expired_time = current_time + LOCKOUT_DURATION + 1
        with patch('app.auth.time.time', return_value=expired_time):
            # ip1 should be expired and cleaned up
            assert AuthManager.is_rate_limited(ip1) is False
            # ip2 should still be rate limited (not yet expired)
            assert AuthManager.is_rate_limited(ip2) is True 