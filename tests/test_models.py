import pytest
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.models import (
    User, ChromaDBInstance, Collection, QueryLog, UserSession, 
    UserInstancePermission, SystemMetrics
)


class TestUser:
    """Test User model functionality"""
    
    def test_create_user(self, db_session: Session):
        """Test creating a user"""
        user = User(
            username="testuser",
            email="test@example.com",
            is_active=True
        )
        user.set_password("Test123!@#")
        
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        
        assert user.id is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.is_active is True
        assert user.is_super_admin is False
        assert user.can_admin is False
        assert user.hashed_password is not None
    
    def test_user_password_verification(self, db_session: Session):
        """Test password hashing and verification"""
        user = User(username="testuser", email="test@example.com")
        password = "Test123!@#"
        user.set_password(password)
        
        assert user.verify_password(password) is True
        assert user.verify_password("wrongpassword") is False
        assert user.verify_password("") is False
        assert user.verify_password(None) is False
    
    def test_password_validation(self):
        """Test password strength validation"""
        # Valid passwords
        assert User.validate_password("Test123!@#") is True
        assert User.validate_password("ValidPass1!") is True
        
        # Invalid passwords
        assert User.validate_password("") is False
        assert User.validate_password("short1!") is False  # Too short
        assert User.validate_password("nouppercase1!") is False  # No uppercase
        assert User.validate_password("NOLOWERCASE1!") is False  # No lowercase
        assert User.validate_password("NoDigits!@#") is False  # No digits
        assert User.validate_password("NoSpecial123") is False  # No special chars
        assert User.validate_password(None) is False
    
    def test_username_validation(self):
        """Test username format validation"""
        # Valid usernames
        assert User.validate_username("testuser") is True
        assert User.validate_username("test_user") is True
        assert User.validate_username("test-user") is True
        assert User.validate_username("user123") is True
        assert User.validate_username("123user") is True
        
        # Invalid usernames
        assert User.validate_username("") is False
        assert User.validate_username("ab") is False  # Too short
        assert User.validate_username("a" * 51) is False  # Too long
        assert User.validate_username("test user") is False  # Spaces
        assert User.validate_username("test@user") is False  # Special chars
        assert User.validate_username(None) is False
    
    def test_email_validation(self):
        """Test email format validation"""
        # Valid emails
        assert User.validate_email("test@example.com") is True
        assert User.validate_email("user.name@domain.org") is True
        assert User.validate_email("user+tag@example.co.uk") is True
        
        # Invalid emails
        assert User.validate_email("") is False
        assert User.validate_email("invalid") is False
        assert User.validate_email("invalid@") is False
        assert User.validate_email("@example.com") is False
        assert User.validate_email("invalid.email") is False
        assert User.validate_email(None) is False
    
    def test_user_unique_constraints(self, db_session: Session):
        """Test unique constraints for username and email"""
        user1 = User(username="testuser", email="test1@example.com")
        user1.set_password("Test123!@#")
        db_session.add(user1)
        db_session.commit()
        
        # Try to create user with same username
        user2 = User(username="testuser", email="test2@example.com")
        user2.set_password("Test123!@#")
        db_session.add(user2)
        
        with pytest.raises(IntegrityError):
            db_session.commit()
        
        db_session.rollback()
        
        # Try to create user with same email
        user3 = User(username="testuser2", email="test1@example.com")
        user3.set_password("Test123!@#")
        db_session.add(user3)
        
        with pytest.raises(IntegrityError):
            db_session.commit()
    
    def test_instance_permissions(self, db_session: Session, sample_user: User, sample_instance: ChromaDBInstance):
        """Test user instance permission methods"""
        # Initially no permissions
        assert sample_user.get_instance_permissions(sample_instance.id) is None
        assert sample_user.has_instance_permission(sample_instance.id, "search") is False
        
        # Create permission
        permission = UserInstancePermission(
            user_id=sample_user.id,
            instance_id=sample_instance.id,
            can_search=True,
            can_create=False
        )
        db_session.add(permission)
        db_session.commit()
        db_session.refresh(sample_user)
        
        # Check permissions
        assert sample_user.get_instance_permissions(sample_instance.id) is not None
        assert sample_user.has_instance_permission(sample_instance.id, "search") is True
        assert sample_user.has_instance_permission(sample_instance.id, "create") is False
    
    def test_super_admin_permissions(self, db_session: Session, super_admin_user: User, sample_instance: ChromaDBInstance):
        """Test that super admin has all permissions"""
        assert super_admin_user.has_instance_permission(sample_instance.id, "search") is True
        assert super_admin_user.has_instance_permission(sample_instance.id, "create") is True
        assert super_admin_user.has_instance_permission(sample_instance.id, "add") is True
        assert super_admin_user.has_instance_permission(sample_instance.id, "manage") is True


class TestChromaDBInstance:
    """Test ChromaDBInstance model functionality"""
    
    def test_create_instance(self, db_session: Session):
        """Test creating a ChromaDB instance"""
        instance = ChromaDBInstance(
            name="test-instance",
            url="http://localhost:8001",
            description="Test instance",
            token="test-token",
            is_active=True,
            is_default=True
        )
        
        db_session.add(instance)
        db_session.commit()
        db_session.refresh(instance)
        
        assert instance.id is not None
        assert instance.name == "test-instance"
        assert instance.url == "http://localhost:8001"
        assert instance.description == "Test instance"
        assert instance.token == "test-token"
        assert instance.is_active is True
        assert instance.is_default is True
        assert instance.created_at is not None
    
    def test_instance_unique_name(self, db_session: Session):
        """Test unique constraint on instance name"""
        instance1 = ChromaDBInstance(name="test-instance", url="http://localhost:8001")
        db_session.add(instance1)
        db_session.commit()
        
        instance2 = ChromaDBInstance(name="test-instance", url="http://localhost:8002")
        db_session.add(instance2)
        
        with pytest.raises(IntegrityError):
            db_session.commit()
    
    def test_instance_relationships(self, db_session: Session, sample_instance: ChromaDBInstance, sample_user: User):
        """Test instance relationships with collections and permissions"""
        # Create collection
        collection = Collection(
            name="test-collection",
            instance_id=sample_instance.id,
            created_by_id=sample_user.id
        )
        db_session.add(collection)
        
        # Create permission
        permission = UserInstancePermission(
            user_id=sample_user.id,
            instance_id=sample_instance.id,
            can_search=True
        )
        db_session.add(permission)
        
        db_session.commit()
        db_session.refresh(sample_instance)
        
        assert len(sample_instance.collections) == 1
        assert sample_instance.collections[0].name == "test-collection"
        assert len(sample_instance.user_permissions) == 1
        assert sample_instance.user_permissions[0].can_search is True


class TestCollection:
    """Test Collection model functionality"""
    
    def test_create_collection(self, db_session: Session, sample_instance: ChromaDBInstance, sample_user: User):
        """Test creating a collection"""
        collection = Collection(
            name="test-collection",
            instance_id=sample_instance.id,
            collection_metadata={"test": "metadata"},
            document_count=10,
            created_by_id=sample_user.id
        )
        
        db_session.add(collection)
        db_session.commit()
        db_session.refresh(collection)
        
        assert collection.id is not None
        assert collection.name == "test-collection"
        assert collection.instance_id == sample_instance.id
        assert collection.collection_metadata == {"test": "metadata"}
        assert collection.document_count == 10
        assert collection.created_by_id == sample_user.id
        assert collection.created_at is not None
    
    def test_collection_unique_per_instance(self, db_session: Session, sample_instance: ChromaDBInstance, sample_user: User):
        """Test unique constraint for collection name per instance"""
        collection1 = Collection(
            name="test-collection",
            instance_id=sample_instance.id,
            created_by_id=sample_user.id
        )
        db_session.add(collection1)
        db_session.commit()
        
        # Same name, same instance should fail
        collection2 = Collection(
            name="test-collection",
            instance_id=sample_instance.id,
            created_by_id=sample_user.id
        )
        db_session.add(collection2)
        
        with pytest.raises(IntegrityError):
            db_session.commit()
        
        db_session.rollback()
        
        # Same name, different instance should work
        instance2 = ChromaDBInstance(name="instance2", url="http://localhost:8002")
        db_session.add(instance2)
        db_session.commit()
        
        collection3 = Collection(
            name="test-collection",
            instance_id=instance2.id,
            created_by_id=sample_user.id
        )
        db_session.add(collection3)
        db_session.commit()  # Should not raise exception


class TestUserSession:
    """Test UserSession model functionality"""
    
    def test_create_session(self, db_session: Session, sample_user: User):
        """Test creating a user session"""
        token = UserSession.generate_token()
        session = UserSession(
            user_id=sample_user.id,
            session_token=token,
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_active=True,
            fingerprint="test_fingerprint"
        )
        
        db_session.add(session)
        db_session.commit()
        db_session.refresh(session)
        
        assert session.id is not None
        assert session.user_id == sample_user.id
        assert session.session_token == token
        assert session.is_active is True
        assert session.fingerprint == "test_fingerprint"
        assert session.created_at is not None
    
    def test_generate_token(self):
        """Test token generation"""
        token1 = UserSession.generate_token()
        token2 = UserSession.generate_token()
        
        assert len(token1) == 43  # token_urlsafe(32) generates 43 chars
        assert len(token2) == 43
        assert token1 != token2  # Should be unique
    
    def test_session_unique_token(self, db_session: Session, sample_user: User):
        """Test unique constraint on session token"""
        token = UserSession.generate_token()
        
        session1 = UserSession(
            user_id=sample_user.id,
            session_token=token,
            expires_at=datetime.utcnow() + timedelta(days=7)
        )
        db_session.add(session1)
        db_session.commit()
        
        session2 = UserSession(
            user_id=sample_user.id,
            session_token=token,
            expires_at=datetime.utcnow() + timedelta(days=7)
        )
        db_session.add(session2)
        
        with pytest.raises(IntegrityError):
            db_session.commit()


class TestUserInstancePermission:
    """Test UserInstancePermission model functionality"""
    
    def test_create_permission(self, db_session: Session, sample_user: User, sample_instance: ChromaDBInstance):
        """Test creating user instance permissions"""
        permission = UserInstancePermission(
            user_id=sample_user.id,
            instance_id=sample_instance.id,
            can_search=True,
            can_create=True,
            can_add=False,
            can_manage=False
        )
        
        db_session.add(permission)
        db_session.commit()
        db_session.refresh(permission)
        
        assert permission.id is not None
        assert permission.user_id == sample_user.id
        assert permission.instance_id == sample_instance.id
        assert permission.can_search is True
        assert permission.can_create is True
        assert permission.can_add is False
        assert permission.can_manage is False
        assert permission.created_at is not None
    
    def test_unique_user_instance_constraint(self, db_session: Session, sample_user: User, sample_instance: ChromaDBInstance):
        """Test unique constraint for user-instance combination"""
        permission1 = UserInstancePermission(
            user_id=sample_user.id,
            instance_id=sample_instance.id,
            can_search=True
        )
        db_session.add(permission1)
        db_session.commit()
        
        # Same user-instance combination should fail
        permission2 = UserInstancePermission(
            user_id=sample_user.id,
            instance_id=sample_instance.id,
            can_create=True
        )
        db_session.add(permission2)
        
        with pytest.raises(IntegrityError):
            db_session.commit()


class TestQueryLog:
    """Test QueryLog model functionality"""
    
    def test_create_query_log(self, db_session: Session, sample_user: User, sample_instance: ChromaDBInstance):
        """Test creating a query log entry"""
        log = QueryLog(
            instance_id=sample_instance.id,
            collection_name="test-collection",
            query_type="query",
            query_text="test query",
            results_count=5,
            execution_time=150,
            user_id=sample_user.id
        )
        
        db_session.add(log)
        db_session.commit()
        db_session.refresh(log)
        
        assert log.id is not None
        assert log.instance_id == sample_instance.id
        assert log.collection_name == "test-collection"
        assert log.query_type == "query"
        assert log.query_text == "test query"
        assert log.results_count == 5
        assert log.execution_time == 150
        assert log.user_id == sample_user.id
        assert log.created_at is not None


class TestSystemMetrics:
    """Test SystemMetrics model functionality"""
    
    def test_create_system_metrics(self, db_session: Session):
        """Test creating system metrics"""
        metric = SystemMetrics(
            metric_name="cpu_usage",
            metric_value="75.5"
        )
        
        db_session.add(metric)
        db_session.commit()
        db_session.refresh(metric)
        
        assert metric.id is not None
        assert metric.metric_name == "cpu_usage"
        assert metric.metric_value == "75.5"
        assert metric.created_at is not None 