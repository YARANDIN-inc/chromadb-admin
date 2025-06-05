import pytest
import os
import tempfile
from typing import Generator
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from unittest.mock import Mock, patch

# Set test environment variables before importing app modules
os.environ["TEST_MODE"] = "1"
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["CREATE_INITIAL_ADMIN"] = "false"

from app.main import app
from app.database import get_db, Base
from app.models import User, ChromaDBInstance, Collection, QueryLog, UserSession, UserInstancePermission
from app.auth import AuthManager


# Test database setup
TEST_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session() -> Generator[Session, None, None]:
    """Create a fresh database session for each test"""
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    # Create session
    session = TestingSessionLocal()
    
    try:
        yield session
    finally:
        session.close()
        # Drop all tables after test
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Create a test client with database dependency override"""
    
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
    
    app.dependency_overrides[get_db] = override_get_db
    
    with TestClient(app) as test_client:
        yield test_client
    
    app.dependency_overrides.clear()


@pytest.fixture
def sample_user(db_session: Session) -> User:
    """Create a sample user for testing"""
    user = User(
        username="testuser",
        email="test@example.com",
        is_active=True,
        can_admin=False,
        is_super_admin=False
    )
    user.set_password("Test123!@#")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def admin_user(db_session: Session) -> User:
    """Create an admin user for testing"""
    user = User(
        username="admin",
        email="admin@example.com",
        is_active=True,
        can_admin=True,
        is_super_admin=False
    )
    user.set_password("Admin123!@#")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def super_admin_user(db_session: Session) -> User:
    """Create a super admin user for testing"""
    user = User(
        username="superadmin",
        email="superadmin@example.com",
        is_active=True,
        can_admin=True,
        is_super_admin=True
    )
    user.set_password("SuperAdmin123!@#")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def sample_instance(db_session: Session) -> ChromaDBInstance:
    """Create a sample ChromaDB instance for testing"""
    instance = ChromaDBInstance(
        name="test-instance",
        url="http://localhost:8001",
        description="Test instance",
        is_active=True,
        is_default=True
    )
    db_session.add(instance)
    db_session.commit()
    db_session.refresh(instance)
    return instance


@pytest.fixture
def sample_collection(db_session: Session, sample_instance: ChromaDBInstance, sample_user: User) -> Collection:
    """Create a sample collection for testing"""
    collection = Collection(
        name="test-collection",
        instance_id=sample_instance.id,
        collection_metadata={"test": "metadata"},
        document_count=0,
        created_by_id=sample_user.id
    )
    db_session.add(collection)
    db_session.commit()
    db_session.refresh(collection)
    return collection


@pytest.fixture
def user_session(db_session: Session, sample_user: User) -> UserSession:
    """Create a user session for testing"""
    session = UserSession(
        user_id=sample_user.id,
        session_token=UserSession.generate_token(),
        expires_at=datetime.utcnow() + timedelta(days=7),
        is_active=True,
        fingerprint="test_fingerprint"
    )
    db_session.add(session)
    db_session.commit()
    db_session.refresh(session)
    return session


@pytest.fixture
def authenticated_client(client: TestClient, user_session: UserSession, sample_user: User) -> TestClient:
    """Create an authenticated test client"""
    from app.auth import get_current_user_required, get_current_user_optional
    
    def mock_get_current_user_required(request=None, session_token=None, db=None):
        return sample_user
    
    def mock_get_current_user_optional(request=None, session_token=None, db=None):
        return sample_user
    
    app.dependency_overrides[get_current_user_required] = mock_get_current_user_required
    app.dependency_overrides[get_current_user_optional] = mock_get_current_user_optional
    
    client.cookies.set("session_token", user_session.session_token)
    
    yield client
    
    # Clean up dependency overrides
    if get_current_user_required in app.dependency_overrides:
        del app.dependency_overrides[get_current_user_required]
    if get_current_user_optional in app.dependency_overrides:
        del app.dependency_overrides[get_current_user_optional]


@pytest.fixture
def admin_authenticated_client(client: TestClient, admin_user: User, db_session: Session) -> TestClient:
    """Create an authenticated admin test client"""
    from app.auth import get_current_user_required, get_current_user_optional, require_admin_permission, require_super_admin
    
    session = UserSession(
        user_id=admin_user.id,
        session_token=UserSession.generate_token(),
        expires_at=datetime.utcnow() + timedelta(days=7),
        is_active=True,
        fingerprint="admin_fingerprint"
    )
    db_session.add(session)
    db_session.commit()
    
    def mock_get_current_user_required(request=None, session_token=None, db=None):
        return admin_user
    
    def mock_get_current_user_optional(request=None, session_token=None, db=None):
        return admin_user
    
    def mock_require_admin_permission(user=None):
        return admin_user
    
    def mock_require_super_admin(user=None):
        return admin_user
    
    app.dependency_overrides[get_current_user_required] = mock_get_current_user_required
    app.dependency_overrides[get_current_user_optional] = mock_get_current_user_optional
    app.dependency_overrides[require_admin_permission] = mock_require_admin_permission
    app.dependency_overrides[require_super_admin] = mock_require_super_admin
    
    client.cookies.set("session_token", session.session_token)
    
    yield client
    
    # Clean up dependency overrides
    for dep in [get_current_user_required, get_current_user_optional, require_admin_permission, require_super_admin]:
        if dep in app.dependency_overrides:
            del app.dependency_overrides[dep]


@pytest.fixture
def user_permission(db_session: Session, sample_user: User, sample_instance: ChromaDBInstance) -> UserInstancePermission:
    """Create user instance permissions for testing"""
    permission = UserInstancePermission(
        user_id=sample_user.id,
        instance_id=sample_instance.id,
        can_search=True,
        can_create=True,
        can_add=True,
        can_manage=False
    )
    db_session.add(permission)
    db_session.commit()
    db_session.refresh(permission)
    return permission


@pytest.fixture
def mock_chromadb_client():
    """Mock ChromaDB client for testing"""
    with patch('app.chromadb_client.chromadb.HttpClient') as mock_client:
        # Mock collection object
        mock_collection = Mock()
        mock_collection.name = "test-collection"
        mock_collection.metadata = {"test": "metadata"}
        mock_collection.count.return_value = 5
        mock_collection.query.return_value = {
            "ids": [["doc1", "doc2"]],
            "documents": [["Document 1", "Document 2"]],
            "metadatas": [[{"key": "value1"}, {"key": "value2"}]],
            "distances": [[0.1, 0.2]]
        }
        mock_collection.get.return_value = {
            "ids": ["doc1"],
            "documents": ["Document 1"],
            "metadatas": [{"key": "value1"}]
        }
        mock_collection.add.return_value = None
        mock_collection.delete.return_value = None
        
        # Mock client methods
        mock_instance = Mock()
        mock_instance.list_collections.return_value = [mock_collection]
        mock_instance.get_collection.return_value = mock_collection
        mock_instance.create_collection.return_value = mock_collection
        mock_instance.delete_collection.return_value = None
        
        mock_client.return_value = mock_instance
        
        yield mock_instance


@pytest.fixture(autouse=True)
def clear_auth_cache():
    """Clear authentication cache before each test"""
    # Clear rate limiting cache
    from app.auth import failed_login_attempts
    failed_login_attempts.clear()
    yield
    failed_login_attempts.clear()


@pytest.fixture
def sample_documents():
    """Sample documents for testing text splitting and document operations"""
    return [
        "This is the first test document. It contains some text for testing purposes.",
        "This is the second document. It has different content and should be split differently.",
        "# Markdown Document\n\nThis is a markdown document with headers.\n\n## Section 1\n\nContent here.\n\n## Section 2\n\nMore content."
    ]


@pytest.fixture
def temp_file():
    """Create a temporary file for testing file operations"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("Test file content\nLine 2\nLine 3")
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    try:
        os.unlink(temp_path)
    except FileNotFoundError:
        pass 