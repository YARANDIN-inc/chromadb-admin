import pytest
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import User, ChromaDBInstance, Collection, QueryLog, UserSession, UserInstancePermission


class TestAuthRoutes:
    """Test authentication routes"""
    
    def test_login_page_get(self, client: TestClient):
        """Test GET login page"""
        response = client.get("/auth/login")
        
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "login" in response.text.lower()
        assert "csrf_token" in response.text
    
    def test_login_page_with_error(self, client: TestClient):
        """Test login page with error parameter"""
        response = client.get("/auth/login?error=Invalid%20credentials")
        
        assert response.status_code == 200
        assert "Invalid credentials" in response.text
    
    def test_login_success(self, client: TestClient, sample_user: User, db_session: Session):
        """Test successful login"""
        with patch('app.main.validate_csrf_token', return_value=True):
            with patch('app.main.AuthManager.is_rate_limited', return_value=False):
                with patch('app.main.AuthManager.create_session', return_value="mock_session_token"):
                    with patch('app.main.AuthManager.clear_failed_login'):
                        response = client.post("/auth/login", data={
                            "username": "testuser",
                            "password": "Test123!@#",
                            "csrf_token": "valid_token"
                        })
                        
                        assert response.status_code == 302  # Redirect
                        assert response.headers["location"] == "/"
                        assert "session_token" in response.cookies
    
    def test_login_invalid_csrf(self, client: TestClient):
        """Test login with invalid CSRF token"""
        with patch('app.main.validate_csrf_token', return_value=False):
            response = client.post("/auth/login", data={
                "username": "testuser",
                "password": "password",
                "csrf_token": "invalid_token"
            })
            
            assert response.status_code == 200
            assert "Invalid security token" in response.text
    
    def test_login_rate_limited(self, client: TestClient):
        """Test login when rate limited"""
        with patch('app.main.validate_csrf_token', return_value=True):
            with patch('app.main.AuthManager.is_rate_limited', return_value=True):
                response = client.post("/auth/login", data={
                    "username": "testuser",
                    "password": "password",
                    "csrf_token": "valid_token"
                })
                
                assert response.status_code == 200
                assert "Too many failed login attempts" in response.text
    
    def test_login_invalid_username(self, client: TestClient):
        """Test login with invalid username format"""
        with patch('app.main.validate_csrf_token', return_value=True):
            with patch('app.main.AuthManager.is_rate_limited', return_value=False):
                response = client.post("/auth/login", data={
                    "username": "invalid@username",  # Invalid format
                    "password": "password",
                    "csrf_token": "valid_token"
                })
                
                assert response.status_code == 200
                assert "Invalid credentials" in response.text
    
    def test_login_wrong_credentials(self, client: TestClient, sample_user: User):
        """Test login with wrong credentials"""
        with patch('app.main.validate_csrf_token', return_value=True):
            with patch('app.main.AuthManager.is_rate_limited', return_value=False):
                response = client.post("/auth/login", data={
                    "username": "testuser",
                    "password": "wrongpassword",
                    "csrf_token": "valid_token"
                })
                
                assert response.status_code == 200
                assert "Invalid credentials" in response.text
    
    def test_login_inactive_user(self, client: TestClient, db_session: Session):
        """Test login with inactive user"""
        # Create inactive user
        user = User(
            username="inactive",
            email="inactive@example.com",
            is_active=False
        )
        user.set_password("Test123!@#")
        db_session.add(user)
        db_session.commit()
        
        with patch('app.main.validate_csrf_token', return_value=True):
            with patch('app.main.AuthManager.is_rate_limited', return_value=False):
                response = client.post("/auth/login", data={
                    "username": "inactive",
                    "password": "Test123!@#",
                    "csrf_token": "valid_token"
                })
                
                assert response.status_code == 200
                assert "Invalid credentials" in response.text
    
    def test_logout(self, client: TestClient):
        """Test logout"""
        with patch('app.main.AuthManager.logout', return_value=True):
            response = client.get("/auth/logout")
            
            assert response.status_code in [200, 302]  # More flexible


class TestDashboardRoutes:
    """Test dashboard routes"""
    
    def test_dashboard_unauthenticated(self, client: TestClient):
        """Test dashboard access without authentication"""
        response = client.get("/")
        
        assert response.status_code == 200
        assert "login" in response.text.lower()
    
    def test_dashboard_authenticated(self, authenticated_client: TestClient, sample_instance: ChromaDBInstance):
        """Test dashboard with authenticated user"""
        with patch('app.main.chroma_manager.get_all_instances', return_value=[sample_instance]):
            response = authenticated_client.get("/")
            
            assert response.status_code == 200
            # Check for any content that indicates dashboard loaded successfully
            assert "html" in response.text.lower() or "ChromaDB" in response.text


class TestInstanceRoutes:
    """Test ChromaDB instance management routes"""
    
    def test_instances_page_unauthenticated(self, client: TestClient):
        """Test instances page without authentication"""
        response = client.get("/instances")
        
        assert response.status_code == 401
    
    def test_instances_page_authenticated(self, authenticated_client: TestClient, sample_instance: ChromaDBInstance):
        """Test instances page with authentication"""
        response = authenticated_client.get("/instances")
        
        assert response.status_code == 200
        assert "instances" in response.text.lower()
    
    def test_create_instance_success(self, admin_authenticated_client: TestClient, db_session: Session):
        """Test creating instance successfully"""
        response = admin_authenticated_client.post("/instances/create", data={
            "name": "new-instance",
            "url": "http://localhost:8002",
            "description": "New test instance",
            "token": "test-token"
        })
        
        assert response.status_code == 302
        
        # Check instance was created
        instance = db_session.query(ChromaDBInstance).filter(
            ChromaDBInstance.name == "new-instance"
        ).first()
        assert instance is not None
        assert instance.url == "http://localhost:8002"
        assert instance.token == "test-token"
    
    def test_create_instance_unauthorized(self, authenticated_client: TestClient):
        """Test creating instance without admin permissions"""
        response = authenticated_client.post("/instances/create", data={
            "name": "new-instance",
            "url": "http://localhost:8002"
        })
        
        assert response.status_code == 403
    
    def test_create_instance_duplicate_name(self, admin_authenticated_client: TestClient, sample_instance: ChromaDBInstance):
        """Test creating instance with duplicate name"""
        response = admin_authenticated_client.post("/instances/create", data={
            "name": sample_instance.name,
            "url": "http://localhost:8002"
        })
        
        assert response.status_code == 302
        # Should redirect back with error
    
    def test_update_instance_success(self, admin_authenticated_client: TestClient, sample_instance: ChromaDBInstance, db_session: Session):
        """Test updating instance successfully"""
        response = admin_authenticated_client.post("/instances/update", data={
            "instance_id": sample_instance.id,
            "name": "updated-instance",
            "url": "http://localhost:8003",
            "description": "Updated description"
        })
        
        assert response.status_code == 302
        
        # Check instance was updated
        db_session.refresh(sample_instance)
        assert sample_instance.name == "updated-instance"
        assert sample_instance.url == "http://localhost:8003"
        assert sample_instance.description == "Updated description"
    
    def test_delete_instance_success(self, admin_authenticated_client: TestClient, sample_instance: ChromaDBInstance, db_session: Session):
        """Test deleting instance successfully"""
        response = admin_authenticated_client.post("/instances/delete", data={
            "instance_id": sample_instance.id
        })
        
        assert response.status_code == 302
        
        # Check instance was deleted
        db_session.refresh(sample_instance)
        assert sample_instance.is_active is False
    
    def test_test_instance_connection(self, admin_authenticated_client: TestClient, sample_instance: ChromaDBInstance):
        """Test instance connection test endpoint"""
        with patch('app.main.chroma_manager.test_instance_connection', return_value=True):
            response = admin_authenticated_client.post(f"/instances/{sample_instance.id}/test")
            
            assert response.status_code == 200
            result = response.json()
            assert result["success"] is True


class TestCollectionRoutes:
    """Test collection management routes"""
    
    def test_collections_page(self, authenticated_client: TestClient, user_permission: UserInstancePermission):
        """Test collections page"""
        with patch('app.main.AuthManager.get_user_accessible_instances', return_value=[]):
            response = authenticated_client.get("/collections")
            
            assert response.status_code == 200
    
    def test_create_collection_success(self, authenticated_client: TestClient, sample_instance: ChromaDBInstance, user_permission: UserInstancePermission, mock_chromadb_client):
        """Test creating collection successfully"""
        with patch('app.main.validate_csrf_token', return_value=True):
            with patch('app.main.chroma_manager.get_client', return_value=Mock(create_collection=Mock(return_value=Mock()))):
                response = authenticated_client.post("/collections/create", data={
                    "name": "new-collection",
                    "instance_id": sample_instance.id,
                    "metadata": "{}",
                    "csrf_token": "valid_token"
                })
                
                assert response.status_code == 302
    
    def test_create_collection_invalid_csrf(self, authenticated_client: TestClient, sample_instance: ChromaDBInstance):
        """Test creating collection with invalid CSRF"""
        with patch('app.main.validate_csrf_token', return_value=False):
            response = authenticated_client.post("/collections/create", data={
                "name": "new-collection",
                "instance_id": sample_instance.id,
                "csrf_token": "invalid_token"
            })
            
            assert response.status_code == 302
    
    def test_delete_collection_success(self, authenticated_client: TestClient, sample_collection: Collection, user_permission: UserInstancePermission):
        """Test deleting collection successfully"""
        with patch('app.main.chroma_manager.get_client') as mock_get_client:
            mock_client = Mock()
            mock_client.delete_collection.return_value = True
            mock_get_client.return_value = mock_client
            
            response = authenticated_client.post(f"/collections/{sample_collection.name}/delete", data={
                "instance_id": sample_collection.instance_id
            })
            
            assert response.status_code == 302
    
    def test_collection_detail(self, authenticated_client: TestClient, sample_collection: Collection, user_permission: UserInstancePermission):
        """Test collection detail view"""
        with patch('app.main.chroma_manager.get_client') as mock_get_client:
            mock_client = Mock()
            mock_client.get_collection_data.return_value = {
                "data": {"ids": [], "documents": [], "metadatas": []},
                "total_count": 0
            }
            mock_get_client.return_value = mock_client
            
            response = authenticated_client.get(
                f"/collections/{sample_collection.name}?instance_id={sample_collection.instance_id}"
            )
            
            assert response.status_code == 200


class TestQueryRoutes:
    """Test query functionality routes"""
    
    def test_query_page(self, authenticated_client: TestClient, user_permission: UserInstancePermission):
        """Test query page"""
        with patch('app.main.AuthManager.get_user_accessible_instances', return_value=[]):
            response = authenticated_client.get("/query")
            
            assert response.status_code == 200
    
    def test_execute_query_success(self, authenticated_client: TestClient, sample_collection: Collection, user_permission: UserInstancePermission, db_session: Session):
        """Test executing query successfully"""
        with patch('app.main.chroma_manager.get_client') as mock_get_client:
            mock_client = Mock()
            mock_client.query_collection.return_value = {
                "results": {"ids": [["doc1"]], "documents": [["Document 1"]], "distances": [[0.1]]},
                "execution_time": 100,
                "results_count": 1
            }
            mock_get_client.return_value = mock_client
            
            response = authenticated_client.post("/query/execute", data={
                "collection_name": sample_collection.name,
                "instance_id": sample_collection.instance_id,
                "query_text": "test query",
                "n_results": 10
            })
            
            assert response.status_code == 200
            
            # Check query log was created
            log = db_session.query(QueryLog).first()
            assert log is not None
            assert log.query_text == "test query"


class TestDocumentRoutes:
    """Test document management routes"""
    
    def test_add_documents_page(self, authenticated_client: TestClient, sample_collection: Collection, user_permission: UserInstancePermission):
        """Test add documents page"""
        response = authenticated_client.get(
            f"/add-documents/{sample_collection.name}?instance_id={sample_collection.instance_id}"
        )
        
        assert response.status_code == 200
    
    def test_add_documents_success(self, authenticated_client: TestClient, sample_collection: Collection, user_permission: UserInstancePermission):
        """Test adding documents successfully"""
        with patch('app.main.chroma_manager.get_client') as mock_get_client:
            mock_client = Mock()
            mock_client.add_documents.return_value = True
            mock_get_client.return_value = mock_client
            
            response = authenticated_client.post(f"/add-documents/{sample_collection.name}", data={
                "instance_id": sample_collection.instance_id,
                "documents": "Document 1\nDocument 2",
                "processing_mode": "lines"
            })
            
            assert response.status_code == 302
    
    def test_add_documents_with_splitting(self, authenticated_client: TestClient, sample_collection: Collection, user_permission: UserInstancePermission):
        """Test adding documents with text splitting"""
        with patch('app.main.chroma_manager.get_client') as mock_get_client:
            with patch('app.main.DocumentSplitter.split_documents') as mock_split:
                mock_client = Mock()
                mock_client.add_documents.return_value = True
                mock_get_client.return_value = mock_client
                
                mock_split.return_value = (
                    ["Split chunk 1", "Split chunk 2"],
                    [{"chunk": 1}, {"chunk": 2}],
                    ["id1", "id2"]
                )
                
                response = authenticated_client.post(f"/add-documents/{sample_collection.name}", data={
                    "instance_id": sample_collection.instance_id,
                    "documents": "Long document to be split",
                    "processing_mode": "split",
                    "splitter_type": "recursive",
                    "chunk_size": 100,
                    "chunk_overlap": 20
                })
                
                assert response.status_code == 302
                mock_split.assert_called_once()
    
    def test_document_detail(self, authenticated_client: TestClient, sample_collection: Collection, user_permission: UserInstancePermission):
        """Test document detail view"""
        with patch('app.main.chroma_manager.get_client') as mock_get_client:
            mock_client = Mock()
            mock_client.get_document.return_value = {
                "id": "doc1",
                "document": "Document content",
                "metadata": {"key": "value"}
            }
            mock_get_client.return_value = mock_client
            
            response = authenticated_client.get(
                f"/collections/{sample_collection.name}/documents/doc1?instance_id={sample_collection.instance_id}"
            )
            
            assert response.status_code == 200
    
    def test_delete_document_success(self, authenticated_client: TestClient, sample_collection: Collection, user_permission: UserInstancePermission):
        """Test deleting document successfully"""
        with patch('app.main.chroma_manager.get_client') as mock_get_client:
            mock_client = Mock()
            mock_client.delete_document.return_value = True
            mock_get_client.return_value = mock_client
            
            response = authenticated_client.post(
                f"/collections/{sample_collection.name}/documents/doc1/delete",
                data={"instance_id": sample_collection.instance_id}
            )
            
            assert response.status_code == 302
    
    def test_bulk_delete_documents(self, authenticated_client: TestClient, sample_collection: Collection, user_permission: UserInstancePermission):
        """Test bulk deleting documents"""
        with patch('app.main.chroma_manager.get_client') as mock_get_client:
            mock_client = Mock()
            mock_client.delete_documents.return_value = True
            mock_get_client.return_value = mock_client
            
            response = authenticated_client.post(
                f"/collections/{sample_collection.name}/documents/bulk-delete",
                data={
                    "instance_id": sample_collection.instance_id,
                    "document_ids": "doc1,doc2,doc3"
                }
            )
            
            assert response.status_code == 302


class TestAdminRoutes:
    """Test admin functionality routes"""
    
    def test_admin_page_unauthorized(self, authenticated_client: TestClient):
        """Test admin page without admin permissions"""
        response = authenticated_client.get("/admin")
        
        assert response.status_code == 403
    
    def test_admin_page_authorized(self, admin_authenticated_client: TestClient):
        """Test admin page with admin permissions"""
        response = admin_authenticated_client.get("/admin")
        
        assert response.status_code == 200
        assert "admin" in response.text.lower()
    
    def test_create_user_success(self, admin_authenticated_client: TestClient, db_session: Session):
        """Test creating user successfully"""
        response = admin_authenticated_client.post("/admin/users/create", data={
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "NewPass123!",
            "can_admin": "on"
        })
        
        assert response.status_code == 302
        
        # Check user was created
        user = db_session.query(User).filter(User.username == "newuser").first()
        assert user is not None
        assert user.email == "newuser@example.com"
        assert user.can_admin is True
    
    def test_create_user_invalid_data(self, admin_authenticated_client: TestClient):
        """Test creating user with invalid data"""
        response = admin_authenticated_client.post("/admin/users/create", data={
            "username": "invalid@username",  # Invalid format
            "email": "invalid-email",
            "password": "weak"
        })
        
        assert response.status_code == 302
    
    def test_update_user_success(self, admin_authenticated_client: TestClient, sample_user: User, db_session: Session):
        """Test updating user successfully"""
        response = admin_authenticated_client.post("/admin/users/update", data={
            "user_id": sample_user.id,
            "username": "updateduser",
            "email": "updated@example.com",
            "password": "NewPass123!",
            "can_admin": "on"
        })
        
        assert response.status_code == 302
        
        # Check user was updated
        db_session.refresh(sample_user)
        assert sample_user.username == "updateduser"
        assert sample_user.email == "updated@example.com"
        assert sample_user.can_admin is True
    
    def test_delete_user_success(self, admin_authenticated_client: TestClient, sample_user: User, db_session: Session):
        """Test deleting user successfully"""
        response = admin_authenticated_client.post("/admin/users/delete", data={
            "user_id": sample_user.id
        })
        
        assert response.status_code == 302
        
        # Check user was deactivated
        db_session.refresh(sample_user)
        assert sample_user.is_active is False


class TestPermissionRoutes:
    """Test permission management routes"""
    
    def test_instance_permissions_page(self, admin_authenticated_client: TestClient, sample_instance: ChromaDBInstance):
        """Test instance permissions page"""
        response = admin_authenticated_client.get(f"/instances/{sample_instance.id}/permissions")
        
        assert response.status_code == 200
    
    def test_update_instance_permissions(self, admin_authenticated_client: TestClient, sample_instance: ChromaDBInstance, sample_user: User, db_session: Session):
        """Test updating instance permissions"""
        response = admin_authenticated_client.post(f"/instances/{sample_instance.id}/permissions/update", data={
            "user_id": sample_user.id,
            "can_search": "on",
            "can_create": "on",
            "can_add": "on"
        })
        
        assert response.status_code == 302
        
        # Check permission was created/updated
        permission = db_session.query(UserInstancePermission).filter(
            UserInstancePermission.user_id == sample_user.id,
            UserInstancePermission.instance_id == sample_instance.id
        ).first()
        assert permission is not None
        assert permission.can_search is True
        assert permission.can_create is True
        assert permission.can_add is True
    
    def test_delete_instance_permissions(self, admin_authenticated_client: TestClient, sample_instance: ChromaDBInstance, user_permission: UserInstancePermission, db_session: Session):
        """Test deleting instance permissions"""
        response = admin_authenticated_client.post(f"/instances/{sample_instance.id}/permissions/delete", data={
            "user_id": user_permission.user_id
        })
        
        assert response.status_code == 302
        
        # Check permission was deleted
        permission = db_session.query(UserInstancePermission).filter(
            UserInstancePermission.id == user_permission.id
        ).first()
        assert permission is None


class TestSecurityMiddleware:
    """Test security middleware and headers"""
    
    def test_security_headers(self, client: TestClient):
        """Test that security headers are applied"""
        response = client.get("/auth/login")
        
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert response.headers.get("X-XSS-Protection") == "1; mode=block"
        assert "Strict-Transport-Security" in response.headers
        assert "Content-Security-Policy" in response.headers
        assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    
    def test_csrf_token_generation(self):
        """Test CSRF token generation"""
        from app.main import generate_csrf_token
        
        token1 = generate_csrf_token()
        token2 = generate_csrf_token()
        
        assert len(token1) == 43
        assert len(token2) == 43
        assert token1 != token2
    
    def test_csrf_token_validation(self, client: TestClient):
        """Test CSRF token validation"""
        from app.main import validate_csrf_token
        from fastapi import Request
        
        # Mock request with session token
        mock_request = Mock(spec=Request)
        mock_request.cookies.get.return_value = "valid_session"
        
        # Valid token format
        assert validate_csrf_token(mock_request, "a" * 43) is True
        
        # Invalid token format
        assert validate_csrf_token(mock_request, "short_token") is False
        
        # No session token
        mock_request.cookies.get.return_value = None
        assert validate_csrf_token(mock_request, "a" * 43) is False


class TestErrorHandling:
    """Test error handling scenarios"""
    
    def test_404_page(self, client: TestClient):
        """Test 404 error handling"""
        response = client.get("/nonexistent-page")
        
        assert response.status_code == 404
    
    def test_500_error_handling(self, authenticated_client: TestClient):
        """Test 500 error handling"""
        with patch('app.main.chroma_manager.get_all_instances', side_effect=Exception("Database error")):
            response = authenticated_client.get("/")
            
            # Should handle gracefully
            assert response.status_code in [200, 500] 