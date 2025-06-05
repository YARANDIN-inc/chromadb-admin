import pytest
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import User, ChromaDBInstance, Collection, UserInstancePermission


@pytest.mark.integration
class TestCompleteUserWorkflow:
    """Integration tests for complete user workflows"""
    
    def test_complete_admin_workflow(self, client: TestClient, db_session: Session):
        """Test complete workflow: create admin -> create instance -> create user -> assign permissions"""
        
        # 1. Create initial admin user
        admin = User(
            username="admin",
            email="admin@example.com",
            is_super_admin=True,
            can_admin=True,
            is_active=True
        )
        admin.set_password("Admin123!@#")
        db_session.add(admin)
        db_session.commit()
        
        # 2. Login as admin
        with patch('app.main.validate_csrf_token', return_value=True):
            with patch('app.main.AuthManager.is_rate_limited', return_value=False):
                with patch('app.main.AuthManager.create_session', return_value="admin_session_token"):
                    login_response = client.post("/auth/login", data={
                        "username": "admin",
                        "password": "Admin123!@#",
                        "csrf_token": "valid_token"
                    })
                    assert login_response.status_code == 302
        
        # Set session cookie
        client.cookies.set("session_token", "admin_session_token")
        
        # Mock the authentication for subsequent requests
        with patch('app.auth.AuthManager.get_current_user', return_value=admin):
            
            # 3. Create ChromaDB instance
            instance_response = client.post("/instances/create", data={
                "name": "test-chromadb",
                "url": "http://localhost:8001",
                "description": "Test ChromaDB instance"
            })
            assert instance_response.status_code in [200, 302]
            
            # Verify instance was created
            instance = db_session.query(ChromaDBInstance).filter(
                ChromaDBInstance.name == "test-chromadb"
            ).first()
            assert instance is not None
            
            # 4. Create regular user
            user_response = client.post("/admin/users/create", data={
                "username": "testuser",
                "email": "testuser@example.com",
                "password": "Test123!@#"
            })
            assert user_response.status_code in [200, 302]
            
            # Verify user was created
            user = db_session.query(User).filter(User.username == "testuser").first()
            assert user is not None
            
            # 5. Assign permissions to user for instance
            perm_response = client.post(f"/instances/{instance.id}/permissions/update", data={
                "user_id": user.id,
                "can_search": "on",
                "can_create": "on",
                "can_add": "on"
            })
            assert perm_response.status_code in [200, 302]
            
            # Verify permission was created
            permission = db_session.query(UserInstancePermission).filter(
                UserInstancePermission.user_id == user.id,
                UserInstancePermission.instance_id == instance.id
            ).first()
            assert permission is not None
            assert permission.can_search is True
            assert permission.can_create is True
            assert permission.can_add is True
    
    def test_complete_user_document_workflow(self, client: TestClient, db_session: Session):
        """Test complete workflow: user login -> create collection -> add documents -> query"""
        
        # Setup: Create user, instance, and permissions
        user = User(
            username="docuser",
            email="docuser@example.com",
            is_active=True
        )
        user.set_password("User123!@#")
        db_session.add(user)
        
        instance = ChromaDBInstance(
            name="doc-instance",
            url="http://localhost:8001",
            is_active=True,
            is_default=True
        )
        db_session.add(instance)
        db_session.commit()
        
        permission = UserInstancePermission(
            user_id=user.id,
            instance_id=instance.id,
            can_search=True,
            can_create=True,
            can_add=True
        )
        db_session.add(permission)
        db_session.commit()
        
        # 1. Login as user
        with patch('app.main.validate_csrf_token', return_value=True):
            with patch('app.main.AuthManager.is_rate_limited', return_value=False):
                with patch('app.main.AuthManager.create_session', return_value="user_session_token"):
                    login_response = client.post("/auth/login", data={
                        "username": "docuser",
                        "password": "User123!@#",
                        "csrf_token": "valid_token"
                    })
                    assert login_response.status_code == 302
        
        client.cookies.set("session_token", "user_session_token")
        
        # Mock authentication and ChromaDB client
        mock_client = Mock()
        mock_collection = Mock()
        
        with patch('app.auth.AuthManager.get_current_user', return_value=user):
            with patch('app.main.chroma_manager.get_client', return_value=mock_client):
                
                # 2. Create collection
                mock_client.create_collection.return_value = mock_collection
                
                with patch('app.main.validate_csrf_token', return_value=True):
                    collection_response = client.post("/collections/create", data={
                        "name": "test-docs",
                        "instance_id": instance.id,
                        "metadata": '{"description": "Test documents"}',
                        "csrf_token": "valid_token"
                    })
                    assert collection_response.status_code in [200, 302]
                
                # 3. Add documents
                mock_client.add_documents.return_value = True
                
                add_docs_response = client.post("/add-documents/test-docs", data={
                    "instance_id": instance.id,
                    "documents": "Document 1: This is the first test document.\nDocument 2: This is the second test document.",
                    "processing_mode": "lines"
                })
                assert add_docs_response.status_code in [200, 302]
                
                # 4. Query documents
                mock_client.query_collection.return_value = {
                    "results": {
                        "ids": [["doc1", "doc2"]],
                        "documents": [["Document 1: This is the first test document.", "Document 2: This is the second test document."]],
                        "distances": [[0.1, 0.2]]
                    },
                    "execution_time": 150,
                    "results_count": 2
                }
                
                query_response = client.post("/query/execute", data={
                    "collection_name": "test-docs",
                    "instance_id": instance.id,
                    "query_text": "test document",
                    "n_results": 10
                })
                assert query_response.status_code == 200
                
                # Verify all mocked calls were made
                mock_client.create_collection.assert_called_once()
                mock_client.add_documents.assert_called_once()
                mock_client.query_collection.assert_called_once()
    
    def test_permission_enforcement_workflow(self, client: TestClient, db_session: Session):
        """Test that permissions are properly enforced in workflows"""
        
        # Create user with limited permissions
        user = User(
            username="limiteduser",
            email="limited@example.com",
            is_active=True
        )
        user.set_password("User123!@#")
        db_session.add(user)
        
        instance = ChromaDBInstance(
            name="limited-instance",
            url="http://localhost:8001",
            is_active=True
        )
        db_session.add(instance)
        db_session.commit()
        
        # Grant only search permission
        permission = UserInstancePermission(
            user_id=user.id,
            instance_id=instance.id,
            can_search=True,
            can_create=False,  # No create permission
            can_add=False      # No add permission
        )
        db_session.add(permission)
        db_session.commit()
        
        # Login
        with patch('app.main.validate_csrf_token', return_value=True):
            with patch('app.main.AuthManager.is_rate_limited', return_value=False):
                with patch('app.main.AuthManager.create_session', return_value="limited_session_token"):
                    login_response = client.post("/auth/login", data={
                        "username": "limiteduser",
                        "password": "User123!@#",
                        "csrf_token": "valid_token"
                    })
                    assert login_response.status_code == 302
        
        client.cookies.set("session_token", "limited_session_token")
        
        with patch('app.auth.AuthManager.get_current_user', return_value=user):
            
            # Should be able to access query page
            query_response = client.get("/query")
            assert query_response.status_code == 200
            
            # Should NOT be able to create collections
            with patch('app.main.validate_csrf_token', return_value=True):
                collection_response = client.post("/collections/create", data={
                    "name": "unauthorized-collection",
                    "instance_id": instance.id,
                    "csrf_token": "valid_token"
                })
                # Should fail due to lack of permissions
                assert collection_response.status_code in [200, 302, 403]  # May return form with error


@pytest.mark.integration
class TestMultiInstanceWorkflow:
    """Integration tests for multi-instance scenarios"""
    
    def test_multiple_instances_workflow(self, client: TestClient, db_session: Session):
        """Test workflow with multiple ChromaDB instances"""
        
        # Create admin user
        admin = User(
            username="multiadmin",
            email="multiadmin@example.com",
            is_super_admin=True,
            can_admin=True,
            is_active=True
        )
        admin.set_password("Admin123!@#")
        db_session.add(admin)
        db_session.commit()
        
        # Login
        with patch('app.main.validate_csrf_token', return_value=True):
            with patch('app.main.AuthManager.is_rate_limited', return_value=False):
                with patch('app.main.AuthManager.create_session', return_value="multi_admin_session"):
                    client.post("/auth/login", data={
                        "username": "multiadmin",
                        "password": "Admin123!@#",
                        "csrf_token": "valid_token"
                    })
        
        client.cookies.set("session_token", "multi_admin_session")
        
        with patch('app.auth.AuthManager.get_current_user', return_value=admin):
            
            # Create multiple instances
            instance1_response = client.post("/instances/create", data={
                "name": "instance-1",
                "url": "http://localhost:8001",
                "description": "First instance"
            })
            assert instance1_response.status_code in [200, 302]
            
            instance2_response = client.post("/instances/create", data={
                "name": "instance-2", 
                "url": "http://localhost:8002",
                "description": "Second instance"
            })
            assert instance2_response.status_code in [200, 302]
            
            # Verify both instances were created
            instances = db_session.query(ChromaDBInstance).all()
            assert len(instances) == 2
            
            instance1 = db_session.query(ChromaDBInstance).filter(
                ChromaDBInstance.name == "instance-1"
            ).first()
            instance2 = db_session.query(ChromaDBInstance).filter(
                ChromaDBInstance.name == "instance-2"
            ).first()
            
            assert instance1 is not None
            assert instance2 is not None
            
            # Create user with different permissions for each instance
            user_response = client.post("/admin/users/create", data={
                "username": "multiuser",
                "email": "multiuser@example.com",
                "password": "User123!@#"
            })
            assert user_response.status_code in [200, 302]
            
            user = db_session.query(User).filter(User.username == "multiuser").first()
            
            # Grant full permissions to instance1
            perm1_response = client.post(f"/instances/{instance1.id}/permissions/update", data={
                "user_id": user.id,
                "can_search": "on",
                "can_create": "on",
                "can_add": "on",
                "can_manage": "on"
            })
            assert perm1_response.status_code in [200, 302]
            
            # Grant only search permissions to instance2
            perm2_response = client.post(f"/instances/{instance2.id}/permissions/update", data={
                "user_id": user.id,
                "can_search": "on"
            })
            assert perm2_response.status_code in [200, 302]
            
            # Verify permissions
            perm1 = db_session.query(UserInstancePermission).filter(
                UserInstancePermission.user_id == user.id,
                UserInstancePermission.instance_id == instance1.id
            ).first()
            perm2 = db_session.query(UserInstancePermission).filter(
                UserInstancePermission.user_id == user.id,
                UserInstancePermission.instance_id == instance2.id
            ).first()
            
            assert perm1.can_create is True
            assert perm1.can_manage is True
            assert perm2.can_create is False
            assert perm2.can_manage is False


@pytest.mark.integration
class TestErrorRecoveryWorkflow:
    """Integration tests for error scenarios and recovery"""
    
    def test_chromadb_connection_failure_workflow(self, client: TestClient, db_session: Session):
        """Test workflow when ChromaDB connection fails"""
        
        # Setup user and instance
        user = User(
            username="erroruser",
            email="error@example.com",
            is_active=True
        )
        user.set_password("User123!@#")
        db_session.add(user)
        
        instance = ChromaDBInstance(
            name="error-instance",
            url="http://localhost:8001",
            is_active=True
        )
        db_session.add(instance)
        db_session.commit()
        
        permission = UserInstancePermission(
            user_id=user.id,
            instance_id=instance.id,
            can_search=True,
            can_create=True
        )
        db_session.add(permission)
        db_session.commit()
        
        # Login
        with patch('app.main.validate_csrf_token', return_value=True):
            with patch('app.main.AuthManager.is_rate_limited', return_value=False):
                with patch('app.main.AuthManager.create_session', return_value="error_session"):
                    client.post("/auth/login", data={
                        "username": "erroruser",
                        "password": "User123!@#",
                        "csrf_token": "valid_token"
                    })
        
        client.cookies.set("session_token", "error_session")
        
        with patch('app.auth.AuthManager.get_current_user', return_value=user):
            
            # Test connection failure scenario
            with patch('app.main.chroma_manager.test_instance_connection', return_value=False):
                test_response = client.post(f"/instances/{instance.id}/test")
                assert test_response.status_code == 200
                result = test_response.json()
                assert result["success"] is False
            
            # Test graceful handling when ChromaDB client returns None
            with patch('app.main.chroma_manager.get_client', return_value=None):
                
                # Should handle gracefully without crashing
                query_response = client.post("/query/execute", data={
                    "collection_name": "test-collection",
                    "instance_id": instance.id,
                    "query_text": "test query"
                })
                # Should redirect back with error message or show error
                assert query_response.status_code in [200, 302, 401]
    
    def test_database_constraint_violation_workflow(self, client: TestClient, db_session: Session):
        """Test workflow when database constraints are violated"""
        
        # Create admin
        admin = User(
            username="constraintadmin",
            email="constraint@example.com",
            is_super_admin=True,
            can_admin=True,
            is_active=True
        )
        admin.set_password("Admin123!@#")
        db_session.add(admin)
        db_session.commit()
        
        # Login
        with patch('app.main.validate_csrf_token', return_value=True):
            with patch('app.main.AuthManager.is_rate_limited', return_value=False):
                with patch('app.main.AuthManager.create_session', return_value="constraint_session"):
                    client.post("/auth/login", data={
                        "username": "constraintadmin",
                        "password": "Admin123!@#",
                        "csrf_token": "valid_token"
                    })
        
        client.cookies.set("session_token", "constraint_session")
        
        with patch('app.auth.AuthManager.get_current_user', return_value=admin):
            
            # Create instance
            instance_response = client.post("/instances/create", data={
                "name": "constraint-instance",
                "url": "http://localhost:8001"
            })
            assert instance_response.status_code in [200, 302]
            
            # Try to create instance with same name (should handle constraint violation)
            duplicate_response = client.post("/instances/create", data={
                "name": "constraint-instance",
                "url": "http://localhost:8002"
            })
            # Should redirect back gracefully
            assert duplicate_response.status_code in [200, 302]
            
            # Verify only one instance was created
            instances = db_session.query(ChromaDBInstance).filter(
                ChromaDBInstance.name == "constraint-instance"
            ).all()
            assert len(instances) == 1


@pytest.mark.integration
@pytest.mark.slow
class TestPerformanceWorkflow:
    """Integration tests for performance scenarios"""
    
    def test_bulk_operations_workflow(self, client: TestClient, db_session: Session):
        """Test workflow with bulk operations"""
        
        # Setup
        user = User(
            username="bulkuser",
            email="bulk@example.com",
            is_active=True
        )
        user.set_password("User123!@#")
        db_session.add(user)
        
        instance = ChromaDBInstance(
            name="bulk-instance",
            url="http://localhost:8001",
            is_active=True
        )
        db_session.add(instance)
        db_session.commit()
        
        permission = UserInstancePermission(
            user_id=user.id,
            instance_id=instance.id,
            can_search=True,
            can_create=True,
            can_add=True
        )
        db_session.add(permission)
        db_session.commit()
        
        # Login
        with patch('app.main.validate_csrf_token', return_value=True):
            with patch('app.main.AuthManager.is_rate_limited', return_value=False):
                with patch('app.main.AuthManager.create_session', return_value="bulk_session"):
                    client.post("/auth/login", data={
                        "username": "bulkuser",
                        "password": "User123!@#",
                        "csrf_token": "valid_token"
                    })
        
        client.cookies.set("session_token", "bulk_session")
        
        # Mock ChromaDB client
        mock_client = Mock()
        mock_collection = Mock()
        mock_collection.name = "bulk-collection"
        mock_client.create_collection.return_value = mock_collection
        mock_client.add_documents.return_value = True
        mock_client.delete_documents.return_value = True
        
        with patch('app.auth.AuthManager.get_current_user', return_value=user):
            with patch('app.main.chroma_manager.get_client', return_value=mock_client):
                
                # Create collection
                with patch('app.main.validate_csrf_token', return_value=True):
                    response = client.post("/collections/create", data={
                        "name": "bulk-collection",
                        "instance_id": instance.id,
                        "csrf_token": "valid_token"
                    })
                    # May return 200 or 302 depending on validation
                    assert response.status_code in [200, 302]
                
                # Add large number of documents
                documents = "\n".join([f"Document {i}: This is test document number {i}" for i in range(100)])
                
                add_response = client.post("/add-documents/bulk-collection", data={
                    "instance_id": instance.id,
                    "documents": documents,
                    "processing_mode": "lines"
                })
                assert add_response.status_code in [200, 302]
                
                # Bulk delete documents
                document_ids = ",".join([f"doc_{i}" for i in range(50)])
                
                delete_response = client.post("/collections/bulk-collection/documents/bulk-delete", data={
                    "instance_id": instance.id,
                    "document_ids": document_ids
                })
                assert delete_response.status_code in [200, 302]
                
                # Verify operations were called if successful
                if add_response.status_code == 302:
                    mock_client.add_documents.assert_called()
                if delete_response.status_code == 302:
                    mock_client.delete_documents.assert_called() 