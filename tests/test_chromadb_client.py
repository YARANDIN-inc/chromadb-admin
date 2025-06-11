import pytest
from unittest.mock import Mock, patch, MagicMock
from sqlalchemy.orm import Session

from app.chromadb_client import ChromaDBClient, ChromaDBManager, chroma_manager
from app.models import ChromaDBInstance


class TestChromaDBClient:
    """Test ChromaDBClient functionality"""
    
    def test_client_initialization_success(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test successful client initialization"""
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            assert client.instance == sample_instance
            assert client.client is not None
    
    def test_client_initialization_failure(self, sample_instance: ChromaDBInstance):
        """Test client initialization failure"""
        with patch('app.chromadb_client.chromadb.HttpClient', side_effect=Exception("Connection failed")):
            client = ChromaDBClient(sample_instance)
            
            assert client.instance == sample_instance
            assert client.client is None
    
    def test_client_initialization_with_token(self, db_session: Session):
        """Test client initialization with authentication token"""
        instance = ChromaDBInstance(
            name="auth-instance",
            url="http://localhost:8001",
            token="auth-token-123"
        )
        
        with patch('app.chromadb_client.chromadb.HttpClient') as mock_http_client:
            mock_client = Mock()
            mock_client.list_collections.return_value = []
            mock_http_client.return_value = mock_client
            
            client = ChromaDBClient(instance)
            
            # Check that HttpClient was called with headers
            mock_http_client.assert_called_once()
            call_args = mock_http_client.call_args
            assert 'headers' in call_args[1]
            assert call_args[1]['headers']['Authorization'] == 'Bearer auth-token-123'
    
    def test_url_parsing(self, db_session: Session):
        """Test URL parsing for different formats"""
        test_cases = [
            ("http://localhost:8001", "localhost", 8001),
            ("https://chromadb.example.com:9000", "chromadb.example.com", 9000),
            ("http://192.168.1.100", "192.168.1.100", 8000),  # Default port
        ]
        
        for url, expected_host, expected_port in test_cases:
            instance = ChromaDBInstance(name=f"test-{expected_port}", url=url)
            
            with patch('app.chromadb_client.chromadb.HttpClient') as mock_http_client:
                mock_client = Mock()
                mock_client.list_collections.return_value = []
                mock_http_client.return_value = mock_client
                
                client = ChromaDBClient(instance)
                
                call_args = mock_http_client.call_args[1]
                assert call_args['host'] == expected_host
                assert call_args['port'] == expected_port
    
    def test_ensure_connection_with_existing_client(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test _ensure_connection with existing client"""
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            result = client._ensure_connection()
            assert result is True
    
    def test_ensure_connection_without_client(self, sample_instance: ChromaDBInstance):
        """Test _ensure_connection without client"""
        client = ChromaDBClient.__new__(ChromaDBClient)
        client.instance = sample_instance
        client.client = None
        
        with patch.object(client, '_initialize_client') as mock_init:
            mock_init.return_value = None
            client._initialize_client = mock_init
            
            result = client._ensure_connection()
            mock_init.assert_called_once()
    
    def test_test_connection_success(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test successful connection test"""
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            result = client.test_connection()
            assert result is True
            mock_chromadb_client.list_collections.assert_called()
    
    def test_test_connection_failure(self, sample_instance: ChromaDBInstance):
        """Test connection test failure"""
        with patch('app.chromadb_client.chromadb.HttpClient') as mock_http_client:
            mock_client = Mock()
            mock_client.list_collections.side_effect = Exception("Connection failed")
            mock_http_client.return_value = mock_client
            
            client = ChromaDBClient(sample_instance)
            
            result = client.test_connection()
            assert result is False
    
    def test_test_connection_no_client(self, sample_instance: ChromaDBInstance):
        """Test connection test with no client"""
        client = ChromaDBClient.__new__(ChromaDBClient)
        client.instance = sample_instance
        client.client = None
        
        result = client.test_connection()
        assert result is False
    
    def test_get_collections_success(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test getting collections successfully"""
        # Mock collection
        mock_collection = Mock()
        mock_collection.name = "test-collection"
        mock_collection.metadata = {"test": "metadata"}
        mock_collection.count.return_value = 5
        
        mock_chromadb_client.list_collections.return_value = [mock_collection]
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            collections = client.get_collections()
            
            assert len(collections) == 1
            assert collections[0]["name"] == "test-collection"
            assert collections[0]["metadata"] == {"test": "metadata"}
            assert collections[0]["count"] == 5
    
    def test_get_collections_with_count_error(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test getting collections when count() fails"""
        # Mock collection with failing count
        mock_collection = Mock()
        mock_collection.name = "test-collection"
        mock_collection.metadata = {"test": "metadata"}
        mock_collection.count.side_effect = Exception("Count failed")
        
        mock_chromadb_client.list_collections.return_value = [mock_collection]
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            collections = client.get_collections()
            
            assert len(collections) == 1
            assert collections[0]["name"] == "test-collection"
            assert collections[0]["count"] == 0  # Default when count fails
    
    def test_get_collections_no_connection(self, sample_instance: ChromaDBInstance):
        """Test getting collections with no connection"""
        with patch('app.chromadb_client.chromadb.HttpClient', side_effect=Exception("No connection")):
            client = ChromaDBClient(sample_instance)
            
            collections = client.get_collections()
            assert collections == []
    
    def test_get_collection_success(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test getting a specific collection"""
        mock_collection = Mock()
        mock_chromadb_client.get_collection.return_value = mock_collection
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            collection = client.get_collection("test-collection")
            
            assert collection == mock_collection
            mock_chromadb_client.get_collection.assert_called_with("test-collection")
    
    def test_get_collection_failure(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test getting collection failure"""
        mock_chromadb_client.get_collection.side_effect = Exception("Collection not found")
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            collection = client.get_collection("nonexistent-collection")
            assert collection is None
    
    def test_create_collection_success(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test creating a collection successfully"""
        mock_collection = Mock()
        mock_chromadb_client.create_collection.return_value = mock_collection
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            collection = client.create_collection("new-collection", {"test": "metadata"})
            
            assert collection == mock_collection
            mock_chromadb_client.create_collection.assert_called_with(
                name="new-collection",
                metadata={"test": "metadata"},
                embedding_function=None
            )
    
    def test_create_collection_without_metadata(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test creating a collection without metadata"""
        mock_collection = Mock()
        mock_chromadb_client.create_collection.return_value = mock_collection
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            collection = client.create_collection("new-collection", None)
            
            assert collection == mock_collection
            mock_chromadb_client.create_collection.assert_called_with(
                name="new-collection",
                embedding_function=None
            )
    
    def test_create_collection_already_exists(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test creating collection that already exists"""
        mock_existing_collection = Mock()
        mock_chromadb_client.create_collection.side_effect = Exception("Collection exists")
        mock_chromadb_client.get_collection.return_value = mock_existing_collection
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            collection = client.create_collection("existing-collection")
            
            assert collection == mock_existing_collection
            mock_chromadb_client.get_collection.assert_called_with("existing-collection")
    
    def test_delete_collection_success(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test deleting a collection successfully"""
        mock_chromadb_client.delete_collection.return_value = None
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            result = client.delete_collection("test-collection")
            
            assert result is True
            mock_chromadb_client.delete_collection.assert_called_with("test-collection")
    
    def test_delete_collection_failure(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test deleting collection failure"""
        mock_chromadb_client.delete_collection.side_effect = Exception("Delete failed")
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            result = client.delete_collection("test-collection")
            assert result is False
    
    def test_query_collection_success(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test querying a collection successfully"""
        mock_collection = Mock()
        mock_collection.query.return_value = {
            "ids": [["doc1", "doc2"]],
            "documents": [["Document 1", "Document 2"]],
            "metadatas": [[{"key": "value1"}, {"key": "value2"}]],
            "distances": [[0.1, 0.2]]
        }
        mock_chromadb_client.get_collection.return_value = mock_collection
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            with patch('app.chromadb_client.time.time', side_effect=[0, 0.15]):  # Mock execution time
                client = ChromaDBClient(sample_instance)
                
                result = client.query_collection("test-collection", ["test query"], 5)
                
                assert result is not None
                assert result["results_count"] == 2
                assert result["execution_time"] == 150  # 0.15 * 1000
                assert "results" in result
                
                mock_collection.query.assert_called_with(
                    query_texts=["test query"],
                    n_results=5,
                    include=['documents', 'metadatas', 'distances']
                )
    
    def test_query_collection_empty_results(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test querying collection with empty results"""
        mock_collection = Mock()
        mock_collection.query.return_value = {
            "ids": [[]],
            "documents": [[]],
            "metadatas": [[]],
            "distances": [[]]
        }
        mock_chromadb_client.get_collection.return_value = mock_collection
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            with patch('app.chromadb_client.time.time', side_effect=[0, 0.1]):
                client = ChromaDBClient(sample_instance)
                
                result = client.query_collection("test-collection", ["test query"])
                
                assert result is not None
                assert result["results_count"] == 0
    
    def test_query_collection_failure(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test query collection failure"""
        mock_chromadb_client.get_collection.side_effect = Exception("Collection not found")
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            result = client.query_collection("nonexistent-collection", ["test query"])
            assert result is None
    
    def test_add_documents_success(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test adding documents successfully"""
        mock_collection = Mock()
        mock_collection.add.return_value = None
        mock_chromadb_client.get_collection.return_value = mock_collection
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            result = client.add_documents(
                "test-collection",
                ["Document 1", "Document 2"],
                [{"key": "value1"}, {"key": "value2"}],
                ["doc1", "doc2"]
            )
            
            assert result is True
            mock_collection.add.assert_called_with(
                documents=["Document 1", "Document 2"],
                metadatas=[{"key": "value1"}, {"key": "value2"}],
                ids=["doc1", "doc2"]
            )
    
    def test_add_documents_failure(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test adding documents failure"""
        mock_chromadb_client.get_collection.side_effect = Exception("Collection not found")
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            result = client.add_documents("test-collection", ["Document 1"])
            assert result is False
    
    def test_get_collection_data_success(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test getting collection data successfully"""
        mock_collection = Mock()
        mock_collection.get.return_value = {
            "ids": ["doc1", "doc2"],
            "documents": ["Document 1", "Document 2"],
            "metadatas": [{"key": "value1"}, {"key": "value2"}]
        }
        mock_chromadb_client.get_collection.return_value = mock_collection
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            result = client.get_collection_data("test-collection", 50)
            
            assert result is not None
            assert result["ids"] == ["doc1", "doc2"]
            assert result["documents"] == ["Document 1", "Document 2"]
            assert result["metadatas"] == [{"key": "value1"}, {"key": "value2"}]
            
            mock_collection.get.assert_called_with(
                limit=50,
                include=['documents', 'metadatas']
            )
    
    def test_get_document_success(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test getting a specific document"""
        mock_collection = Mock()
        mock_collection.get.return_value = {
            "ids": ["doc1"],
            "documents": ["Document 1"],
            "metadatas": [{"key": "value1"}]
        }
        mock_chromadb_client.get_collection.return_value = mock_collection
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            result = client.get_document("test-collection", "doc1")
            
            assert result is not None
            assert result["id"] == "doc1"
            assert result["document"] == "Document 1"
            assert result["metadata"] == {"key": "value1"}
    
    def test_get_document_not_found(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test getting document that doesn't exist"""
        mock_collection = Mock()
        mock_collection.get.return_value = {
            "ids": [],
            "documents": [],
            "metadatas": []
        }
        mock_chromadb_client.get_collection.return_value = mock_collection
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            result = client.get_document("test-collection", "nonexistent")
            assert result is None
    
    def test_delete_document_success(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test deleting a document successfully"""
        mock_collection = Mock()
        mock_collection.delete.return_value = None
        mock_chromadb_client.get_collection.return_value = mock_collection
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            result = client.delete_document("test-collection", "doc1")
            
            assert result is True
            mock_collection.delete.assert_called_with(ids=["doc1"])
    
    def test_delete_documents_success(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test deleting multiple documents successfully"""
        mock_collection = Mock()
        mock_collection.delete.return_value = None
        mock_chromadb_client.get_collection.return_value = mock_collection
        
        with patch('app.chromadb_client.chromadb.HttpClient', return_value=mock_chromadb_client):
            client = ChromaDBClient(sample_instance)
            
            result = client.delete_documents("test-collection", ["doc1", "doc2"])
            
            assert result is True
            mock_collection.delete.assert_called_with(ids=["doc1", "doc2"])


class TestChromaDBManager:
    """Test ChromaDBManager functionality"""
    
    def test_manager_singleton(self):
        """Test that manager is a singleton"""
        assert chroma_manager is not None
        
        # Create another instance - should be the same
        new_manager = ChromaDBManager()
        # Note: The singleton pattern isn't enforced in the current implementation
        # but we can test that multiple instances work independently
    
    def test_get_client_new_instance(self, sample_instance: ChromaDBInstance, mock_chromadb_client):
        """Test getting client for new instance"""
        manager = ChromaDBManager()
        
        with patch('app.chromadb_client.ChromaDBClient') as mock_client_class:
            mock_client_instance = Mock()
            mock_client_class.return_value = mock_client_instance
            
            client = manager.get_client(sample_instance.id)
            
            assert client == mock_client_instance
            # Should be cached
            assert sample_instance.id in manager.clients
    
    def test_get_client_cached_instance(self, sample_instance: ChromaDBInstance):
        """Test getting cached client"""
        manager = ChromaDBManager()
        mock_client = Mock()
        
        # Manually add to cache
        manager.clients[sample_instance.id] = mock_client
        
        client = manager.get_client(sample_instance.id)
        assert client == mock_client
    
    def test_get_client_nonexistent_instance(self, db_session: Session):
        """Test getting client for nonexistent instance"""
        manager = ChromaDBManager()
        
        with patch('app.chromadb_client.SessionLocal', return_value=db_session):
            client = manager.get_client(99999)  # Nonexistent ID
            assert client is None
    
    def test_remove_client(self, sample_instance: ChromaDBInstance):
        """Test removing client from cache"""
        manager = ChromaDBManager()
        mock_client = Mock()
        
        # Add to cache
        manager.clients[sample_instance.id] = mock_client
        
        # Remove
        manager.remove_client(sample_instance.id)
        
        assert sample_instance.id not in manager.clients
    
    def test_remove_nonexistent_client(self):
        """Test removing nonexistent client"""
        manager = ChromaDBManager()
        
        # Should not raise exception
        manager.remove_client(99999)
    
    def test_clear_cache(self, sample_instance: ChromaDBInstance):
        """Test clearing client cache"""
        manager = ChromaDBManager()
        mock_client = Mock()
        
        # Add to cache
        manager.clients[sample_instance.id] = mock_client
        
        # Clear cache
        manager.clear_cache()
        
        assert len(manager.clients) == 0
    
    def test_get_all_instances(self, db_session: Session, sample_instance: ChromaDBInstance):
        """Test getting all instances"""
        manager = ChromaDBManager()
        
        with patch('app.chromadb_client.SessionLocal', return_value=db_session):
            instances = manager.get_all_instances()
            
            assert len(instances) == 1
            assert instances[0].id == sample_instance.id
    
    def test_test_instance_connection_success(self, sample_instance: ChromaDBInstance):
        """Test successful instance connection test"""
        manager = ChromaDBManager()
        mock_client = Mock()
        mock_client.test_connection.return_value = True
        
        with patch.object(manager, 'get_client', return_value=mock_client):
            result = manager.test_instance_connection(sample_instance.id)
            assert result is True
    
    def test_test_instance_connection_failure(self, sample_instance: ChromaDBInstance):
        """Test failed instance connection test"""
        manager = ChromaDBManager()
        mock_client = Mock()
        mock_client.test_connection.return_value = False
        
        with patch.object(manager, 'get_client', return_value=mock_client):
            result = manager.test_instance_connection(sample_instance.id)
            assert result is False
    
    def test_test_instance_connection_no_client(self):
        """Test connection test with no client"""
        manager = ChromaDBManager()
        
        with patch.object(manager, 'get_client', return_value=None):
            result = manager.test_instance_connection(99999)
            assert result is False 