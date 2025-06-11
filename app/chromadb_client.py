import chromadb
from chromadb import ClientAPI
from typing import List, Dict, Any, Optional
import time
import uuid
import socket

from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction
from sqlalchemy.orm import Session
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

from .database import SessionLocal
from .models import ChromaDBInstance

# Set global socket timeout to prevent hanging
socket.setdefaulttimeout(1.0)

class TimeoutHTTPAdapter(HTTPAdapter):
    """Custom HTTP adapter with aggressive timeouts"""
    
    def __init__(self, timeout=5.0, *args, **kwargs):
        self.timeout = timeout
        super().__init__(*args, **kwargs)
        
    def send(self, request, **kwargs):
        # Force timeout on all requests
        kwargs['timeout'] = self.timeout
        return super().send(request, **kwargs)

class ChromaDBClient:
    """Individual ChromaDB client for a specific instance with timeout protection"""
    
    def __init__(self, instance: ChromaDBInstance):
        self.instance = instance
        self.client: Optional[ClientAPI] = None
        self._initialize_client()
    
    def _test_socket_connection(self, host: str, port: int, timeout: float = 3.0) -> bool:
        """Test socket connectivity before creating ChromaDB client"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _initialize_client(self):
        """Initialize ChromaDB client for this instance with timeout protection"""
        try:
            # Parse the URL to get host and port
            url_parts = self.instance.url.replace("http://", "").replace("https://", "")
            if ":" in url_parts:
                host, port = url_parts.split(":", 1)
                port = int(port)
            else:
                host = url_parts
                port = 8000

            test_response = requests.get(f"{self.instance.url.rstrip('/')}/api/v2/heartbeat",
                                  headers={"Authorization": f"Bearer {self.instance.token}"} if self.instance.token else {},
                                  timeout=3)

            # Test socket connectivity first (fast fail)
            if test_response.status_code != 200:
                print(f"Healthcheck failed for ChromaDB instance '{self.instance.name}' at {host}:{port}")
                self.client = None
                return
            
            # Prepare headers for authentication if token is provided
            headers = {}
            if self.instance.token:
                headers["Authorization"] = f"Bearer {self.instance.token}"
            
            # Configure timeout settings for ChromaDB
            settings = chromadb.Settings(
                chroma_api_impl="chromadb.api.fastapi.FastAPI",
                chroma_server_host=host,
                chroma_server_http_port=port,
                anonymized_telemetry=False,
            )
            
            # Create client with timeout protection
            client_kwargs = {
                "host": host,
                "port": port,
                "settings": settings
            }
            
            # Add headers if authentication is needed
            if headers:
                client_kwargs["headers"] = headers
            
            # Create the client with timeout
            with socket.socket() as test_sock:
                test_sock.settimeout(1.5)
                self.client = chromadb.HttpClient(**client_kwargs)
            
            # Test the connection with timeout
            start_time = time.time()
            collections = self._safe_operation(lambda: self.client.list_collections(), timeout=5.0)
            end_time = time.time()
            
            if collections is not None:
                print(f"✓ Connected to ChromaDB instance '{self.instance.name}' at {self.instance.url} ({end_time - start_time:.2f}s)")
                print(f"  Found {len(collections)} existing collections")
            else:
                raise Exception("Connection test failed")
            
        except Exception as e:
            print(f"✗ Failed to connect to ChromaDB instance '{self.instance.name}' at {self.instance.url}: {e}")
            self.client = None
    
    def _safe_operation(self, operation, timeout: float = 1.0, default_return=None):
        """Execute ChromaDB operation with timeout protection"""
        if not self.client:
            return default_return
            
        try:
            # Set socket timeout for this operation
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(timeout)
            
            # Execute operation
            result = operation()
            return result
            
        except (socket.timeout, requests.exceptions.Timeout, requests.exceptions.ConnectTimeout, 
                requests.exceptions.ReadTimeout, ConnectionError, OSError) as e:
            print(f"Timeout/Connection error in ChromaDB operation for instance '{self.instance.name}': {e}")
            return default_return
        except Exception as e:
            print(f"Error in ChromaDB operation for instance '{self.instance.name}': {e}")
            return default_return
        finally:
            # Restore original timeout
            if 'old_timeout' in locals():
                socket.setdefaulttimeout(old_timeout)
    
    def test_connection(self) -> bool:
        """Test if the connection is working with timeout"""
        result = self._safe_operation(lambda: self.client.list_collections(), timeout=3.0)
        return result is not None
    
    def get_collections(self) -> List[Dict[str, Any]]:
        """Get all collections from this ChromaDB instance with timeout"""
        collections = self._safe_operation(lambda: self.client.list_collections(), timeout=5.0, default_return=[])
        if not collections:
            return []
        
        result = []
        for collection in collections:
            try:
                count = self._safe_operation(lambda: collection.count(), timeout=3.0, default_return=0)
                result.append({
                    "name": collection.name,
                    "metadata": collection.metadata or {},
                    "count": count
                })
            except Exception as e:
                print(f"Error getting collection info for {collection.name}: {e}")
                result.append({
                    "name": collection.name,
                    "metadata": collection.metadata or {},
                    "count": 0
                })
        
        return result
    
    def get_collection(self, name: str):
        """Get a specific collection with timeout"""
        return self._safe_operation(lambda: self.client.get_collection(name, embedding_function=OpenAIEmbeddingFunction(
                    model_name="text-embedding-ada-002"
                )), timeout=5.0)
    
    def create_collection(self, name: str, metadata: Optional[Dict] = None):
        """Create a new collection with timeout"""
        def create_op():
            if metadata is None or metadata == {}:
                metadata_to_use = {"name": name}
            else:
                metadata_to_use = metadata
            
            collection = self.client.create_collection(
                name=name,
                metadata=metadata_to_use,
                embedding_function=OpenAIEmbeddingFunction(
                    model_name="text-embedding-ada-002"
                )
            )
            print(f"Successfully created collection '{name}' in instance '{self.instance.name}'")
            return collection
        
        result = self._safe_operation(create_op, timeout=10.0)
        
        # If creation failed, try to get existing collection
        if result is None:
            try:
                existing = self._safe_operation(lambda: self.client.get_collection(name, embedding_function=OpenAIEmbeddingFunction(
                model_name="text-embedding-ada-002"
            )), timeout=5.0)
                if existing:
                    print(f"Collection {name} already exists in instance '{self.instance.name}'")
                return existing
            except:
                return None
        
        return result
    
    def delete_collection(self, name: str) -> bool:
        """Delete a collection with timeout"""
        def delete_op():
            self.client.delete_collection(name)
            print(f"Successfully deleted collection '{name}' from instance '{self.instance.name}'")
            return True
        
        result = self._safe_operation(delete_op, timeout=10.0, default_return=False)
        return result is True
    
    def query_collection(self, collection_name: str, query_texts: List[str], n_results: int = 10):
        """Query a collection with timeout"""
        def query_op():
            start_time = time.time()
            collection = self.client.get_collection(collection_name, embedding_function=OpenAIEmbeddingFunction(
                model_name="text-embedding-ada-002"
            ))
            
            results = collection.query(
                query_texts=query_texts,
                n_results=n_results,
                include=['documents', 'metadatas', 'distances']
            )
            
            execution_time = int((time.time() - start_time) * 1000)
            
            results_count = 0
            if (results and 'ids' in results and results['ids'] is not None and 
                len(results['ids']) > 0 and results['ids'][0] is not None):
                results_count = len(results['ids'][0])
            
            return {
                "results": results,
                "execution_time": execution_time,
                "results_count": results_count
            }
        
        return self._safe_operation(query_op, timeout=15.0)
    
    def add_documents(self, collection_name: str, documents: List[str], 
                     metadatas: Optional[List[Dict]] = None, ids: Optional[List[str]] = None):
        """Add documents to a collection with timeout (optimized)"""
        def add_op():
            collection = self.client.get_collection(collection_name, embedding_function=OpenAIEmbeddingFunction(
                model_name="text-embedding-ada-002"
            ))
            
            if ids is None:
                ids_to_use = [str(uuid.uuid4()) for _ in documents]
            else:
                ids_to_use = ids
            
            if len(ids_to_use) != len(documents):
                ids_to_use = [str(uuid.uuid4()) for _ in documents]
            
            # Use upsert instead of add for better performance with duplicates
            collection.upsert(
                ids=ids_to_use,
                documents=documents,
                metadatas=metadatas
            )
            
            print(f"Successfully added {len(documents)} documents to collection '{collection_name}' in instance '{self.instance.name}'")
            return True
        
        # Optimized timeout calculation based on document count and size
        doc_count = len(documents)
        avg_doc_size = sum(len(doc) for doc in documents) / doc_count if doc_count > 0 else 0
        
        # Base timeout + additional time based on document count and average size
        base_timeout = 15.0
        doc_count_factor = min(doc_count * 0.1, 60.0)  # Max 60s for document count
        size_factor = min(avg_doc_size / 1000, 30.0)   # Max 30s for document size
        
        timeout = base_timeout + doc_count_factor + size_factor
        timeout = min(timeout, 120.0)  # Cap at 2 minutes
        
        print(f"Adding {doc_count} documents (avg size: {avg_doc_size:.0f} chars) with {timeout:.1f}s timeout")
        result = self._safe_operation(add_op, timeout=timeout, default_return=False)
        return result is True
    
    def get_collection_data(self, collection_name: str, limit: int = 100):
        """Get documents from a collection with timeout"""
        def get_data_op():
            collection = self.client.get_collection(collection_name, embedding_function=OpenAIEmbeddingFunction(
                model_name="text-embedding-ada-002"
            ))
            return collection.get(limit=limit, include=['documents', 'metadatas'])
        
        return self._safe_operation(get_data_op, timeout=15.0)
    
    def get_document(self, collection_name: str, document_id: str):
        """Get a specific document by ID with timeout"""
        def get_doc_op():
            collection = self.client.get_collection(collection_name, embedding_function=OpenAIEmbeddingFunction(
                model_name="text-embedding-ada-002"
            ))

            results = collection.get(
                ids=[document_id],
                include=['documents', 'metadatas', 'embeddings']
            )
            
            if not results or 'ids' not in results or not results['ids']:
                return None
            
            doc_id = results['ids'][0]
            document_text = results['documents'][0] if results.get('documents') else None
            metadata = results['metadatas'][0] if results.get('metadatas') else None
            embedding = results['embeddings'][0] if results.get('embeddings') else None
            
            return {
                'id': doc_id,
                'document': document_text,
                'metadata': metadata,
                'embedding': embedding
            }
        
        return self._safe_operation(get_doc_op, timeout=10.0)
    
    def delete_document(self, collection_name: str, document_id: str) -> bool:
        """Delete a specific document by ID with timeout"""
        def delete_op():
            collection = self.client.get_collection(collection_name, embedding_function=OpenAIEmbeddingFunction(
                model_name="text-embedding-ada-002"
            ))
            collection.delete(ids=[document_id])
            print(f"Successfully deleted document '{document_id}' from collection '{collection_name}' in instance '{self.instance.name}'")
            return True
        
        result = self._safe_operation(delete_op, timeout=10.0, default_return=False)
        return result is True
    
    def delete_documents(self, collection_name: str, document_ids: List[str]) -> bool:
        """Delete multiple documents by IDs with timeout"""
        def delete_op():
            collection = self.client.get_collection(collection_name, embedding_function=OpenAIEmbeddingFunction(
                model_name="text-embedding-ada-002"
            ))
            collection.delete(ids=document_ids)
            print(f"Successfully deleted {len(document_ids)} documents from collection '{collection_name}' in instance '{self.instance.name}'")
            return True
        
        result = self._safe_operation(delete_op, timeout=15.0, default_return=False)
        return result is True

class ChromaDBManager:
    """Manager for multiple ChromaDB instances with timeout protection"""
    
    def __init__(self):
        self.clients: Dict[int, ChromaDBClient] = {}
    
    def get_client(self, instance_id: int) -> Optional[ChromaDBClient]:
        """Get or create a client for a specific instance"""
        if instance_id in self.clients:
            client = self.clients[instance_id]
            # Test if client is still working
            if client.client is None or not client.test_connection():
                # Remove broken client and try to recreate
                del self.clients[instance_id]
            else:
                return client
        
        # Load instance from database
        db = SessionLocal()
        try:
            instance = db.query(ChromaDBInstance).filter(
                ChromaDBInstance.id == instance_id,
                ChromaDBInstance.is_active == True
            ).first()
            
            if not instance:
                return None
            
            # Create and cache client
            client = ChromaDBClient(instance)
            if client.client is not None:  # Only cache if connection successful
                self.clients[instance_id] = client
                return client
            else:
                return None
        
        finally:
            db.close()
    
    def remove_client(self, instance_id: int):
        """Remove a client from cache (useful when instance is updated)"""
        if instance_id in self.clients:
            del self.clients[instance_id]
    
    def clear_cache(self):
        """Clear all cached clients"""
        self.clients.clear()
    
    def get_all_instances(self) -> List[ChromaDBInstance]:
        """Get all active ChromaDB instances from database"""
        db = SessionLocal()
        try:
            return db.query(ChromaDBInstance).filter(ChromaDBInstance.is_active == True).all()
        finally:
            db.close()
    
    def test_instance_connection(self, instance_id: int) -> bool:
        """Test connection to a specific instance with timeout protection"""
        client = self.get_client(instance_id)
        if not client:
            return False
        return client.test_connection()

# Global instance
chroma_manager = ChromaDBManager() 