import chromadb
from chromadb import ClientAPI
from typing import List, Dict, Any, Optional
import time
import uuid
from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import ChromaDBInstance

class ChromaDBClient:
    """Individual ChromaDB client for a specific instance"""
    
    def __init__(self, instance: ChromaDBInstance):
        self.instance = instance
        self.client: Optional[ClientAPI] = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize ChromaDB client for this instance"""
        try:
            # Parse the URL to get host and port
            url_parts = self.instance.url.replace("http://", "").replace("https://", "")
            if ":" in url_parts:
                host, port = url_parts.split(":", 1)
                port = int(port)
            else:
                host = url_parts
                port = 8000
            
            # Prepare headers for authentication if token is provided
            headers = {}
            if self.instance.token:
                headers["Authorization"] = f"Bearer {self.instance.token}"
                print(f"Using ChromaDB authentication with token for instance '{self.instance.name}'")
            
            # Create client using the ChromaDB 1.0.12 API
            client_kwargs = {
                "host": host,
                "port": port,
                "settings": chromadb.Settings(
                    chroma_api_impl="chromadb.api.fastapi.FastAPI",
                    chroma_server_host=host,
                    chroma_server_http_port=port,
                    anonymized_telemetry=False
                )
            }
            
            # Add headers if authentication is needed
            if headers:
                client_kwargs["headers"] = headers
            
            self.client = chromadb.HttpClient(**client_kwargs)
            
            # Test the connection by listing collections
            collections = self.client.list_collections()
            print(f"Successfully connected to ChromaDB instance '{self.instance.name}' at {self.instance.url}")
            print(f"Found {len(collections)} existing collections")
            
        except Exception as e:
            print(f"Warning: Could not connect to ChromaDB instance '{self.instance.name}' at {self.instance.url}: {e}")
            print(f"ChromaDB functionality for instance '{self.instance.name}' will be limited until connection is established.")
            self.client = None
    
    def _ensure_connection(self):
        """Ensure we have a valid connection to ChromaDB"""
        if self.client is None:
            self._initialize_client()
        return self.client is not None
    
    def test_connection(self) -> bool:
        """Test if the connection is working"""
        try:
            if not self.client:
                return False
            self.client.list_collections()
            return True
        except Exception:
            return False
    
    def get_collections(self) -> List[Dict[str, Any]]:
        """Get all collections from this ChromaDB instance"""
        if not self._ensure_connection():
            return []
        
        try:
            collections = self.client.list_collections()
            result = []
            
            for collection in collections:
                try:
                    count = collection.count()
                    result.append({
                        "name": collection.name,
                        "metadata": collection.metadata or {},
                        "count": count
                    })
                except Exception as e:
                    print(f"Error getting count for collection {collection.name}: {e}")
                    result.append({
                        "name": collection.name,
                        "metadata": collection.metadata or {},
                        "count": 0
                    })
            
            return result
        except Exception as e:
            print(f"Error getting collections from instance '{self.instance.name}': {e}")
            return []
    
    def get_collection(self, name: str):
        """Get a specific collection"""
        if not self._ensure_connection():
            return None
            
        try:
            return self.client.get_collection(name)
        except Exception as e:
            print(f"Error getting collection {name} from instance '{self.instance.name}': {e}")
            return None
    
    def create_collection(self, name: str, metadata: Optional[Dict] = None):
        """Create a new collection"""
        if not self._ensure_connection():
            return None
            
        try:
            # In ChromaDB 1.0.12, omit metadata parameter entirely if None to avoid validation error
            if metadata is None:
                collection = self.client.create_collection(
                    name=name,
                    embedding_function=None  # Use default embedding function
                )
            else:
                collection = self.client.create_collection(
                    name=name,
                    metadata=metadata,
                    embedding_function=None  # Use default embedding function
                )
            print(f"Successfully created collection '{name}' in instance '{self.instance.name}'")
            return collection
        except Exception as e:
            print(f"Error creating collection {name} in instance '{self.instance.name}': {e}")
            # Check if collection already exists
            try:
                existing = self.client.get_collection(name)
                print(f"Collection {name} already exists in instance '{self.instance.name}'")
                return existing
            except:
                return None
    
    def delete_collection(self, name: str) -> bool:
        """Delete a collection"""
        if not self._ensure_connection():
            return False
            
        try:
            self.client.delete_collection(name)
            print(f"Successfully deleted collection '{name}' from instance '{self.instance.name}'")
            return True
        except Exception as e:
            print(f"Error deleting collection {name} from instance '{self.instance.name}': {e}")
            return False
    
    def query_collection(self, collection_name: str, query_texts: List[str], n_results: int = 10):
        """Query a collection"""
        if not self._ensure_connection():
            return None
            
        try:
            start_time = time.time()
            collection = self.client.get_collection(collection_name)
            
            # ChromaDB 1.0.12 query API
            results = collection.query(
                query_texts=query_texts,
                n_results=n_results,
                include=['documents', 'metadatas', 'distances']
            )
            
            execution_time = int((time.time() - start_time) * 1000)
            
            # Calculate results count from the nested structure
            results_count = 0
            if (results and 
                'ids' in results and 
                results['ids'] is not None and 
                len(results['ids']) > 0 and
                results['ids'][0] is not None):
                results_count = len(results['ids'][0])
            
            return {
                "results": results,
                "execution_time": execution_time,
                "results_count": results_count
            }
        except Exception as e:
            print(f"Error querying collection {collection_name} in instance '{self.instance.name}': {e}")
            return None
    
    def add_documents(self, collection_name: str, documents: List[str], 
                     metadatas: Optional[List[Dict]] = None, ids: Optional[List[str]] = None):
        """Add documents to a collection"""
        if not self._ensure_connection():
            return False
            
        try:
            collection = self.client.get_collection(collection_name)
            
            # Generate IDs if not provided
            if ids is None:
                ids = [str(uuid.uuid4()) for _ in documents]
            
            # Ensure we have the right number of IDs
            if len(ids) != len(documents):
                ids = [str(uuid.uuid4()) for _ in documents]
            
            # Add documents using ChromaDB 1.0.12 API
            collection.add(
                ids=ids,
                documents=documents,
                metadatas=metadatas
            )
            
            print(f"Successfully added {len(documents)} documents to collection '{collection_name}' in instance '{self.instance.name}'")
            return True
        except Exception as e:
            print(f"Error adding documents to collection {collection_name} in instance '{self.instance.name}': {e}")
            return False
    
    def get_collection_data(self, collection_name: str, limit: int = 100):
        """Get documents from a collection"""
        if not self._ensure_connection():
            return None
            
        try:
            collection = self.client.get_collection(collection_name)
            
            # Get all documents with limit
            results = collection.get(
                limit=limit,
                include=['documents', 'metadatas']
            )
            
            return results
        except Exception as e:
            print(f"Error getting data from collection {collection_name} in instance '{self.instance.name}': {e}")
            return None
    
    def get_document(self, collection_name: str, document_id: str):
        """Get a specific document by ID"""
        if not self._ensure_connection():
            return None
            
        try:
            collection = self.client.get_collection(collection_name)
            
            # Get specific document by ID
            results = collection.get(
                ids=[document_id],
                include=['documents', 'metadatas', 'embeddings']
            )
            
            # Safely check if we got results
            if not results:
                return None
                
            if 'ids' not in results:
                return None
                
            ids_list = results['ids']
            if not ids_list or len(ids_list) == 0:
                return None
                
            # Extract the first (and should be only) result
            doc_id = ids_list[0]
            
            # Extract document text
            document_text = None
            if 'documents' in results and results['documents'] is not None and len(results['documents']) > 0:
                document_text = results['documents'][0]
                
            # Extract metadata
            metadata = None
            if 'metadatas' in results and results['metadatas'] is not None and len(results['metadatas']) > 0:
                metadata = results['metadatas'][0]
                
            # Extract embedding (embeddings can be None or a numpy array)
            embedding = None
            if ('embeddings' in results and 
                results['embeddings'] is not None and 
                len(results['embeddings']) > 0 and
                results['embeddings'][0] is not None):
                embedding = results['embeddings'][0]
                
            return {
                'id': doc_id,
                'document': document_text,
                'metadata': metadata,
                'embedding': embedding
            }
            
        except Exception as e:
            print(f"Error getting document {document_id} from collection {collection_name} in instance '{self.instance.name}': {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def delete_document(self, collection_name: str, document_id: str) -> bool:
        """Delete a specific document by ID"""
        if not self._ensure_connection():
            return False
            
        try:
            collection = self.client.get_collection(collection_name)
            
            # Delete document by ID
            collection.delete(ids=[document_id])
            
            print(f"Successfully deleted document '{document_id}' from collection '{collection_name}' in instance '{self.instance.name}'")
            return True
        except Exception as e:
            print(f"Error deleting document {document_id} from collection {collection_name} in instance '{self.instance.name}': {e}")
            return False
    
    def delete_documents(self, collection_name: str, document_ids: List[str]) -> bool:
        """Delete multiple documents by IDs"""
        if not self._ensure_connection():
            return False
            
        try:
            collection = self.client.get_collection(collection_name)
            
            # Delete documents by IDs
            collection.delete(ids=document_ids)
            
            print(f"Successfully deleted {len(document_ids)} documents from collection '{collection_name}' in instance '{self.instance.name}'")
            return True
        except Exception as e:
            print(f"Error deleting documents from collection {collection_name} in instance '{self.instance.name}': {e}")
            return False

class ChromaDBManager:
    """Manager for multiple ChromaDB instances"""
    
    def __init__(self):
        self.clients: Dict[int, ChromaDBClient] = {}
    
    def get_client(self, instance_id: int) -> Optional[ChromaDBClient]:
        """Get or create a client for a specific instance"""
        if instance_id in self.clients:
            return self.clients[instance_id]
        
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
            self.clients[instance_id] = client
            return client
        
        finally:
            db.close()
    
    def remove_client(self, instance_id: int):
        """Remove a client from cache (useful when instance is updated)"""
        if instance_id in self.clients:
            del self.clients[instance_id]
    
    def clear_cache(self):
        """Clear all cached clients (useful when instances are updated)"""
        self.clients.clear()
    
    def get_all_instances(self) -> List[ChromaDBInstance]:
        """Get all active ChromaDB instances from database"""
        db = SessionLocal()
        try:
            return db.query(ChromaDBInstance).filter(ChromaDBInstance.is_active == True).all()
        finally:
            db.close()
    
    def test_instance_connection(self, instance_id: int) -> bool:
        """Test connection to a specific instance"""
        client = self.get_client(instance_id)
        if not client:
            return False
        return client.test_connection()

# Global instance
chroma_manager = ChromaDBManager() 