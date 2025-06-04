import chromadb
from chromadb import ClientAPI
from typing import List, Dict, Any, Optional
import time
import uuid
from .config import settings

class ChromaDBManager:
    def __init__(self):
        self.client: Optional[ClientAPI] = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize ChromaDB client with the 1.0.12 API"""
        try:
            # Parse the URL to get host and port
            url_parts = settings.CHROMADB_URL.replace("http://", "").replace("https://", "")
            if ":" in url_parts:
                host, port = url_parts.split(":")
                port = int(port)
            else:
                host = url_parts
                port = 8000
            
            # Prepare headers for authentication if token is provided
            headers = {}
            if settings.CHROMADB_TOKEN and settings.CHROMADB_TOKEN != "":
                headers["Authorization"] = f"Bearer {settings.CHROMADB_TOKEN}"
                print(f"Using ChromaDB authentication with token")
            
            # Create client using the new 1.0.12 API
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
            print(f"Successfully connected to ChromaDB 1.0.12 at {settings.CHROMADB_URL}")
            print(f"Found {len(collections)} existing collections")
            
        except Exception as e:
            print(f"Warning: Could not connect to ChromaDB at {settings.CHROMADB_URL}: {e}")
            print("ChromaDB functionality will be limited until connection is established.")
            self.client = None
    
    def _ensure_connection(self):
        """Ensure we have a valid connection to ChromaDB"""
        if self.client is None:
            self._initialize_client()
        return self.client is not None
    
    def get_collections(self) -> List[Dict[str, Any]]:
        """Get all collections from ChromaDB"""
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
            print(f"Error getting collections: {e}")
            return []
    
    def get_collection(self, name: str):
        """Get a specific collection"""
        if not self._ensure_connection():
            return None
            
        try:
            return self.client.get_collection(name)
        except Exception as e:
            print(f"Error getting collection {name}: {e}")
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
            print(f"Successfully created collection: {name}")
            return collection
        except Exception as e:
            print(f"Error creating collection {name}: {e}")
            # Check if collection already exists
            try:
                existing = self.client.get_collection(name)
                print(f"Collection {name} already exists")
                return existing
            except:
                return None
    
    def delete_collection(self, name: str) -> bool:
        """Delete a collection"""
        if not self._ensure_connection():
            return False
            
        try:
            self.client.delete_collection(name)
            print(f"Successfully deleted collection: {name}")
            return True
        except Exception as e:
            print(f"Error deleting collection {name}: {e}")
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
            if results and 'ids' in results and results['ids']:
                results_count = len(results['ids'][0]) if results['ids'][0] else 0
            
            return {
                "results": results,
                "execution_time": execution_time,
                "results_count": results_count
            }
        except Exception as e:
            print(f"Error querying collection {collection_name}: {e}")
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
            
            print(f"Successfully added {len(documents)} documents to {collection_name}")
            return True
        except Exception as e:
            print(f"Error adding documents to {collection_name}: {e}")
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
            print(f"Error getting data from {collection_name}: {e}")
            return None
    
    def reset_database(self):
        """Reset the entire ChromaDB database (useful for development)"""
        if not self._ensure_connection():
            return False
            
        try:
            self.client.reset()
            print("Successfully reset ChromaDB database")
            return True
        except Exception as e:
            print(f"Error resetting database: {e}")
            return False

# Global instance
chroma_manager = ChromaDBManager() 