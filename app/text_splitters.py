"""
Text splitting functionality using LangChain text splitters
"""

from typing import List, Dict, Any, Optional
from langchain_text_splitters import (
    RecursiveCharacterTextSplitter,
    CharacterTextSplitter,
    TokenTextSplitter,
    MarkdownHeaderTextSplitter,
    PythonCodeTextSplitter,
    Language,
    RecursiveCharacterTextSplitter
)
import uuid


class DocumentSplitter:
    """Handle document splitting using various LangChain text splitters"""
    
    @staticmethod
    def get_available_splitters() -> Dict[str, str]:
        """Get available text splitter options"""
        return {
            "recursive": "Recursive Character Splitter (Recommended)",
            "character": "Character Text Splitter",
            "token": "Token Text Splitter",
            "markdown": "Markdown Header Splitter",
            "python": "Python Code Splitter",
            "javascript": "JavaScript Code Splitter",
            "java": "Java Code Splitter",
            "cpp": "C++ Code Splitter",
            "html": "HTML Splitter"
        }
    
    @staticmethod
    def split_documents(
        documents: List[str],
        splitter_type: str = "recursive",
        chunk_size: int = 1000,
        chunk_overlap: int = 200,
        metadata_list: Optional[List[Dict]] = None,
        ids_list: Optional[List[str]] = None
    ) -> tuple[List[str], List[Dict], List[str]]:
        """
        Split documents into chunks using the specified splitter
        
        Args:
            documents: List of document texts
            splitter_type: Type of splitter to use
            chunk_size: Maximum size of each chunk
            chunk_overlap: Overlap between chunks
            metadata_list: Optional metadata for each document
            ids_list: Optional IDs for each document
            
        Returns:
            Tuple of (split_texts, split_metadatas, split_ids)
        """
        
        # Initialize the splitter based on type
        splitter = DocumentSplitter._get_splitter(
            splitter_type, chunk_size, chunk_overlap
        )
        
        split_texts = []
        split_metadatas = []
        split_ids = []
        
        for i, document in enumerate(documents):
            # Get original metadata and ID
            original_metadata = metadata_list[i] if metadata_list and i < len(metadata_list) else {}
            original_id = ids_list[i] if ids_list and i < len(ids_list) else str(uuid.uuid4())
            
            try:
                # Split the document
                if splitter_type == "markdown":
                    # Markdown splitter works differently
                    chunks = DocumentSplitter._split_markdown(document, chunk_size, chunk_overlap)
                else:
                    chunks = splitter.split_text(document)
                
                # Create metadata and IDs for each chunk
                for j, chunk in enumerate(chunks):
                    if chunk.strip():  # Skip empty chunks
                        # Create chunk metadata
                        chunk_metadata = original_metadata.copy()
                        chunk_metadata.update({
                            "source_document_id": original_id,
                            "chunk_index": j,
                            "total_chunks": len(chunks),
                            "splitter_type": splitter_type,
                            "chunk_size": chunk_size,
                            "chunk_overlap": chunk_overlap,
                            "original_length": len(document),
                            "chunk_length": len(chunk)
                        })
                        
                        # Create chunk ID
                        chunk_id = f"{original_id}_chunk_{j}"
                        
                        split_texts.append(chunk)
                        split_metadatas.append(chunk_metadata)
                        split_ids.append(chunk_id)
                        
            except Exception as e:
                print(f"Error splitting document {i}: {e}")
                # Fall back to using the original document
                chunk_metadata = original_metadata.copy()
                chunk_metadata.update({
                    "source_document_id": original_id,
                    "chunk_index": 0,
                    "total_chunks": 1,
                    "splitter_type": "none",
                    "error": str(e),
                    "original_length": len(document),
                    "chunk_length": len(document)
                })
                
                split_texts.append(document)
                split_metadatas.append(chunk_metadata)
                split_ids.append(original_id)
        
        return split_texts, split_metadatas, split_ids
    
    @staticmethod
    def _get_splitter(splitter_type: str, chunk_size: int, chunk_overlap: int):
        """Get the appropriate text splitter"""
        
        if splitter_type == "recursive":
            return RecursiveCharacterTextSplitter(
                chunk_size=chunk_size,
                chunk_overlap=chunk_overlap,
                length_function=len,
                separators=["\n\n", "\n", " ", ""]
            )
        
        elif splitter_type == "character":
            return CharacterTextSplitter(
                chunk_size=chunk_size,
                chunk_overlap=chunk_overlap,
                separator="\n"
            )
        
        elif splitter_type == "token":
            return TokenTextSplitter(
                chunk_size=chunk_size,
                chunk_overlap=chunk_overlap
            )
        
        elif splitter_type == "python":
            return RecursiveCharacterTextSplitter.from_language(
                language=Language.PYTHON,
                chunk_size=chunk_size,
                chunk_overlap=chunk_overlap
            )
        
        elif splitter_type == "javascript":
            return RecursiveCharacterTextSplitter.from_language(
                language=Language.JS,
                chunk_size=chunk_size,
                chunk_overlap=chunk_overlap
            )
        
        elif splitter_type == "java":
            return RecursiveCharacterTextSplitter.from_language(
                language=Language.JAVA,
                chunk_size=chunk_size,
                chunk_overlap=chunk_overlap
            )
        
        elif splitter_type == "cpp":
            return RecursiveCharacterTextSplitter.from_language(
                language=Language.CPP,
                chunk_size=chunk_size,
                chunk_overlap=chunk_overlap
            )
        
        elif splitter_type == "html":
            return RecursiveCharacterTextSplitter.from_language(
                language=Language.HTML,
                chunk_size=chunk_size,
                chunk_overlap=chunk_overlap
            )
        
        else:
            # Default to recursive
            return RecursiveCharacterTextSplitter(
                chunk_size=chunk_size,
                chunk_overlap=chunk_overlap
            )
    
    @staticmethod
    def _split_markdown(text: str, chunk_size: int, chunk_overlap: int) -> List[str]:
        """Split markdown text using header-based splitting"""
        try:
            # First split by headers
            headers_to_split_on = [
                ("#", "Header 1"),
                ("##", "Header 2"),
                ("###", "Header 3"),
                ("####", "Header 4"),
            ]
            
            markdown_splitter = MarkdownHeaderTextSplitter(
                headers_to_split_on=headers_to_split_on
            )
            
            md_header_splits = markdown_splitter.split_text(text)
            
            # Then split further if chunks are too large
            recursive_splitter = RecursiveCharacterTextSplitter(
                chunk_size=chunk_size,
                chunk_overlap=chunk_overlap
            )
            
            final_chunks = []
            for doc in md_header_splits:
                if len(doc.page_content) > chunk_size:
                    sub_chunks = recursive_splitter.split_text(doc.page_content)
                    final_chunks.extend(sub_chunks)
                else:
                    final_chunks.append(doc.page_content)
            
            return final_chunks
            
        except Exception as e:
            print(f"Error in markdown splitting: {e}")
            # Fall back to recursive splitter
            fallback_splitter = RecursiveCharacterTextSplitter(
                chunk_size=chunk_size,
                chunk_overlap=chunk_overlap
            )
            return fallback_splitter.split_text(text)
    
    @staticmethod
    def estimate_chunks(text: str, chunk_size: int, chunk_overlap: int) -> int:
        """Estimate how many chunks a text will be split into"""
        if not text:
            return 0
        
        text_length = len(text)
        if text_length <= chunk_size:
            return 1
        
        # Rough estimation
        effective_chunk_size = chunk_size - chunk_overlap
        estimated_chunks = max(1, (text_length - chunk_overlap) // effective_chunk_size)
        return estimated_chunks 