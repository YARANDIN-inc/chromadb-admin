import pytest
from unittest.mock import Mock, patch
from typing import List, Dict

from app.text_splitters import DocumentSplitter


class TestDocumentSplitter:
    """Test DocumentSplitter functionality"""
    
    def test_get_available_splitters(self):
        """Test getting available splitter options"""
        splitters = DocumentSplitter.get_available_splitters()
        
        assert isinstance(splitters, dict)
        assert "recursive" in splitters
        assert "character" in splitters
        assert "token" in splitters
        assert "markdown" in splitters
        assert "python" in splitters
        assert "javascript" in splitters
        assert "java" in splitters
        assert "cpp" in splitters
        assert "html" in splitters
        
        # Check descriptions
        assert "Recursive" in splitters["recursive"]
        assert "Character" in splitters["character"]
    
    def test_split_documents_recursive_splitter(self, sample_documents):
        """Test document splitting with recursive character splitter"""
        documents = [sample_documents[0]]  # Use first document
        
        with patch('app.text_splitters.RecursiveCharacterTextSplitter') as mock_splitter_class:
            mock_splitter = Mock()
            mock_splitter.split_text.return_value = ["Chunk 1", "Chunk 2"]
            mock_splitter_class.return_value = mock_splitter
            
            split_texts, split_metadatas, split_ids = DocumentSplitter.split_documents(
                documents, "recursive", 100, 20
            )
            
            assert len(split_texts) == 2
            assert split_texts == ["Chunk 1", "Chunk 2"]
            assert len(split_metadatas) == 2
            assert len(split_ids) == 2
            
            # Check metadata structure
            assert split_metadatas[0]["chunk_index"] == 0
            assert split_metadatas[1]["chunk_index"] == 1
            assert split_metadatas[0]["total_chunks"] == 2
            assert split_metadatas[0]["splitter_type"] == "recursive"
            assert split_metadatas[0]["chunk_size"] == 100
            assert split_metadatas[0]["chunk_overlap"] == 20
            
            # Check IDs
            assert "_chunk_0" in split_ids[0]
            assert "_chunk_1" in split_ids[1]
    
    def test_split_documents_character_splitter(self, sample_documents):
        """Test document splitting with character text splitter"""
        documents = [sample_documents[0]]
        
        with patch('app.text_splitters.CharacterTextSplitter') as mock_splitter_class:
            mock_splitter = Mock()
            mock_splitter.split_text.return_value = ["Character chunk 1", "Character chunk 2"]
            mock_splitter_class.return_value = mock_splitter
            
            split_texts, split_metadatas, split_ids = DocumentSplitter.split_documents(
                documents, "character", 200, 50
            )
            
            assert len(split_texts) == 2
            assert split_texts == ["Character chunk 1", "Character chunk 2"]
            assert split_metadatas[0]["splitter_type"] == "character"
            assert split_metadatas[0]["chunk_size"] == 200
            assert split_metadatas[0]["chunk_overlap"] == 50
    
    def test_split_documents_token_splitter(self, sample_documents):
        """Test document splitting with token text splitter"""
        documents = [sample_documents[0]]
        
        with patch('app.text_splitters.TokenTextSplitter') as mock_splitter_class:
            mock_splitter = Mock()
            mock_splitter.split_text.return_value = ["Token chunk"]
            mock_splitter_class.return_value = mock_splitter
            
            split_texts, split_metadatas, split_ids = DocumentSplitter.split_documents(
                documents, "token", 150, 30
            )
            
            assert len(split_texts) == 1
            assert split_metadatas[0]["splitter_type"] == "token"
    
    def test_split_documents_python_splitter(self, sample_documents):
        """Test document splitting with Python code splitter"""
        python_code = ["""
def hello_world():
    print("Hello, World!")

class MyClass:
    def __init__(self):
        self.value = 42
"""]
        
        with patch('app.text_splitters.RecursiveCharacterTextSplitter') as mock_splitter_class:
            mock_splitter = Mock()
            mock_splitter.split_text.return_value = ["Function chunk", "Class chunk"]
            mock_splitter_class.from_language.return_value = mock_splitter
            
            split_texts, split_metadatas, split_ids = DocumentSplitter.split_documents(
                python_code, "python", 100, 20
            )
            
            assert len(split_texts) == 2
            assert split_metadatas[0]["splitter_type"] == "python"
            
            # Verify from_language was called with Python
            mock_splitter_class.from_language.assert_called_once()
    
    def test_split_documents_javascript_splitter(self, sample_documents):
        """Test document splitting with JavaScript code splitter"""
        js_code = ["""
function helloWorld() {
    console.log("Hello, World!");
}

class MyClass {
    constructor() {
        this.value = 42;
    }
}
"""]
        
        with patch('app.text_splitters.RecursiveCharacterTextSplitter') as mock_splitter_class:
            mock_splitter = Mock()
            mock_splitter.split_text.return_value = ["JS function", "JS class"]
            mock_splitter_class.from_language.return_value = mock_splitter
            
            split_texts, split_metadatas, split_ids = DocumentSplitter.split_documents(
                js_code, "javascript", 100, 20
            )
            
            assert len(split_texts) == 2
            assert split_metadatas[0]["splitter_type"] == "javascript"
    
    def test_split_documents_markdown_splitter(self, sample_documents):
        """Test document splitting with markdown splitter"""
        markdown_doc = [sample_documents[2]]  # Markdown document
        
        with patch.object(DocumentSplitter, '_split_markdown') as mock_split_markdown:
            mock_split_markdown.return_value = ["# Header chunk", "Content chunk"]
            
            split_texts, split_metadatas, split_ids = DocumentSplitter.split_documents(
                markdown_doc, "markdown", 100, 20
            )
            
            assert len(split_texts) == 2
            assert split_metadatas[0]["splitter_type"] == "markdown"
            mock_split_markdown.assert_called_once()
    
    def test_split_documents_with_custom_metadata(self, sample_documents):
        """Test document splitting with custom metadata"""
        documents = [sample_documents[0]]
        metadata_list = [{"custom_field": "custom_value", "author": "test_author"}]
        ids_list = ["custom_id_1"]
        
        with patch('app.text_splitters.RecursiveCharacterTextSplitter') as mock_splitter_class:
            mock_splitter = Mock()
            mock_splitter.split_text.return_value = ["Chunk with metadata"]
            mock_splitter_class.return_value = mock_splitter
            
            split_texts, split_metadatas, split_ids = DocumentSplitter.split_documents(
                documents, "recursive", 100, 20, metadata_list, ids_list
            )
            
            assert len(split_texts) == 1
            assert len(split_metadatas) == 1
            assert len(split_ids) == 1
            
            # Check that custom metadata is preserved
            assert split_metadatas[0]["custom_field"] == "custom_value"
            assert split_metadatas[0]["author"] == "test_author"
            assert split_metadatas[0]["source_document_id"] == "custom_id_1"
            assert "custom_id_1_chunk_0" == split_ids[0]
    
    def test_split_documents_multiple_documents(self, sample_documents):
        """Test splitting multiple documents"""
        documents = sample_documents[:2]  # First two documents
        
        with patch('app.text_splitters.RecursiveCharacterTextSplitter') as mock_splitter_class:
            mock_splitter = Mock()
            # Return different chunks for each document
            mock_splitter.split_text.side_effect = [
                ["Doc1 Chunk1", "Doc1 Chunk2"], 
                ["Doc2 Chunk1"]
            ]
            mock_splitter_class.return_value = mock_splitter
            
            split_texts, split_metadatas, split_ids = DocumentSplitter.split_documents(
                documents, "recursive", 100, 20
            )
            
            assert len(split_texts) == 3  # 2 + 1 chunks
            assert split_texts == ["Doc1 Chunk1", "Doc1 Chunk2", "Doc2 Chunk1"]
            
            # Check that chunks are properly attributed to their source documents
            assert split_metadatas[0]["chunk_index"] == 0
            assert split_metadatas[1]["chunk_index"] == 1
            assert split_metadatas[2]["chunk_index"] == 0  # First chunk of second document
            
            # Different source document IDs
            doc1_id = split_metadatas[0]["source_document_id"]
            doc2_id = split_metadatas[2]["source_document_id"]
            assert doc1_id != doc2_id
    
    def test_split_documents_with_empty_chunks(self, sample_documents):
        """Test splitting documents that produce empty chunks"""
        documents = [sample_documents[0]]
        
        with patch('app.text_splitters.RecursiveCharacterTextSplitter') as mock_splitter_class:
            mock_splitter = Mock()
            mock_splitter.split_text.return_value = ["Valid chunk", "", "   ", "Another valid chunk"]
            mock_splitter_class.return_value = mock_splitter
            
            split_texts, split_metadatas, split_ids = DocumentSplitter.split_documents(
                documents, "recursive", 100, 20
            )
            
            # Empty chunks should be filtered out
            assert len(split_texts) == 2
            assert split_texts == ["Valid chunk", "Another valid chunk"]
            assert len(split_metadatas) == 2
            assert len(split_ids) == 2
    
    def test_split_documents_with_error(self, sample_documents):
        """Test document splitting when splitter raises an error"""
        documents = [sample_documents[0]]
        custom_ids = ["error_doc"]
        
        with patch('app.text_splitters.RecursiveCharacterTextSplitter') as mock_splitter_class:
            mock_splitter = Mock()
            mock_splitter.split_text.side_effect = Exception("Splitter error")
            mock_splitter_class.return_value = mock_splitter
            
            split_texts, split_metadatas, split_ids = DocumentSplitter.split_documents(
                documents, "recursive", 100, 20, ids_list=custom_ids
            )
            
            # Should fall back to original document
            assert len(split_texts) == 1
            assert split_texts[0] == documents[0]  # Original document
            assert split_metadatas[0]["splitter_type"] == "none"
            assert "error" in split_metadatas[0]
            assert split_ids[0] == "error_doc"
    
    def test_get_splitter_recursive(self):
        """Test getting recursive character text splitter"""
        with patch('app.text_splitters.RecursiveCharacterTextSplitter') as mock_class:
            DocumentSplitter._get_splitter("recursive", 100, 20)
            
            mock_class.assert_called_with(
                chunk_size=100,
                chunk_overlap=20,
                length_function=len,
                separators=["\n\n", "\n", " ", ""]
            )
    
    def test_get_splitter_character(self):
        """Test getting character text splitter"""
        with patch('app.text_splitters.CharacterTextSplitter') as mock_class:
            DocumentSplitter._get_splitter("character", 100, 20)
            
            mock_class.assert_called_with(
                chunk_size=100,
                chunk_overlap=20,
                separator="\n"
            )
    
    def test_get_splitter_token(self):
        """Test getting token text splitter"""
        with patch('app.text_splitters.TokenTextSplitter') as mock_class:
            DocumentSplitter._get_splitter("token", 100, 20)
            
            mock_class.assert_called_with(
                chunk_size=100,
                chunk_overlap=20
            )
    
    def test_get_splitter_python(self):
        """Test getting Python code splitter"""
        with patch('app.text_splitters.RecursiveCharacterTextSplitter') as mock_class:
            with patch('app.text_splitters.Language') as mock_language:
                mock_language.PYTHON = "PYTHON"
                
                DocumentSplitter._get_splitter("python", 100, 20)
                
                mock_class.from_language.assert_called_with(
                    language=mock_language.PYTHON,
                    chunk_size=100,
                    chunk_overlap=20
                )
    
    def test_get_splitter_unknown_type(self):
        """Test getting splitter for unknown type defaults to recursive"""
        with patch('app.text_splitters.RecursiveCharacterTextSplitter') as mock_class:
            DocumentSplitter._get_splitter("unknown_type", 100, 20)
            
            mock_class.assert_called_with(
                chunk_size=100,
                chunk_overlap=20
            )
    
    def test_split_markdown_success(self):
        """Test markdown splitting functionality"""
        markdown_text = """# Header 1

Some content under header 1.

## Header 2

Content under header 2.

### Header 3

More content here."""
        
        with patch('app.text_splitters.MarkdownHeaderTextSplitter') as mock_header_splitter:
            with patch('app.text_splitters.RecursiveCharacterTextSplitter') as mock_recursive_splitter:
                mock_header_instance = Mock()
                mock_header_instance.split_text.return_value = [
                    Mock(page_content="Header 1 content", metadata={}),
                    Mock(page_content="Header 2 content", metadata={})
                ]
                mock_header_splitter.return_value = mock_header_instance
                
                mock_recursive_instance = Mock()
                mock_recursive_instance.split_text.side_effect = lambda x: [x]  # Return as-is
                mock_recursive_splitter.return_value = mock_recursive_instance
                
                result = DocumentSplitter._split_markdown(markdown_text, 100, 20)
                
                assert len(result) == 2
                assert "Header 1 content" in result
                assert "Header 2 content" in result
    
    def test_split_markdown_fallback(self):
        """Test markdown splitting fallback to recursive splitter"""
        markdown_text = "Simple markdown without headers"
        
        with patch('app.text_splitters.MarkdownHeaderTextSplitter') as mock_header_splitter:
            with patch('app.text_splitters.RecursiveCharacterTextSplitter') as mock_recursive_splitter:
                # Make header splitter fail
                mock_header_splitter.side_effect = Exception("Header splitter failed")
                
                mock_recursive_instance = Mock()
                mock_recursive_instance.split_text.return_value = ["Fallback chunk"]
                mock_recursive_splitter.return_value = mock_recursive_instance
                
                result = DocumentSplitter._split_markdown(markdown_text, 100, 20)
                
                assert result == ["Fallback chunk"]
                mock_recursive_splitter.assert_called_once()
    
    def test_estimate_chunks(self):
        """Test chunk estimation functionality"""
        text = "This is a test text for chunk estimation. " * 100  # Long text
        
        # Test with different chunk sizes
        chunks_small = DocumentSplitter.estimate_chunks(text, 100, 20)
        chunks_large = DocumentSplitter.estimate_chunks(text, 1000, 20)
        
        assert isinstance(chunks_small, int)
        assert isinstance(chunks_large, int)
        assert chunks_small > chunks_large  # Smaller chunks = more chunks
        assert chunks_small > 0
        assert chunks_large > 0
    
    def test_estimate_chunks_short_text(self):
        """Test chunk estimation for short text"""
        text = "Short text"
        
        chunks = DocumentSplitter.estimate_chunks(text, 100, 20)
        assert chunks == 1  # Should fit in one chunk
    
    def test_estimate_chunks_empty_text(self):
        """Test chunk estimation for empty text"""
        text = ""
        
        chunks = DocumentSplitter.estimate_chunks(text, 100, 20)
        assert chunks == 0
    
    def test_estimate_chunks_exact_size(self):
        """Test chunk estimation for text exactly matching chunk size"""
        text = "a" * 100  # Exactly 100 characters
        
        chunks = DocumentSplitter.estimate_chunks(text, 100, 0)  # No overlap
        assert chunks == 1 