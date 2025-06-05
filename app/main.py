from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session
from typing import List, Optional
import json
from datetime import datetime
import secrets
import html

from .database import get_db, engine
from .models import Base, Collection, QueryLog, SystemMetrics, User, ChromaDBInstance, UserInstancePermission
from .chromadb_client import chroma_manager
from .auth import (
    AuthManager, get_current_user_optional, get_current_user_required, 
    require_super_admin, require_admin_permission, require_any_instance_access
)
from .config import settings
from .text_splitters import DocumentSplitter

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="ChromaDB Admin Panel", description="Admin interface for ChromaDB management")

# Mount static files and templates
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# Add security middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https:"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    return response

# CSRF token generation and validation
def generate_csrf_token():
    return secrets.token_urlsafe(32)

def validate_csrf_token(request: Request, token: str) -> bool:
    session_token = request.cookies.get("session_token")
    if not session_token:
        return False
    # In production, store CSRF tokens in the session or cache
    # For now, we'll use a simple validation
    return len(token) == 43  # token_urlsafe(32) generates 43 chars

@app.on_event("startup")
async def create_initial_admin():
    """Create initial admin user from environment variables if configured"""
    if not settings.CREATE_INITIAL_ADMIN:
        return
    
    if not all([settings.INITIAL_ADMIN_USERNAME, settings.INITIAL_ADMIN_EMAIL, settings.INITIAL_ADMIN_PASSWORD]):
        print("⚠️  CREATE_INITIAL_ADMIN is true but missing required environment variables:")
        print("   INITIAL_ADMIN_USERNAME, INITIAL_ADMIN_EMAIL, INITIAL_ADMIN_PASSWORD")
        return
    
    from .database import SessionLocal
    
    db = SessionLocal()
    try:
        # Check if any users exist
        existing_users_count = db.query(User).count()
        
        if existing_users_count > 0:
            print(f"ℹ️  Initial admin creation skipped - {existing_users_count} users already exist in database")
            return
        
        # Check if admin username already exists
        existing_admin = db.query(User).filter(
            (User.username == settings.INITIAL_ADMIN_USERNAME) | 
            (User.email == settings.INITIAL_ADMIN_EMAIL)
        ).first()
        
        if existing_admin:
            print(f"⚠️  User with username '{settings.INITIAL_ADMIN_USERNAME}' or email '{settings.INITIAL_ADMIN_EMAIL}' already exists")
            return
        
        # Create initial admin user (updated for new model)
        admin_user = User(
            username=settings.INITIAL_ADMIN_USERNAME,
            email=settings.INITIAL_ADMIN_EMAIL,
            is_super_admin=True,
            can_admin=True,
            is_active=True
        )
        admin_user.set_password(settings.INITIAL_ADMIN_PASSWORD)
        
        db.add(admin_user)
        db.commit()
        
        print(f"✅ Initial super admin user '{settings.INITIAL_ADMIN_USERNAME}' created successfully!")
        print(f"   Email: {settings.INITIAL_ADMIN_EMAIL}")
        print(f"   You can now login at http://localhost:8080/auth/login")
        
    except Exception as e:
        print(f"❌ Error creating initial admin user: {e}")
        db.rollback()
    finally:
        db.close()

# Authentication routes
@app.get("/auth/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[str] = None):
    """Login page"""
    csrf_token = generate_csrf_token()
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error,
        "csrf_token": csrf_token
    })

@app.post("/auth/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db)
):
    """Process login"""
    # Validate CSRF token
    if not validate_csrf_token(request, csrf_token):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid security token",
            "csrf_token": generate_csrf_token()
        })
    
    # Check rate limiting
    client_ip = AuthManager.get_client_ip(request)
    if AuthManager.is_rate_limited(client_ip):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Too many failed login attempts. Please try again later.",
            "csrf_token": generate_csrf_token()
        })
    
    # Sanitize and validate inputs
    username = html.escape(username.strip())
    if not User.validate_username(username):
        AuthManager.record_failed_login(client_ip)
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid credentials",
            "csrf_token": generate_csrf_token()
        })
    
    user = db.query(User).filter(
        User.username == username,
        User.is_active == True
    ).first()
    
    if not user or not user.verify_password(password):
        AuthManager.record_failed_login(client_ip)
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid credentials",
            "csrf_token": generate_csrf_token()
        })
    
    try:
        # Clear failed login attempts on successful login
        AuthManager.clear_failed_login(client_ip)
        
        # Create session with request for fingerprinting
        session_token = AuthManager.create_session(user, db, request)
        
        # Redirect to dashboard
        response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
        response.set_cookie(
            key="session_token",
            value=session_token,
            max_age=7 * 24 * 60 * 60,  # 7 days
            httponly=True,
            secure=True,  # Set to True for HTTPS
            samesite="strict"  # CSRF protection
        )
        return response
    except Exception as e:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Login failed. Please try again.",
            "csrf_token": generate_csrf_token()
        })

@app.get("/auth/logout")
async def logout(
    request: Request,
    session_token: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Logout"""
    if session_token:
        AuthManager.logout(session_token, db)
    
    response = RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("session_token")
    return response

# Main routes with authentication
@app.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request, 
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Main dashboard"""
    if not current_user:
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)
    
    # Get user's accessible instances
    accessible_instances = AuthManager.get_user_accessible_instances(current_user, db)
    
    # Check if user has access to any instances
    if not accessible_instances and not current_user.is_super_admin:
        # If user has no instances, show message
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "current_user": current_user,
            "collections": [],
            "recent_queries": [],
            "total_collections": 0,
            "total_documents": 0,
            "accessible_instances": [],
            "no_instances": True
        })
    
    # Aggregate collections from all accessible instances
    all_collections = []
    total_documents = 0
    
    for instance in accessible_instances:
        client = chroma_manager.get_client(instance.id)
        if client:
            instance_collections = client.get_collections()
            for col in instance_collections:
                col['instance_name'] = instance.name
                col['instance_id'] = instance.id
                all_collections.append(col)
                total_documents += col.get('count', 0)
    
    # Get recent query logs for accessible instances
    instance_ids = [inst.id for inst in accessible_instances]
    recent_queries = db.query(QueryLog).filter(
        QueryLog.instance_id.in_(instance_ids)
    ).order_by(QueryLog.created_at.desc()).limit(10).all()
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "current_user": current_user,
        "collections": all_collections,
        "recent_queries": recent_queries,
        "total_collections": len(all_collections),
        "total_documents": total_documents,
        "accessible_instances": accessible_instances,
        "no_instances": False
    })

# ChromaDB Instances Management
@app.get("/instances", response_class=HTMLResponse)
async def instances_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_required)
):
    """ChromaDB instances management page"""
    # Get all instances or user's accessible instances
    if current_user.is_super_admin or current_user.can_admin:
        instances = db.query(ChromaDBInstance).all()
    else:
        instances = AuthManager.get_user_accessible_instances(current_user, db)
    
    # Get instance status and collections count
    instance_status = {}
    instance_collections = {}
    user_permissions = {}
    
    for instance in instances:
        # Test connection status
        instance_status[instance.id] = chroma_manager.test_instance_connection(instance.id)
        
        # Get collections count
        client = chroma_manager.get_client(instance.id)
        if client:
            collections = client.get_collections()
            instance_collections[instance.id] = len(collections)
        else:
            instance_collections[instance.id] = 0
        
        # Get user permissions for this instance
        if not current_user.is_super_admin:
            user_permissions[instance.id] = current_user.get_instance_permissions(instance.id)
    
    return templates.TemplateResponse("instances.html", {
        "request": request,
        "current_user": current_user,
        "instances": instances,
        "instance_status": instance_status,
        "instance_collections": instance_collections,
        "user_permissions": user_permissions
    })

@app.post("/instances/create")
async def create_instance(
    name: str = Form(...),
    url: str = Form(...),
    description: str = Form(""),
    token: str = Form(""),
    is_default: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_permission)
):
    """Create a new ChromaDB instance"""
    try:
        # Check if name already exists
        existing = db.query(ChromaDBInstance).filter(ChromaDBInstance.name == name).first()
        if existing:
            raise HTTPException(status_code=400, detail=f"Instance with name '{name}' already exists")
        
        # If setting as default, unset other defaults
        if is_default == "true":
            db.query(ChromaDBInstance).filter(ChromaDBInstance.is_default == True).update({
                ChromaDBInstance.is_default: False
            })
        
        # Create instance
        instance = ChromaDBInstance(
            name=name,
            url=url,
            description=description if description else None,
            token=token if token else None,
            is_default=is_default == "true",
            is_active=True
        )
        
        db.add(instance)
        db.commit()
        
        # Clear cache to pick up new instance
        chroma_manager.clear_cache()
        
        return RedirectResponse(url="/instances", status_code=status.HTTP_302_FOUND)
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/instances/update")
async def update_instance(
    instance_id: int = Form(...),
    name: str = Form(...),
    url: str = Form(...),
    description: str = Form(""),
    token: str = Form(""),
    is_default: Optional[str] = Form(None),
    is_active: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_permission)
):
    """Update a ChromaDB instance"""
    try:
        instance = db.query(ChromaDBInstance).filter(ChromaDBInstance.id == instance_id).first()
        if not instance:
            raise HTTPException(status_code=404, detail="Instance not found")
        
        # Check if name already exists (excluding current instance)
        existing = db.query(ChromaDBInstance).filter(
            ChromaDBInstance.name == name,
            ChromaDBInstance.id != instance_id
        ).first()
        if existing:
            raise HTTPException(status_code=400, detail=f"Instance with name '{name}' already exists")
        
        # If setting as default, unset other defaults
        if is_default == "true":
            db.query(ChromaDBInstance).filter(
                ChromaDBInstance.is_default == True,
                ChromaDBInstance.id != instance_id
            ).update({ChromaDBInstance.is_default: False})
        
        # Update instance
        instance.name = name
        instance.url = url
        instance.description = description if description else None
        if token:  # Only update token if provided
            instance.token = token
        instance.is_default = is_default == "true"
        instance.is_active = is_active == "true"
        
        db.commit()
        
        # Remove from cache to refresh connection
        chroma_manager.remove_client(instance_id)
        
        return RedirectResponse(url="/instances", status_code=status.HTTP_302_FOUND)
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/instances/delete")
async def delete_instance(
    instance_id: int = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_permission)
):
    """Delete a ChromaDB instance"""
    try:
        instance = db.query(ChromaDBInstance).filter(ChromaDBInstance.id == instance_id).first()
        if not instance:
            raise HTTPException(status_code=404, detail="Instance not found")
        
        # Don't allow deleting default instance
        if instance.is_default:
            raise HTTPException(status_code=400, detail="Cannot delete default instance")
        
        # Delete related records
        db.query(UserInstancePermission).filter(UserInstancePermission.instance_id == instance_id).delete()
        db.query(Collection).filter(Collection.instance_id == instance_id).delete()
        db.query(QueryLog).filter(QueryLog.instance_id == instance_id).delete()
        
        # Delete instance
        db.delete(instance)
        db.commit()
        
        # Remove from cache
        chroma_manager.remove_client(instance_id)
        
        return RedirectResponse(url="/instances", status_code=status.HTTP_302_FOUND)
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/instances/{instance_id}/test")
async def test_instance_connection(
    instance_id: int,
    current_user: User = Depends(require_admin_permission)
):
    """Test connection to a ChromaDB instance"""
    try:
        # Remove from cache to force fresh connection
        chroma_manager.remove_client(instance_id)
        
        # Test connection
        success = chroma_manager.test_instance_connection(instance_id)
        
        return JSONResponse(content={
            "success": success,
            "message": "Connection successful" if success else "Connection failed"
        })
        
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        })

@app.get("/collections", response_class=HTMLResponse)
async def collections_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_instance_access)
):
    """Collections management page"""
    # Get user's accessible instances
    accessible_instances = AuthManager.get_user_accessible_instances(current_user, db)
    
    # Aggregate collections from all accessible instances
    all_collections = []
    
    for instance in accessible_instances:
        client = chroma_manager.get_client(instance.id)
        if client:
            instance_collections = client.get_collections()
            for col in instance_collections:
                col['instance_name'] = instance.name
                col['instance_id'] = instance.id
                all_collections.append(col)
    
    csrf_token = generate_csrf_token()
    
    return templates.TemplateResponse("collections.html", {
        "request": request,
        "current_user": current_user,
        "collections": all_collections,
        "instances": accessible_instances,
        "csrf_token": csrf_token
    })

@app.post("/collections/create")
async def create_collection(
    name: str = Form(...),
    instance_id: int = Form(...),
    metadata: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_required)
):
    """Create a new collection"""
    try:
        # Validate CSRF token
        if not csrf_token or len(csrf_token) != 43:
            raise HTTPException(status_code=400, detail="Invalid security token")
        
        # Sanitize and validate inputs
        name = html.escape(name.strip())
        if not name or len(name) > 100:
            raise HTTPException(status_code=400, detail="Invalid collection name")
        
        if not isinstance(instance_id, int) or instance_id <= 0:
            raise HTTPException(status_code=400, detail="Invalid instance ID")
        
        # Check if user has permission to create collections in this instance
        if not AuthManager.check_instance_permission(current_user, instance_id, "create", db):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permission denied"
            )
        
        # Get the instance
        instance = db.query(ChromaDBInstance).filter(
            ChromaDBInstance.id == instance_id,
            ChromaDBInstance.is_active == True
        ).first()
        
        if not instance:
            raise HTTPException(status_code=404, detail="Instance not found")
        
        # Parse metadata safely
        metadata_dict = {}
        if metadata.strip():
            try:
                metadata_dict = json.loads(metadata)
                if not isinstance(metadata_dict, dict):
                    raise ValueError("Metadata must be a JSON object")
            except (json.JSONDecodeError, ValueError):
                raise HTTPException(status_code=400, detail="Invalid metadata format")
        
        # Create collection via ChromaDB client
        client = chroma_manager.get_client(instance_id)
        if not client:
            raise HTTPException(status_code=503, detail="Service unavailable")
        
        collection = client.create_collection(name, metadata_dict)
        
        if collection:
            # Store in database
            db_collection = Collection(
                name=name,
                instance_id=instance_id,
                collection_metadata=metadata_dict,
                created_by_id=current_user.id
            )
            db.add(db_collection)
            db.commit()
            
            return RedirectResponse(url=f"/instances/{instance_id}/collections", status_code=status.HTTP_302_FOUND)
        else:
            raise HTTPException(status_code=500, detail="Failed to create collection")
            
    except HTTPException:
        raise
    except Exception as e:
        # Log error securely without exposing details
        print(f"Collection creation error: {type(e).__name__}")
        raise HTTPException(status_code=500, detail="An error occurred")

@app.post("/collections/{collection_name}/delete")
async def delete_collection(
    collection_name: str,
    instance_id: int = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_required)
):
    """Delete a collection from a specific instance"""
    # Check create permission for the specific instance (create permission allows delete)
    if not AuthManager.check_instance_permission(current_user, instance_id, "create", db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Create collection permission required for this instance"
        )
    
    try:
        # Get the ChromaDB client for this instance
        client = chroma_manager.get_client(instance_id)
        if not client:
            raise HTTPException(status_code=400, detail="ChromaDB instance not available")
        
        success = client.delete_collection(collection_name)
        
        if success:
            # Remove from local database
            db.query(Collection).filter(
                Collection.name == collection_name,
                Collection.instance_id == instance_id
            ).delete()
            db.commit()
            
            return RedirectResponse(url="/collections", status_code=status.HTTP_302_FOUND)
        else:
            raise HTTPException(status_code=400, detail="Failed to delete collection")
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/instances/{instance_id}/collections", response_class=HTMLResponse)
async def instance_collections(
    request: Request,
    instance_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_required)
):
    """Collections for a specific instance"""
    # Check if user has access to this instance
    if not AuthManager.check_instance_permission(current_user, instance_id, "search", db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this instance"
        )
    
    # Get instance details
    instance = db.query(ChromaDBInstance).filter(ChromaDBInstance.id == instance_id).first()
    if not instance:
        raise HTTPException(status_code=404, detail="Instance not found")
    
    # Get collections for this instance
    client = chroma_manager.get_client(instance_id)
    collections = []
    if client:
        collections = client.get_collections()
        for col in collections:
            col['instance_name'] = instance.name
            col['instance_id'] = instance.id
    
    return templates.TemplateResponse("instance_collections.html", {
        "request": request,
        "current_user": current_user,
        "instance": instance,
        "collections": collections
    })

@app.get("/collections/{collection_name}", response_class=HTMLResponse)
async def collection_detail(
    request: Request, 
    collection_name: str,
    instance_id: int,
    current_user: User = Depends(get_current_user_required)
):
    """Collection detail page for a specific instance"""
    # Check search permission for the specific instance
    if not current_user.is_super_admin and not current_user.has_instance_permission(instance_id, "search"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Search permission required for this instance"
        )
    
    # Get the ChromaDB client for this instance
    client = chroma_manager.get_client(instance_id)
    if not client:
        raise HTTPException(status_code=400, detail="ChromaDB instance not available")
    
    # Get the collection object
    chroma_collection = client.get_collection(collection_name)
    if not chroma_collection:
        raise HTTPException(status_code=404, detail="Collection not found")
    
    # Get collection details from the collections list to get count and metadata
    collections = client.get_collections()
    collection_info = None
    for col in collections:
        if col['name'] == collection_name:
            collection_info = col
            break
    
    if not collection_info:
        # Fallback if not found in collections list
        collection_info = {
            'name': collection_name,
            'metadata': chroma_collection.metadata or {},
            'count': 0
        }
    
    # Get some sample documents
    collection_data = client.get_collection_data(collection_name, limit=50)
    
    return templates.TemplateResponse("collection_detail.html", {
        "request": request,
        "current_user": current_user,
        "collection": collection_info,  # Pass the collection info object
        "collection_name": collection_name,
        "collection_data": collection_data,  # Pass the documents data
        "instance_id": instance_id
    })

@app.get("/query", response_class=HTMLResponse)
async def query_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_instance_access)
):
    """Query interface page"""
    accessible_instances = AuthManager.get_user_accessible_instances(current_user, db)
    
    # Get all collections from accessible instances
    all_collections = []
    for instance in accessible_instances:
        if current_user.is_super_admin or current_user.has_instance_permission(instance.id, "search"):
            client = chroma_manager.get_client(instance.id)
            if client:
                instance_collections = client.get_collections()
                for col in instance_collections:
                    col['instance_name'] = instance.name
                    col['instance_id'] = instance.id
                    all_collections.append(col)
    
    return templates.TemplateResponse("query.html", {
        "request": request,
        "current_user": current_user,
        "collections": all_collections,
        "instances": accessible_instances
    })

@app.post("/query/execute")
async def execute_query(
    request: Request,
    collection_name: str = Form(...),
    instance_id: int = Form(...),
    query_text: str = Form(...),
    n_results: int = Form(10),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_required)
):
    """Execute a query against a specific collection in a specific instance"""
    # Check search permission for the specific instance
    if not AuthManager.check_instance_permission(current_user, instance_id, "search", db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Search permission required for this instance"
        )
    
    try:
        # Get the ChromaDB client for this instance
        client = chroma_manager.get_client(instance_id)
        if not client:
            raise HTTPException(status_code=400, detail="ChromaDB instance not available")
        
        result = client.query_collection(collection_name, [query_text], n_results)
        
        if result:
            # Log the query
            query_log = QueryLog(
                instance_id=instance_id,
                collection_name=collection_name,
                query_type="query",
                query_text=query_text,
                results_count=result["results_count"],
                execution_time=result["execution_time"],
                user_id=current_user.id
            )
            db.add(query_log)
            db.commit()
            
            return templates.TemplateResponse("query_results.html", {
                "request": request,
                "current_user": current_user,
                "query_text": query_text,
                "collection_name": collection_name,
                "instance_id": instance_id,
                "results": result["results"],
                "execution_time": result["execution_time"],
                "results_count": result["results_count"]
            })
        else:
            raise HTTPException(status_code=400, detail="Query failed")
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/add-documents/{collection_name}", response_class=HTMLResponse)
async def add_documents_page(
    request: Request, 
    collection_name: str,
    instance_id: int = Query(...),
    current_user: User = Depends(get_current_user_required)
):
    """Add documents page for a specific collection in a specific instance"""
    # Check add permission for the specific instance
    if not current_user.is_super_admin and not current_user.has_instance_permission(instance_id, "add"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Add documents permission required for this instance"
        )
    
    # Get available text splitters
    available_splitters = DocumentSplitter.get_available_splitters()
    
    return templates.TemplateResponse("add_documents.html", {
        "request": request,
        "current_user": current_user,
        "collection_name": collection_name,
        "instance_id": instance_id,
        "available_splitters": available_splitters
    })

@app.post("/add-documents/{collection_name}")
async def add_documents(
    collection_name: str,
    instance_id: int = Form(...),
    documents: str = Form(...),
    ids: str = Form(""),
    metadatas: str = Form(""),
    processing_mode: str = Form("lines"),  # "lines" or "split"
    splitter_type: str = Form("recursive"),
    chunk_size: int = Form(1000),
    chunk_overlap: int = Form(200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_required)
):
    """Add documents to a collection in a specific instance"""
    # Check add permission for the specific instance
    if not AuthManager.check_instance_permission(current_user, instance_id, "add", db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Add documents permission required for this instance"
        )
    
    try:
        # Get the ChromaDB client for this instance
        client = chroma_manager.get_client(instance_id)
        if not client:
            raise HTTPException(status_code=400, detail="ChromaDB instance not available")
        
        # Parse documents based on processing mode
        if processing_mode == "lines":
            # Original line-by-line processing
            doc_list = [doc.strip() for doc in documents.split('\n') if doc.strip()]
            
            if not doc_list:
                raise HTTPException(status_code=400, detail="No documents provided")
            
            # Parse IDs if provided
            ids_list = None
            if ids.strip():
                ids_list = [id_str.strip() for id_str in ids.split('\n') if id_str.strip()]
                if len(ids_list) != len(doc_list):
                    raise HTTPException(status_code=400, detail="Number of IDs must match number of documents")
            
            # Parse metadata if provided
            metadata_list = None
            if metadatas.strip():
                try:
                    metadata_list = []
                    for meta_str in metadatas.split('\n'):
                        meta_str = meta_str.strip()
                        if meta_str:
                            metadata_list.append(json.loads(meta_str))
                        else:
                            metadata_list.append({})
                    
                    if len(metadata_list) != len(doc_list):
                        raise HTTPException(status_code=400, detail="Number of metadata entries must match number of documents")
                except json.JSONDecodeError:
                    raise HTTPException(status_code=400, detail="Invalid JSON in metadata")
            
            final_docs = doc_list
            final_metadatas = metadata_list
            final_ids = ids_list
            
        else:  # processing_mode == "split"
            # Text splitting mode
            
            # Treat the entire input as documents to be split
            # Support multiple documents separated by a delimiter
            delimiter = "\n---DOCUMENT---\n"
            if delimiter in documents:
                doc_list = [doc.strip() for doc in documents.split(delimiter) if doc.strip()]
            else:
                # Single large document
                doc_list = [documents.strip()] if documents.strip() else []
            
            if not doc_list:
                raise HTTPException(status_code=400, detail="No documents provided")
            
            # Parse base IDs if provided (for document sources)
            base_ids_list = None
            if ids.strip():
                base_ids_list = [id_str.strip() for id_str in ids.split('\n') if id_str.strip()]
                if len(base_ids_list) != len(doc_list):
                    # If not enough IDs, generate the missing ones
                    while len(base_ids_list) < len(doc_list):
                        base_ids_list.append(f"doc_{len(base_ids_list) + 1}")
            
            # Parse base metadata if provided
            base_metadata_list = None
            if metadatas.strip():
                try:
                    base_metadata_list = []
                    for meta_str in metadatas.split('\n'):
                        meta_str = meta_str.strip()
                        if meta_str:
                            base_metadata_list.append(json.loads(meta_str))
                        else:
                            base_metadata_list.append({})
                    
                    # If not enough metadata entries, fill with empty dicts
                    while len(base_metadata_list) < len(doc_list):
                        base_metadata_list.append({})
                        
                except json.JSONDecodeError:
                    raise HTTPException(status_code=400, detail="Invalid JSON in metadata")
            
            # Use text splitter to split documents
            final_docs, final_metadatas, final_ids = DocumentSplitter.split_documents(
                documents=doc_list,
                splitter_type=splitter_type,
                chunk_size=chunk_size,
                chunk_overlap=chunk_overlap,
                metadata_list=base_metadata_list,
                ids_list=base_ids_list
            )
        
        # Add documents to ChromaDB
        success = client.add_documents(collection_name, final_docs, final_metadatas, final_ids)
        
        if success:
            # Update document count in local database
            db_collection = db.query(Collection).filter(
                Collection.name == collection_name,
                Collection.instance_id == instance_id
            ).first()
            if db_collection:
                # Refresh count from ChromaDB
                collections = client.get_collections()
                for col in collections:
                    if col['name'] == collection_name:
                        db_collection.document_count = col['count']
                        break
                db.commit()
            
            return RedirectResponse(url=f"/collections/{collection_name}?instance_id={instance_id}", status_code=status.HTTP_302_FOUND)
        else:
            raise HTTPException(status_code=400, detail="Failed to add documents")
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Document Management Routes
@app.get("/collections/{collection_name}/documents/{document_id}", response_class=HTMLResponse)
async def document_detail(
    request: Request,
    collection_name: str,
    document_id: str,
    instance_id: int = Query(...),
    current_user: User = Depends(get_current_user_required)
):
    """Document detail page for inspecting a specific document"""
    # Check search permission for the specific instance
    if not current_user.is_super_admin and not current_user.has_instance_permission(instance_id, "search"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Search permission required for this instance"
        )
    
    # Get the ChromaDB client for this instance
    client = chroma_manager.get_client(instance_id)
    if not client:
        raise HTTPException(status_code=400, detail="ChromaDB instance not available")
    
    # Get the specific document
    document = client.get_document(collection_name, document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Get collection info for breadcrumb
    collections = client.get_collections()
    collection_info = None
    for col in collections:
        if col['name'] == collection_name:
            collection_info = col
            break
    
    if not collection_info:
        collection_info = {'name': collection_name, 'metadata': {}, 'count': 0}
    
    return templates.TemplateResponse("document_detail.html", {
        "request": request,
        "current_user": current_user,
        "collection": collection_info,
        "collection_name": collection_name,
        "document": document,
        "instance_id": instance_id
    })

@app.post("/collections/{collection_name}/documents/{document_id}/delete")
async def delete_document(
    collection_name: str,
    document_id: str,
    instance_id: int = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_required)
):
    """Delete a specific document"""
    # Check manage permission for the specific instance (manage allows delete)
    if not AuthManager.check_instance_permission(current_user, instance_id, "manage", db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Manage permission required for this instance to delete documents"
        )
    
    try:
        # Get the ChromaDB client for this instance
        client = chroma_manager.get_client(instance_id)
        if not client:
            raise HTTPException(status_code=400, detail="ChromaDB instance not available")
        
        # Delete the document
        success = client.delete_document(collection_name, document_id)
        
        if success:
            return RedirectResponse(
                url=f"/collections/{collection_name}?instance_id={instance_id}", 
                status_code=status.HTTP_302_FOUND
            )
        else:
            raise HTTPException(status_code=400, detail="Failed to delete document")
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/collections/{collection_name}/documents/bulk-delete")
async def bulk_delete_documents(
    collection_name: str,
    instance_id: int = Form(...),
    document_ids: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_required)
):
    """Delete multiple documents"""
    # Check manage permission for the specific instance (manage allows delete)
    if not AuthManager.check_instance_permission(current_user, instance_id, "manage", db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Manage permission required for this instance to delete documents"
        )
    
    try:
        # Parse document IDs (comma-separated or one per line)
        ids_list = []
        for line in document_ids.replace(',', '\n').split('\n'):
            doc_id = line.strip()
            if doc_id:
                ids_list.append(doc_id)
        
        if not ids_list:
            raise HTTPException(status_code=400, detail="No document IDs provided")
        
        # Get the ChromaDB client for this instance
        client = chroma_manager.get_client(instance_id)
        if not client:
            raise HTTPException(status_code=400, detail="ChromaDB instance not available")
        
        # Delete the documents
        success = client.delete_documents(collection_name, ids_list)
        
        if success:
            return RedirectResponse(
                url=f"/collections/{collection_name}?instance_id={instance_id}", 
                status_code=status.HTTP_302_FOUND
            )
        else:
            raise HTTPException(status_code=400, detail="Failed to delete documents")
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Admin routes
@app.get("/admin", response_class=HTMLResponse)
async def admin_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_permission)
):
    """Admin page for user management"""
    # Get all users (super admins can see everyone, regular admins can't see other super admins)
    if current_user.is_super_admin:
        users = db.query(User).order_by(User.created_at.desc()).all()
    else:
        users = db.query(User).filter(User.is_super_admin == False).order_by(User.created_at.desc()).all()
    
    return templates.TemplateResponse("admin.html", {
        "request": request,
        "current_user": current_user,
        "users": users
    })

@app.post("/admin/users/create")
async def create_user(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    can_admin: Optional[str] = Form(None),
    is_super_admin: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin)
):
    """Create a new user (super admin only)"""
    # Check if username or email already exists
    existing = db.query(User).filter(
        (User.username == username) | (User.email == email)
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    # Create new user
    new_user = User(
        username=username,
        email=email,
        can_admin=can_admin == "true",
        is_super_admin=is_super_admin == "true"
    )
    new_user.set_password(password)
    
    db.add(new_user)
    db.commit()
    
    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)

@app.post("/admin/users/update")
async def update_user(
    user_id: int = Form(...),
    username: str = Form(...),
    email: str = Form(...),
    password: Optional[str] = Form(""),
    can_admin: Optional[str] = Form(None),
    is_active: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_permission)
):
    """Update user"""
    user_to_update = db.query(User).filter(User.id == user_id).first()
    if not user_to_update:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Only super admins can modify super admin users or grant super admin
    if user_to_update.is_super_admin and not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Only super admins can modify super admin users")
    
    # Check if username or email already exists (excluding current user)
    existing = db.query(User).filter(
        ((User.username == username) | (User.email == email)) & (User.id != user_id)
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    # Update user fields
    user_to_update.username = username
    user_to_update.email = email
    
    if password:
        user_to_update.set_password(password)
    
    # Only update admin permissions if current user has permission
    if current_user.is_super_admin:
        user_to_update.can_admin = can_admin == "true"
    
    user_to_update.is_active = is_active == "true"
    
    db.commit()
    
    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)

@app.post("/admin/users/delete")
async def delete_user(
    user_id: int = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_permission)
):
    """Delete user"""
    user_to_delete = db.query(User).filter(User.id == user_id).first()
    if not user_to_delete:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Can't delete yourself
    if user_to_delete.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    # Only super admins can delete super admin users
    if user_to_delete.is_super_admin and not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Only super admins can delete super admin users")
    
    # Delete user's instance permissions first
    db.query(UserInstancePermission).filter(UserInstancePermission.user_id == user_id).delete()
    
    # Delete user
    db.delete(user_to_delete)
    db.commit()
    
    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)

# Instance Permission Management Routes
@app.get("/instances/{instance_id}/permissions", response_class=HTMLResponse)
async def instance_permissions_page(
    request: Request,
    instance_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_permission)
):
    """Instance permissions management page"""
    # Get instance
    instance = db.query(ChromaDBInstance).filter(ChromaDBInstance.id == instance_id).first()
    if not instance:
        raise HTTPException(status_code=404, detail="Instance not found")
    
    # Get all users and their permissions for this instance
    users = db.query(User).order_by(User.username).all()
    user_permissions = {}
    
    for user in users:
        perm = user.get_instance_permissions(instance_id)
        user_permissions[user.id] = perm
    
    return templates.TemplateResponse("instance_permissions.html", {
        "request": request,
        "current_user": current_user,
        "instance": instance,
        "users": users,
        "user_permissions": user_permissions
    })

@app.post("/instances/{instance_id}/permissions/update")
async def update_instance_permissions(
    instance_id: int,
    user_id: int = Form(...),
    can_search: Optional[str] = Form(None),
    can_create: Optional[str] = Form(None),
    can_add: Optional[str] = Form(None),
    can_manage: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_permission)
):
    """Update user permissions for a specific instance"""
    # Check if instance exists
    instance = db.query(ChromaDBInstance).filter(ChromaDBInstance.id == instance_id).first()
    if not instance:
        raise HTTPException(status_code=404, detail="Instance not found")
    
    # Check if user exists
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get or create permission record
    permission = db.query(UserInstancePermission).filter(
        UserInstancePermission.user_id == user_id,
        UserInstancePermission.instance_id == instance_id
    ).first()
    
    if not permission:
        permission = UserInstancePermission(
            user_id=user_id,
            instance_id=instance_id
        )
        db.add(permission)
    
    # Update permissions
    permission.can_search = can_search == "true"
    permission.can_create = can_create == "true"
    permission.can_add = can_add == "true"
    permission.can_manage = can_manage == "true"
    
    db.commit()
    
    return RedirectResponse(url=f"/instances/{instance_id}/permissions", status_code=status.HTTP_302_FOUND)

@app.post("/instances/{instance_id}/permissions/delete")
async def delete_instance_permissions(
    instance_id: int,
    user_id: int = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_permission)
):
    """Remove all permissions for a user on a specific instance"""
    db.query(UserInstancePermission).filter(
        UserInstancePermission.user_id == user_id,
        UserInstancePermission.instance_id == instance_id
    ).delete()
    
    db.commit()
    
    return RedirectResponse(url=f"/instances/{instance_id}/permissions", status_code=status.HTTP_302_FOUND)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080) 