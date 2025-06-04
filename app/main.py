from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import List, Optional
import json
from datetime import datetime

from .database import get_db, engine
from .models import Base, Collection, QueryLog, SystemMetrics, User
from .chromadb_client import chroma_manager
from .auth import (
    AuthManager, get_current_user_optional, get_current_user_required, 
    require_super_admin, require_admin_permission
)
from .config import settings

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="ChromaDB Admin Panel", description="Admin interface for ChromaDB management")

# Mount static files and templates
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

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
        
        # Create initial admin user
        admin_user = User(
            username=settings.INITIAL_ADMIN_USERNAME,
            email=settings.INITIAL_ADMIN_EMAIL,
            is_super_admin=True,
            can_search=True,
            can_create=True,
            can_add=True,
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
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error
    })

@app.post("/auth/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Process login"""
    user = db.query(User).filter(
        User.username == username,
        User.is_active == True
    ).first()
    
    if not user or not user.verify_password(password):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid username or password"
        })
    
    # Create session
    session_token = AuthManager.create_session(user, db)
    
    # Redirect to dashboard
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key="session_token",
        value=session_token,
        max_age=7 * 24 * 60 * 60,  # 7 days
        httponly=True,
        secure=False  # Set to True in production with HTTPS
    )
    return response

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
    
    # Check search permission for dashboard access
    if not (current_user.can_search or current_user.is_super_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Dashboard access requires search permission"
        )
    
    collections = chroma_manager.get_collections()
    
    # Update local database with collection info
    for col_info in collections:
        db_collection = db.query(Collection).filter(Collection.name == col_info["name"]).first()
        if not db_collection:
            db_collection = Collection(
                name=col_info["name"],
                collection_metadata=col_info["metadata"],
                document_count=col_info["count"],
                created_by_id=current_user.id
            )
            db.add(db_collection)
        else:
            db_collection.document_count = col_info["count"]
            db_collection.collection_metadata = col_info["metadata"]
    
    db.commit()
    
    # Get recent query logs
    recent_queries = db.query(QueryLog).order_by(QueryLog.created_at.desc()).limit(10).all()
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "current_user": current_user,
        "collections": collections,
        "recent_queries": recent_queries,
        "total_collections": len(collections),
        "total_documents": sum(col["count"] for col in collections)
    })

@app.get("/collections", response_class=HTMLResponse)
async def collections_page(
    request: Request,
    current_user: User = Depends(get_current_user_required)
):
    """Collections management page"""
    collections = chroma_manager.get_collections()
    return templates.TemplateResponse("collections.html", {
        "request": request,
        "current_user": current_user,
        "collections": collections
    })

@app.post("/collections/create")
async def create_collection(
    name: str = Form(...),
    metadata: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_required)
):
    """Create a new collection"""
    # Check create permission
    if not (current_user.can_create or current_user.is_super_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Create collection permission required"
        )
    
    try:
        # Debug logging to see exactly what we're getting
        print(f"DEBUG: name='{name}', metadata='{metadata}', metadata type={type(metadata)}")
        print(f"DEBUG: metadata.strip()='{metadata.strip()}', len={len(metadata.strip())}")
        
        # Handle empty metadata properly for ChromaDB 1.0.12
        if not metadata or metadata.strip() == "" or metadata.strip() == "{}":
            metadata_dict = None  # Pass None instead of empty dict for ChromaDB 1.0.12
            print("DEBUG: Using None for metadata")
        else:
            metadata_dict = json.loads(metadata)
            print(f"DEBUG: Parsed metadata: {metadata_dict}")
            # Also check if parsed metadata is empty dict
            if metadata_dict == {}:
                metadata_dict = None
                print("DEBUG: Converted empty dict to None")
        
        collection = chroma_manager.create_collection(name, metadata_dict)
        
        if collection:
            # Add to local database - use empty dict for database storage
            db_collection = Collection(
                name=name,
                collection_metadata=metadata_dict or {},
                document_count=0,
                created_by_id=current_user.id
            )
            db.add(db_collection)
            db.commit()
            
            return RedirectResponse(url="/collections", status_code=status.HTTP_302_FOUND)
        else:
            raise HTTPException(status_code=400, detail="Failed to create collection")
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON metadata")

@app.post("/collections/{collection_name}/delete")
async def delete_collection(
    collection_name: str, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_required)
):
    """Delete a collection"""
    # Check create permission for deletion
    if not (current_user.can_create or current_user.is_super_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Create collection permission required for deletion"
        )
    
    success = chroma_manager.delete_collection(collection_name)
    
    if success:
        # Remove from local database
        db_collection = db.query(Collection).filter(Collection.name == collection_name).first()
        if db_collection:
            db.delete(db_collection)
            db.commit()
        
        return RedirectResponse(url="/collections", status_code=status.HTTP_302_FOUND)
    else:
        raise HTTPException(status_code=400, detail="Failed to delete collection")

@app.get("/collections/{collection_name}", response_class=HTMLResponse)
async def collection_detail(
    request: Request, 
    collection_name: str,
    current_user: User = Depends(get_current_user_required)
):
    """Collection detail page"""
    collection_data = chroma_manager.get_collection_data(collection_name, limit=50)
    collections = chroma_manager.get_collections()
    current_collection = next((c for c in collections if c["name"] == collection_name), None)
    
    if not current_collection:
        raise HTTPException(status_code=404, detail="Collection not found")
    
    return templates.TemplateResponse("collection_detail.html", {
        "request": request,
        "current_user": current_user,
        "collection": current_collection,
        "collection_data": collection_data
    })

@app.get("/query", response_class=HTMLResponse)
async def query_page(
    request: Request,
    current_user: User = Depends(get_current_user_required)
):
    """Query interface page"""
    # Check search permission
    if not (current_user.can_search or current_user.is_super_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Search permission required"
        )
    
    collections = chroma_manager.get_collections()
    return templates.TemplateResponse("query.html", {
        "request": request,
        "current_user": current_user,
        "collections": collections
    })

@app.post("/query/execute")
async def execute_query(
    request: Request,
    collection_name: str = Form(...),
    query_text: str = Form(...),
    n_results: int = Form(10),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_required)
):
    """Execute a query"""
    # Check search permission
    if not (current_user.can_search or current_user.is_super_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Search permission required"
        )
    
    result = chroma_manager.query_collection(collection_name, [query_text], n_results)
    
    if result:
        # Log the query
        query_log = QueryLog(
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
            "results": result["results"],
            "execution_time": result["execution_time"],
            "query_text": query_text,
            "collection_name": collection_name
        })
    else:
        raise HTTPException(status_code=400, detail="Query execution failed")

@app.get("/add-documents/{collection_name}", response_class=HTMLResponse)
async def add_documents_page(
    request: Request, 
    collection_name: str,
    current_user: User = Depends(get_current_user_required)
):
    """Add documents page"""
    # Check add permission
    if not (current_user.can_add or current_user.is_super_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Add documents permission required"
        )
    
    return templates.TemplateResponse("add_documents.html", {
        "request": request,
        "current_user": current_user,
        "collection_name": collection_name
    })

@app.post("/add-documents/{collection_name}")
async def add_documents(
    collection_name: str,
    documents: str = Form(...),
    ids: str = Form(""),
    metadatas: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_required)
):
    """Add documents to a collection"""
    # Check add permission
    if not (current_user.can_add or current_user.is_super_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Add documents permission required"
        )
    
    try:
        docs_list = [doc.strip() for doc in documents.split('\n') if doc.strip()]
        ids_list = [id.strip() for id in ids.split('\n') if id.strip()] if ids.strip() else None
        
        metadatas_list = None
        if metadatas.strip():
            metadatas_list = [json.loads(meta.strip()) for meta in metadatas.split('\n') if meta.strip()]
        
        success = chroma_manager.add_documents(collection_name, docs_list, metadatas_list, ids_list)
        
        if success:
            # Log the operation
            query_log = QueryLog(
                collection_name=collection_name,
                query_type="add",
                query_text=f"Added {len(docs_list)} documents",
                results_count=len(docs_list),
                execution_time=0,
                user_id=current_user.id
            )
            db.add(query_log)
            db.commit()
            
            return RedirectResponse(url=f"/collections/{collection_name}", status_code=status.HTTP_302_FOUND)
        else:
            raise HTTPException(status_code=400, detail="Failed to add documents")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error processing documents: {str(e)}")

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
    can_search: Optional[str] = Form(None),
    can_create: Optional[str] = Form(None),
    can_add: Optional[str] = Form(None),
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
        can_search=can_search == "true",
        can_create=can_create == "true",
        can_add=can_add == "true",
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
    can_search: Optional[str] = Form(None),
    can_create: Optional[str] = Form(None),
    can_add: Optional[str] = Form(None),
    can_admin: Optional[str] = Form(None),
    is_active: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_permission)
):
    """Update user"""
    user_to_update = db.query(User).filter(User.id == user_id).first()
    if not user_to_update:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check permissions: super admins can edit anyone, regular admins can't edit super admins
    if not current_user.is_super_admin and user_to_update.is_super_admin:
        raise HTTPException(status_code=403, detail="Cannot edit super admin")
    
    # Update user
    user_to_update.username = username
    user_to_update.email = email
    user_to_update.can_search = can_search == "true"
    user_to_update.can_create = can_create == "true"
    user_to_update.can_add = can_add == "true"
    user_to_update.can_admin = can_admin == "true"
    user_to_update.is_active = is_active == "true"
    
    if password:
        user_to_update.set_password(password)
    
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
    
    # Check permissions
    if not current_user.is_super_admin and user_to_delete.is_super_admin:
        raise HTTPException(status_code=403, detail="Cannot delete super admin")
    
    if user_to_delete.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    db.delete(user_to_delete)
    db.commit()
    
    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080) 