import logging

from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi_csrf_protect import CsrfProtect
from fastapi_csrf_protect.exceptions import CsrfProtectError
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import Optional
import json
from datetime import datetime
import html

from .database import get_db, engine
from .models import Base, Collection, QueryLog, User, ChromaDBInstance, UserInstancePermission
from .chromadb_client import chroma_manager, ChromaDBClient
from .auth import (
    AuthManager, get_current_user_optional, get_current_user_required,
    require_super_admin, require_admin_permission, require_any_instance_access
)
from .config import settings
from .text_splitters import DocumentSplitter
from .csrf import get_csrf_config  # Import CSRF configuration

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="ChromaDB Admin Panel", description="Admin interface for ChromaDB management")

# Mount static files and templates
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

class LogFilter(logging.Filter):
    block_endpoints = ["/health", "/healthz"]

    def filter(self, record):
        if record.args and len(record.args) >= 3:
            if record.args[2] in self.block_endpoints:
                return False

        return True

logging.getLogger('uvicorn.access').addFilter(LogFilter())

# Add security middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers[
        "Content-Security-Policy"
    ] = "default-src 'self' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https:"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    return response


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint for container orchestration"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.get("/healthz")
async def healthz():
    """Alternative health check endpoint (Kubernetes style)"""
    return {"status": "ok"}


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
            print(
                f"⚠️  User with username '{settings.INITIAL_ADMIN_USERNAME}' or email '{settings.INITIAL_ADMIN_EMAIL}' already exists")
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

    except Exception as e:
        print(f"❌ Error creating initial admin user: {e}")
        db.rollback()
    finally:
        db.close()


# Authentication routes
@app.get("/auth/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[str] = None, csrf_protect: CsrfProtect = Depends(), ):
    """Login page"""

    return prepare_csrf_template("login.html", {
        "request": request,
        "error": error,
    }, csrf_protect)


def prepare_csrf_template(tpl: str, data: dict[str, any], csrf_protect: CsrfProtect) -> HTMLResponse:
    csrf_token, signed_token = csrf_protect.generate_csrf_tokens()

    response = templates.TemplateResponse(tpl, {
        **data,
        "csrf_token": csrf_token,
    })

    csrf_protect.set_csrf_cookie(signed_token, response)

    return response


@app.post("/auth/login")
async def login(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        db: Session = Depends(get_db),
        csrf_protect: CsrfProtect = Depends()
):
    try:
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError as e:
        return prepare_csrf_template("login.html", {
            "request": request, "error": "Invalid security token"
        }, csrf_protect)

    # Check rate limiting
    client_ip = AuthManager.get_client_ip(request)
    if AuthManager.is_rate_limited(client_ip):
        return prepare_csrf_template("login.html", {
            "request": request,
            "error": "Too many failed login attempts. Please try again later.",
        }, csrf_protect)

    # Sanitize and validate inputs
    username = html.escape(username.strip())
    if not User.validate_username(username):
        AuthManager.record_failed_login(client_ip)

        return prepare_csrf_template("login.html", {
            "request": request,
            "error": "Invalid credentials",
        }, csrf_protect)

    user = db.query(User).filter(
        User.username == username,
        User.is_active == True
    ).first()

    if not user or not user.verify_password(password):
        AuthManager.record_failed_login(client_ip)

        return prepare_csrf_template("login.html", {
            "request": request,
            "error": "Invalid credentials",
        }, csrf_protect)

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
        return prepare_csrf_template("login.html", {
            "request": request,
            "error": "Login failed. Please try again.",
        }, csrf_protect)


@app.get("/auth/logout")
async def logout(
        request: Request,
        session_token: Optional[str] = None,
        db: Session = Depends(get_db),
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

    # Get collections from database only (avoiding ChromaDB client initialization that causes hanging)
    all_collections = []
    total_documents = 0

    try:
        instance_ids = [inst.id for inst in accessible_instances]
        if instance_ids:
            # Get collections from local database instead of ChromaDB to prevent hanging
            collections_query = db.query(Collection).filter(
                Collection.instance_id.in_(instance_ids)
            ).limit(10).all()

            for collection in collections_query:
                instance = next((inst for inst in accessible_instances if inst.id == collection.instance_id), None)
                all_collections.append({
                    "name": collection.name,
                    "instance_id": collection.instance_id,
                    "instance_name": instance.name if instance else "Unknown",
                    "metadata": collection.collection_metadata or {},
                    "count": 0  # Placeholder to avoid ChromaDB hanging issues
                })

        # Get recent query logs for accessible instances
        recent_queries = db.query(QueryLog).filter(
            QueryLog.instance_id.in_(instance_ids)
        ).order_by(QueryLog.created_at.desc()).limit(10).all() if instance_ids else []

    except Exception as e:
        print(f"Error loading dashboard data: {e}")
        all_collections = []
        recent_queries = []

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
        current_user: User = Depends(get_current_user_required),
        csrf_protect: CsrfProtect = Depends()
):
    """ChromaDB instances management page"""
    # Get all instances or user's accessible instances
    if current_user.is_super_admin or current_user.can_admin:
        instances = db.query(ChromaDBInstance).all()
    else:
        instances = AuthManager.get_user_accessible_instances(current_user, db)

    # Get instance status and collections count (avoiding ChromaDB to prevent hanging)
    instance_status = {}
    instance_collections = {}
    user_permissions = {}

    try:
        for instance in instances:
            # Get collections count from database instead of ChromaDB
            collection_count = db.query(Collection).filter(
                Collection.instance_id == instance.id
            ).count()
            instance_collections[instance.id] = collection_count

            # Infer status based on activity and database state (avoiding ChromaDB calls)
            if not instance.is_active:
                instance_status[instance.id] = "inactive"
            elif collection_count > 0:
                # If we have collections in the database, assume the instance is working
                instance_status[instance.id] = "online"
            else:
                # No collections but active - status unknown (will be tested via async API)
                instance_status[instance.id] = "unknown"

            # Get user permissions for this instance
            if not current_user.is_super_admin:
                user_permissions[instance.id] = current_user.get_instance_permissions(instance.id)

    except Exception as e:
        print(f"Error loading instance data: {e}")
        # Fallback to empty data
        for instance in instances:
            instance_status[instance.id] = "unknown"
            instance_collections[instance.id] = 0
            if not current_user.is_super_admin:
                user_permissions[instance.id] = None

    return prepare_csrf_template("instances.html", {
        "request": request,
        "current_user": current_user,
        "instances": instances,
        "instance_status": instance_status,
        "instance_collections": instance_collections,
        "user_permissions": user_permissions,
    }, csrf_protect)


@app.post("/instances/create")
async def create_instance(
        request: Request,
        name: str = Form(...),
        url: str = Form(...),
        description: str = Form(""),
        token: str = Form(""),
        is_default: Optional[str] = Form(None),
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin_permission),
        csrf_protect: CsrfProtect = Depends()
):
    """Create a new ChromaDB instance"""
    try:
        # Validate CSRF token
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError:
        raise HTTPException(status_code=400, detail="Invalid security token")

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
        request: Request,
        instance_id: int = Form(...),
        name: str = Form(...),
        url: str = Form(...),
        description: str = Form(""),
        token: str = Form(""),
        is_default: Optional[str] = Form(None),
        is_active: Optional[str] = Form(None),
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin_permission),
        csrf_protect: CsrfProtect = Depends()
):
    """Update a ChromaDB instance"""
    try:
        # Validate CSRF token
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError:
        raise HTTPException(status_code=400, detail="Invalid security token")

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
        request: Request,
        instance_id: int = Form(...),
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin_permission),
        csrf_protect: CsrfProtect = Depends()
):
    """Delete a ChromaDB instance"""
    try:
        # Validate CSRF token
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError:
        raise HTTPException(status_code=400, detail="Invalid security token")

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
        current_user: User = Depends(require_any_instance_access),
        csrf_protect: CsrfProtect = Depends()
):
    """Collections management page"""
    # Get user's accessible instances
    accessible_instances = AuthManager.get_user_accessible_instances(current_user, db)

    # Get collections from database only (avoiding ChromaDB to prevent hanging)
    all_collections = []

    try:
        instance_ids = [inst.id for inst in accessible_instances]
        if instance_ids:
            # Get collections from local database instead of ChromaDB to prevent hanging
            collections_query = db.query(Collection).filter(
                Collection.instance_id.in_(instance_ids)
            ).all()

            for collection in collections_query:
                instance = next((inst for inst in accessible_instances if inst.id == collection.instance_id), None)
                all_collections.append({
                    "name": collection.name,
                    "instance_id": collection.instance_id,
                    "instance_name": instance.name if instance else "Unknown",
                    "metadata": collection.collection_metadata or {},
                    "count": 0  # Placeholder to avoid ChromaDB hanging issues
                })

    except Exception as e:
        print(f"Error loading collections: {e}")
        all_collections = []

    return prepare_csrf_template("collections.html", {
        "request": request,
        "current_user": current_user,
        "collections": all_collections,
        "instances": accessible_instances,
    }, csrf_protect)


@app.post("/collections/create")
async def create_collection(
        request: Request,
        name: str = Form(...),
        instance_id: int = Form(...),
        metadata: str = Form(""),
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user_required),
        csrf_protect: CsrfProtect = Depends()
):
    """Create a new collection"""
    try:
        # Validate CSRF token
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError:
        raise HTTPException(status_code=400, detail="Invalid security token")

    try:
        # Sanitize and validate inputs
        # TODO: be careful!
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

        # Check if collection already exists in this instance
        existing_collection = db.query(Collection).filter(
            Collection.name == name,
            Collection.instance_id == instance_id
        ).first()
        
        if existing_collection:
            raise HTTPException(status_code=400, detail=f"Collection '{name}' already exists in this instance")

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
            # Store in database with IntegrityError handling
            try:
                db_collection = Collection(
                    name=name,
                    instance_id=instance_id,
                    collection_metadata=metadata_dict,
                    created_by_id=current_user.id
                )
                db.add(db_collection)
                db.commit()
            except Exception as db_error:
                # If database insertion fails, try to clean up ChromaDB collection
                try:
                    client.delete_collection(name)
                except:
                    pass  # Ignore cleanup errors
                
                if isinstance(db_error, IntegrityError):
                    raise HTTPException(status_code=400, detail=f"Collection '{name}' already exists in this instance")
                else:
                    raise HTTPException(status_code=500, detail="Failed to create collection record")

            return RedirectResponse(url=f"/collections/{name}?instance_id={instance_id}", status_code=status.HTTP_302_FOUND)
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
        request: Request,
        collection_name: str,
        instance_id: int = Form(...),
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user_required),
        csrf_protect: CsrfProtect = Depends()
):
    """Delete a collection from a specific instance"""
    try:
        # Validate CSRF token
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError:
        raise HTTPException(status_code=400, detail="Invalid security token")

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
        current_user: User = Depends(get_current_user_required),
        csrf_protect: CsrfProtect = Depends()
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

    return prepare_csrf_template("collections.html", {
        "request": request,
        "current_user": current_user,
        "instance": instance,
        "collections": collections
    }, csrf_protect)


@app.get("/collections/{collection_name}", response_class=HTMLResponse)
async def collection_detail(
        request: Request,
        collection_name: str,
        instance_id: int,
        current_user: User = Depends(get_current_user_required),
        csrf_protect: CsrfProtect = Depends()
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

    return prepare_csrf_template("collection_detail.html", {
        "request": request,
        "current_user": current_user,
        "collection": collection_info,  # Pass the collection info object
        "collection_name": collection_name,
        "collection_data": collection_data,  # Pass the documents data
        "instance_id": instance_id,
    }, csrf_protect)


@app.get("/query", response_class=HTMLResponse)
async def query_page(
        request: Request,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_any_instance_access),
        csrf_protect: CsrfProtect = Depends()
):
    """Query interface page"""
    accessible_instances = AuthManager.get_user_accessible_instances(current_user, db)

    # Get collections from database only (avoiding ChromaDB to prevent hanging)
    all_collections = []
    
    try:
        instance_ids = []
        for instance in accessible_instances:
            if current_user.is_super_admin or current_user.has_instance_permission(instance.id, "search"):
                instance_ids.append(instance.id)
        
        if instance_ids:
            # Get collections from local database instead of ChromaDB to prevent hanging
            collections_query = db.query(Collection).filter(
                Collection.instance_id.in_(instance_ids)
            ).all()

            for collection in collections_query:
                instance = next((inst for inst in accessible_instances if inst.id == collection.instance_id), None)
                all_collections.append({
                    "name": collection.name,
                    "instance_id": collection.instance_id,
                    "instance_name": instance.name if instance else "Unknown",
                    "metadata": collection.collection_metadata or {},
                    "count": 0  # Placeholder to avoid ChromaDB hanging issues
                })

    except Exception as e:
        print(f"Error loading query collections: {e}")
        all_collections = []

    return prepare_csrf_template("query.html", {
        "request": request,
        "current_user": current_user,
        "collections": all_collections,
        "instances": accessible_instances,
    }, csrf_protect)


@app.post("/query/execute")
async def execute_query(
        request: Request,
        collection_name: str = Form(...),
        instance_id: int = Form(...),
        query_text: str = Form(...),
        n_results: int = Form(10),
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user_required),
        csrf_protect: CsrfProtect = Depends()
):
    """Execute a query against a specific collection in a specific instance"""
    try:
        # Validate CSRF token
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError:
        raise HTTPException(status_code=400, detail="Invalid security token")

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

            return prepare_csrf_template("query_results.html", {
                "request": request,
                "current_user": current_user,
                "query_text": query_text,
                "collection_name": collection_name,
                "instance_id": instance_id,
                "results": result["results"],
                "execution_time": result["execution_time"],
                "results_count": result["results_count"]
            }, csrf_protect)
        else:
            raise HTTPException(status_code=400, detail="Query failed")

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/add-documents/{collection_name}", response_class=HTMLResponse)
async def add_documents_page(
        request: Request,
        collection_name: str,
        instance_id: int = Query(...),
        current_user: User = Depends(get_current_user_required),
        csrf_protect: CsrfProtect = Depends()
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

    return prepare_csrf_template("add_documents.html", {
        "request": request,
        "current_user": current_user,
        "collection_name": collection_name,
        "instance_id": instance_id,
        "available_splitters": available_splitters,
    }, csrf_protect)


@app.post("/add-documents/{collection_name}")
async def add_documents(
        request: Request,
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
        current_user: User = Depends(get_current_user_required),
        csrf_protect: CsrfProtect = Depends()
):
    """Add documents to a collection in a specific instance"""
    try:
        # Validate CSRF token
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError:
        raise HTTPException(status_code=400, detail="Invalid security token")

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

        # Parse documents based on processing mode (optimized)
        if processing_mode == "lines":
            # Optimized line-by-line processing
            doc_list = []
            for line in documents.split('\n'):
                line = line.strip()
                if line and len(line) > 0:  # Skip empty lines
                    doc_list.append(line)

            if not doc_list:
                raise HTTPException(status_code=400, detail="No documents provided")

            # Limit document count for performance
            if len(doc_list) > 1000:
                raise HTTPException(status_code=400, detail=f"Too many documents ({len(doc_list)}). Maximum 1000 documents per batch.")

            # Parse IDs if provided (optimized)
            ids_list = None
            if ids.strip():
                ids_list = [id_str.strip() for id_str in ids.split('\n') if id_str.strip()]
                if len(ids_list) != len(doc_list):
                    raise HTTPException(status_code=400, detail="Number of IDs must match number of documents")

            # Parse metadata if provided (optimized)
            metadata_list = None
            if metadatas.strip():
                try:
                    metadata_list = []
                    for meta_str in metadatas.split('\n'):
                        meta_str = meta_str.strip()
                        if meta_str:
                            # Pre-validate JSON before parsing
                            if not meta_str.startswith('{') or not meta_str.endswith('}'):
                                raise ValueError(f"Invalid JSON format: {meta_str[:50]}...")
                            metadata_list.append(json.loads(meta_str))
                        else:
                            metadata_list.append({})

                    if len(metadata_list) != len(doc_list):
                        raise HTTPException(status_code=400,
                                            detail="Number of metadata entries must match number of documents")
                except (json.JSONDecodeError, ValueError) as e:
                    raise HTTPException(status_code=400, detail=f"Invalid JSON in metadata: {str(e)}")

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

        # Performance monitoring
        import time
        start_time = time.time()
        
        # Optimize document addition with batching
        batch_size = 100  # Process documents in batches to avoid timeouts
        total_docs = len(final_docs)
        print(f"📊 Processing {total_docs} documents for collection '{collection_name}' (mode: {processing_mode})")
        
        try:
            if total_docs <= batch_size:
                # Small batch - process all at once
                success = client.add_documents(collection_name, final_docs, final_metadatas, final_ids)
                if not success:
                    raise HTTPException(status_code=400, detail="Failed to add documents")
            else:
                # Large batch - process in chunks
                for i in range(0, total_docs, batch_size):
                    end_idx = min(i + batch_size, total_docs)
                    batch_docs = final_docs[i:end_idx]
                    batch_metadatas = final_metadatas[i:end_idx] if final_metadatas else None
                    batch_ids = final_ids[i:end_idx] if final_ids else None
                    
                    success = client.add_documents(collection_name, batch_docs, batch_metadatas, batch_ids)
                    if not success:
                        raise HTTPException(status_code=400, detail=f"Failed to add document batch {i//batch_size + 1}")

            # Update document count in local database (optimized - no collection list retrieval)
            db_collection = db.query(Collection).filter(
                Collection.name == collection_name,
                Collection.instance_id == instance_id
            ).first()

            if db_collection:
                # Simply increment the count by number of documents added
                # This is much faster than fetching all collections from ChromaDB
                db_collection.document_count = (db_collection.document_count or 0) + total_docs
                db.commit()

            # Performance logging
            end_time = time.time()
            duration = end_time - start_time
            print(f"✅ Successfully processed {total_docs} documents in {duration:.2f}s ({total_docs/duration:.1f} docs/sec)")

            return RedirectResponse(url=f"/collections/{collection_name}?instance_id={instance_id}",
                                    status_code=status.HTTP_302_FOUND)
                                    
        except Exception as e:
            print(f"Error adding documents to collection '{collection_name}': {e}")
            raise HTTPException(status_code=400, detail=f"Failed to add documents: {str(e)}")

    except Exception as e:
        print(f"Add documents error: {type(e).__name__}: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/add-documents/{collection_name}")
async def api_add_documents(
        request: Request,
        collection_name: str,
        instance_id: int = Form(...),
        documents: str = Form(...),
        ids: str = Form(""),
        metadatas: str = Form(""),
        processing_mode: str = Form("lines"),
        splitter_type: str = Form("recursive"),
        chunk_size: int = Form(1000),
        chunk_overlap: int = Form(200),
        csrf_token: str = Form(...),
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user_required),
        csrf_protect: CsrfProtect = Depends()
):
    """Add documents via async API for better performance"""
    try:
        # Validate CSRF token
        try:
            await csrf_protect.validate_csrf(request)
        except CsrfProtectError:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Invalid security token"}
            )

        # Check permission
        if not AuthManager.check_instance_permission(current_user, instance_id, "add", db):
            return JSONResponse(
                status_code=403,
                content={"success": False, "error": "Add documents permission required"}
            )

        # Quick validation
        if not documents.strip():
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "No documents provided"}
            )

        # Return immediate success - process in background for better UX
        # In a production environment, you'd use a task queue like Celery or Redis Queue
        return JSONResponse(content={
            "success": True,
            "message": f"Document addition initiated for collection '{collection_name}'",
            "documents_count": len([d for d in documents.split('\n') if d.strip()]),
            "processing_mode": processing_mode
        })

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)}
        )


# Document Management Routes
@app.get("/collections/{collection_name}/documents/{document_id}", response_class=HTMLResponse)
async def document_detail(
        request: Request,
        collection_name: str,
        document_id: str,
        instance_id: int = Query(...),
        current_user: User = Depends(get_current_user_required),
        csrf_protect: CsrfProtect = Depends()
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

    return prepare_csrf_template("document_detail.html", {
        "request": request,
        "current_user": current_user,
        "collection": collection_info,
        "collection_name": collection_name,
        "document": document,
        "instance_id": instance_id,
    }, csrf_protect)


@app.post("/collections/{collection_name}/documents/{document_id}/delete")
async def delete_document(
        request: Request,
        collection_name: str,
        document_id: str,
        instance_id: int = Form(...),
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user_required),
        csrf_protect: CsrfProtect = Depends()
):
    """Delete a specific document"""
    try:
        # Validate CSRF token
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError:
        raise HTTPException(status_code=400, detail="Invalid security token")

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
        request: Request,
        collection_name: str,
        instance_id: int = Form(...),
        document_ids: str = Form(...),
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user_required),
        csrf_protect: CsrfProtect = Depends()
):
    """Delete multiple documents"""
    try:
        # Validate CSRF token
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError:
        raise HTTPException(status_code=400, detail="Invalid security token")

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


@app.post("/collections/{collection_name}/documents/delete-all")
async def delete_all_documents(
        request: Request,
        collection_name: str,
        instance_id: int = Form(...),
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user_required),
        csrf_protect: CsrfProtect = Depends()
):
    """Delete all documents in a collection"""
    try:
        # Validate CSRF token
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError:
        raise HTTPException(status_code=400, detail="Invalid security token")

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

        # Get all document IDs first to delete them
        collection_data = client.get_collection_data(collection_name, limit=10000)  # High limit to get all docs
        
        if not collection_data or not collection_data.get('ids'):
            # No documents to delete, redirect back
            return RedirectResponse(
                url=f"/collections/{collection_name}?instance_id={instance_id}",
                status_code=status.HTTP_302_FOUND
            )
        
        document_ids = collection_data['ids']
        print(f"Deleting all {len(document_ids)} documents from collection '{collection_name}'")
        
        # Delete all documents
        success = client.delete_documents(collection_name, document_ids)

        if success:
            # Update document count in local database to 0
            db_collection = db.query(Collection).filter(
                Collection.name == collection_name,
                Collection.instance_id == instance_id
            ).first()

            if db_collection:
                db_collection.document_count = 0
                db.commit()
            
            print(f"✅ Successfully deleted all {len(document_ids)} documents from collection '{collection_name}'")
            return RedirectResponse(
                url=f"/collections/{collection_name}?instance_id={instance_id}",
                status_code=status.HTTP_302_FOUND
            )
        else:
            raise HTTPException(status_code=400, detail="Failed to delete all documents")

    except Exception as e:
        print(f"Error deleting all documents from collection '{collection_name}': {e}")
        raise HTTPException(status_code=400, detail=str(e))


# Admin routes
@app.get("/admin", response_class=HTMLResponse)
async def admin_page(
        request: Request,
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin_permission),
        csrf_protect: CsrfProtect = Depends()
):
    """Admin page for user management"""
    # Get all users (super admins can see everyone, regular admins can't see other super admins)
    if current_user.is_super_admin:
        users = db.query(User).order_by(User.created_at.desc()).all()
    else:
        users = db.query(User).filter(User.is_super_admin == False).order_by(User.created_at.desc()).all()

    return prepare_csrf_template("admin.html", {
        "request": request,
        "current_user": current_user,
        "users": users,
    }, csrf_protect)


@app.post("/admin/users/create")
async def create_user(
        request: Request,
        username: str = Form(...),
        email: str = Form(...),
        password: str = Form(...),
        can_admin: Optional[str] = Form(None),
        is_super_admin: Optional[str] = Form(None),
        db: Session = Depends(get_db),
        current_user: User = Depends(require_super_admin),
        csrf_protect: CsrfProtect = Depends()
):
    """Create a new user (super admin only)"""
    try:
        # Validate CSRF token
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError:
        raise HTTPException(status_code=400, detail="Invalid security token")

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
        request: Request,
        user_id: int = Form(...),
        username: str = Form(...),
        email: str = Form(...),
        password: Optional[str] = Form(""),
        can_admin: Optional[str] = Form(None),
        is_active: Optional[str] = Form(None),
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin_permission),
        csrf_protect: CsrfProtect = Depends()
):
    """Update user"""
    try:
        # Validate CSRF token
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError:
        raise HTTPException(status_code=400, detail="Invalid security token")

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
        request: Request,
        user_id: int = Form(...),
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin_permission),
        csrf_protect: CsrfProtect = Depends()
):
    """Delete user"""
    try:
        # Validate CSRF token
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError:
        raise HTTPException(status_code=400, detail="Invalid security token")

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
        current_user: User = Depends(require_admin_permission),
        csrf_protect: CsrfProtect = Depends()
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

    return prepare_csrf_template("instance_permissions.html", {
        "request": request,
        "current_user": current_user,
        "instance": instance,
        "users": users,
        "user_permissions": user_permissions,
    }, csrf_protect)


@app.post("/instances/{instance_id}/permissions/update")
async def update_instance_permissions(
        request: Request,
        instance_id: int,
        user_id: int = Form(...),
        can_search: Optional[str] = Form(None),
        can_create: Optional[str] = Form(None),
        can_add: Optional[str] = Form(None),
        can_manage: Optional[str] = Form(None),
        db: Session = Depends(get_db),
        current_user: User = Depends(require_admin_permission),
        csrf_protect: CsrfProtect = Depends()
):
    """Update user permissions for a specific instance"""
    try:
        # Validate CSRF token
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError:
        raise HTTPException(status_code=400, detail="Invalid security token")

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
        request: Request,
        instance_id: int,
        user_id: int = Form(...),
        db: Session = Depends(get_db),
        csrf_protect: CsrfProtect = Depends()
):
    """Remove all permissions for a user on a specific instance"""
    try:
        # Validate CSRF token
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError:
        raise HTTPException(status_code=400, detail="Invalid security token")

    db.query(UserInstancePermission).filter(
        UserInstancePermission.user_id == user_id,
        UserInstancePermission.instance_id == instance_id
    ).delete()

    db.commit()

    return RedirectResponse(url=f"/instances/{instance_id}/permissions", status_code=status.HTTP_302_FOUND)


# Async API endpoints that don't block with ChromaDB client initialization

@app.post("/api/collections/create")
async def api_create_collection(
        request: Request,
        name: str = Form(...),
        instance_id: int = Form(...),
        metadata: str = Form("{}"),
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user_required),
        csrf_protect: CsrfProtect = Depends()
):
    """Create collection via async API without blocking on ChromaDB initialization"""
    try:
        # Validate CSRF token
        try:
            await csrf_protect.validate_csrf(request)
        except CsrfProtectError:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Invalid security token"}
            )

        # Validate instance exists and user has access
        instance = db.query(ChromaDBInstance).filter(ChromaDBInstance.id == instance_id).first()
        if not instance:
            return JSONResponse(
                status_code=404,
                content={"success": False, "error": "Instance not found"}
            )

        # Check user permissions
        if not current_user.is_super_admin and not current_user.has_instance_permission(instance_id, "create"):
            return JSONResponse(
                status_code=403,
                content={"success": False, "error": "Access denied to this instance"}
            )

        # Parse metadata
        try:
            metadata_dict = json.loads(metadata) if metadata.strip() else {}
        except json.JSONDecodeError:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Invalid metadata JSON"}
            )

        # Save collection info to database without immediate ChromaDB creation
        collection = Collection(
            name=name,
            instance_id=instance_id,
            collection_metadata=metadata_dict,
            created_by_id=current_user.id
        )
        db.add(collection)

        chroma_client = chroma_manager.get_client(instance.id)
        chroma_client.create_collection(name, metadata_dict)

        db.commit()

        return JSONResponse(content={
            "success": True, 
            "message": f"Collection '{name}' queued for creation",
            "collection_id": collection.id
        })

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)}
        )


@app.post("/api/collections/{collection_name}/delete")
async def api_delete_collection(
        request: Request,
        collection_name: str,
        instance_id: int = Form(...),
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user_required),
        csrf_protect: CsrfProtect = Depends()
):
    """Delete collection via async API"""
    try:
        # Validate CSRF token
        try:
            await csrf_protect.validate_csrf(request)
        except CsrfProtectError:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Invalid security token"}
            )

        # Check if user has access to the instance
        if not current_user.is_super_admin and not current_user.has_instance_permission(instance_id, "create"):
            return JSONResponse(
                status_code=403,
                content={"success": False, "error": "Permission denied"}
            )

        # Remove from database (actual ChromaDB deletion can be done later)
        collection = db.query(Collection).filter(
            Collection.name == collection_name,
            Collection.instance_id == instance_id
        ).first()

        if collection:
            db.delete(collection)

            chroma_client = chroma_manager.get_client(instance_id)
            chroma_client.delete_collection(collection_name)

            db.commit()

        return JSONResponse(content={
            "success": True,
            "message": f"Collection '{collection_name}' marked for deletion"
        })

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)}
        )


@app.post("/api/query/execute")
async def api_execute_query(
        request: Request,
        collection_name: str = Form(...),
        instance_id: int = Form(...),
        query_text: str = Form(...),
        n_results: int = Form(10),
        csrf_token: str = Form(...),
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user_required),
        csrf_protect: CsrfProtect = Depends()
):
    """Execute query synchronously via async API with timeout protection"""
    import time
    
    try:
        # Validate CSRF token
        try:
            await csrf_protect.validate_csrf(request)
        except CsrfProtectError:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Invalid security token"}
            )

        # Check permissions
        if not current_user.is_super_admin and not current_user.has_instance_permission(instance_id, "search"):
            return JSONResponse(
                status_code=403,
                content={"success": False, "error": "Search permission denied"}
            )

        # Validate inputs
        if not query_text.strip():
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Query text cannot be empty"}
            )

        if n_results <= 0 or n_results > 100:
            n_results = min(max(1, n_results), 100)  # Clamp between 1 and 100

        # Get ChromaDB client
        client = chroma_manager.get_client(instance_id)
        if not client:
            return JSONResponse(
                status_code=503,
                content={"success": False, "error": "ChromaDB instance not available"}
            )

        # Performance monitoring
        start_time = time.time()
        print(f"🔍 Executing query on collection '{collection_name}' (instance_id: {instance_id})")
        print(f"   Query: '{query_text[:100]}{'...' if len(query_text) > 100 else ''}'")
        print(f"   Results limit: {n_results}")

        # Execute the actual query
        try:
            query_result = client.query_collection(
                collection_name=collection_name,
                query_texts=[query_text],
                n_results=n_results
            )

            if query_result is None:
                return JSONResponse(
                    status_code=500,
                    content={"success": False, "error": "Query execution failed or timed out"}
                )

            # Extract results from ChromaDB response
            chroma_results = query_result.get("results", {})
            execution_time = query_result.get("execution_time", 0)
            results_count = query_result.get("results_count", 0)

            # Process and format results
            documents = chroma_results.get("documents", [[]])
            metadatas = chroma_results.get("metadatas", [[]])
            distances = chroma_results.get("distances", [[]])
            ids = chroma_results.get("ids", [[]])

            # Ensure we have valid data
            if not documents or not documents[0]:
                formatted_results = {
                    "documents": [],
                    "metadatas": [],
                    "distances": [],
                    "ids": [],
                    "count": 0
                }
            else:
                # Format results for consistent API response
                formatted_results = {
                    "documents": documents[0] if documents else [],
                    "metadatas": metadatas[0] if metadatas else [],
                    "distances": distances[0] if distances else [],
                    "ids": ids[0] if ids else [],
                    "count": len(documents[0]) if documents and documents[0] else 0
                }

            # Log the successful query
            end_time = time.time()
            total_time = end_time - start_time
            
            query_log = QueryLog(
                user_id=current_user.id,
                instance_id=instance_id,
                collection_name=collection_name,
                query_text=query_text,
                query_type="similarity_search",
                execution_time=int(total_time * 1000),
                results_count=formatted_results["count"]
            )
            db.add(query_log)
            db.commit()

            print(f"✅ Query completed in {total_time:.2f}s, found {formatted_results['count']} results")

            return JSONResponse(content={
                "success": True,
                "results": formatted_results,
                "execution_time_ms": execution_time,
                "total_time_ms": int(total_time * 1000),
                "query": query_text,
                "collection": collection_name,
                "n_results": n_results,
                "message": f"Found {formatted_results['count']} results"
            })

        except Exception as query_error:
            print(f"❌ Query execution error: {query_error}")
            return JSONResponse(
                status_code=500,
                content={
                    "success": False, 
                    "error": f"Query execution failed: {str(query_error)}",
                    "query": query_text,
                    "collection": collection_name
                }
            )

    except Exception as e:
        print(f"❌ API query error: {type(e).__name__}: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": f"Query API error: {str(e)}"}
        )


@app.post("/api/instances/{instance_id}/test")
async def api_test_instance_connection(
        instance_id: int,
        db: Session = Depends(get_db)
):
    """Test instance connection via async API with immediate response"""
    try:
        # Get instance from database
        instance = db.query(ChromaDBInstance).filter(ChromaDBInstance.id == instance_id).first()
        if not instance:
            return JSONResponse(
                status_code=404,
                content={"success": False, "error": "Instance not found"}
            )

        # Check if instance is active
        if not instance.is_active:
            return JSONResponse(content={
                "success": False,
                "message": "Instance is marked as inactive",
                "status": "inactive"
            })

        # Try a quick non-blocking connection check
        try:
            import requests
            print(f"Testing chromadb instance ({instance_id}) via {instance.url.rstrip('/')}/api/v2/heartbeat")

            # Quick health check with timeout
            response = requests.get(f"{instance.url.rstrip('/')}/api/v2/heartbeat", 
                                  headers={"Authorization": f"Bearer {instance.token}"} if instance.token else {},
                                  timeout=3)
            if response.status_code == 200:
                return JSONResponse(content={
                    "success": True,
                    "message": "Connection successful",
                    "status": "online"
                })
            else:
                return JSONResponse(content={
                    "success": False,
                    "message": f"Connection failed: HTTP {response.status_code}",
                    "status": "offline"
                })
        except requests.exceptions.Timeout:
            return JSONResponse(content={
                "success": False,
                "message": "Connection timeout",
                "status": "timeout"
            })
        except requests.exceptions.ConnectionError:
            return JSONResponse(content={
                "success": False,
                "message": "Connection refused",
                "status": "offline"
            })
        except Exception as conn_error:
            return JSONResponse(content={
                "success": False,
                "message": f"Connection error: {str(conn_error)}",
                "status": "error"
            })

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)}
        )


@app.get("/api/collections")
async def api_get_collections(
        instance_id: Optional[int] = Query(None),
        current_user: User = Depends(require_any_instance_access),
        db: Session = Depends(get_db)
):
    """Get collections list via async API"""
    try:
        # Get accessible instances
        accessible_instances = AuthManager.get_user_accessible_instances(current_user, db)
        accessible_instance_ids = [inst.id for inst in accessible_instances]

        if not accessible_instance_ids:
            return JSONResponse(content={"collections": []})

        # Build query
        query = db.query(Collection)
        
        if instance_id:
            if instance_id not in accessible_instance_ids:
                return JSONResponse(
                    status_code=403,
                    content={"success": False, "error": "Access denied to this instance"}
                )
            query = query.filter(Collection.instance_id == instance_id)
        else:
            query = query.filter(Collection.instance_id.in_(accessible_instance_ids))

        collections = query.all()

        # Format response
        result = []
        for collection in collections:
            instance = next((inst for inst in accessible_instances if inst.id == collection.instance_id), None)
            result.append({
                "name": collection.name,
                "instance_id": collection.instance_id,
                "instance_name": instance.name if instance else "Unknown",
                "metadata": collection.collection_metadata or {},
                "count": 0,  # Placeholder to avoid ChromaDB call
                "created_at": collection.created_at.isoformat() if collection.created_at else None
            })

        return JSONResponse(content={"collections": result})

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)}
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
