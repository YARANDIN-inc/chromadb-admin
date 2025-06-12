![Yarandin Logo](images/logo.jpg)

# ChromaDB Admin Panel

A comprehensive web-based administration interface for ChromaDB with user management, permissions, and beautiful UI.

## Features

### Core Features
- **Full ChromaDB Management**: Create, view, delete collections
- **Document Operations**: Add, search, and manage documents
- **Semantic Search**: Query collections with natural language
- **Analytics Dashboard**: Collection statistics and activity monitoring
- **Beautiful UI**: Modern Bootstrap-based interface with responsive design

### User Management & Security
- **Role-Based Access Control**: Super admins and regular users
- **Granular Permissions**: 
  - `search`: Search documents and access dashboard
  - `create`: Create and delete collections
  - `add`: Add documents to collections
  - `admin`: Manage users and system administration
- **Session-Based Authentication**: Secure cookie-based sessions (7-day expiry)
- **User Administration**: Complete user CRUD operations
- **Permission Management**: Flexible permission assignment per user
- **Automatic Initial Setup**: Environment variable-based admin user creation
- **ChromaDB Authentication**: Optional token-based authentication support

## Technology Stack

- **Backend**: FastAPI 0.115.9 with Python 3.11
- **Database**: PostgreSQL 15 for user management and analytics
- **Vector Database**: ChromaDB 1.0.12 for document storage and search
- **Frontend**: Bootstrap 5.3.2 with Jinja2 templates
- **Authentication**: Passlib with bcrypt password hashing (fixed compatibility issues)
- **Deployment**: Docker Compose with separate services

## Quick Start

### 1. Clone and Start Services

```bash
git clone <repository-url>
cd chromadb-admin
docker compose up --build -d
```

The application will automatically create a super admin user with these default credentials:
- **Username**: `admin`
- **Email**: `admin@localhost.com`
- **Password**: `admin123`

### 2. Access the Application

- **Web Interface**: http://localhost:8080
- **ChromaDB API**: http://localhost:8001
- **Login**: Use the credentials above or your custom environment variables

### 3. Customize Admin User (Recommended)

For production deployments, customize the admin user by setting environment variables before starting:

```bash
# Set custom admin credentials
export CREATE_INITIAL_ADMIN=true
export INITIAL_ADMIN_USERNAME=myadmin
export INITIAL_ADMIN_EMAIL=admin@mycompany.com
export INITIAL_ADMIN_PASSWORD=my-secure-password

# Start with custom admin
docker compose up --build -d
```

## Environment Variables Configuration

### Core Application Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://chromadb:password@postgres:5432/chromadb_admin` | PostgreSQL connection URL |
| `CHROMADB_URL` | `http://chromadb:8000` | ChromaDB server URL |
| `CHROMADB_TOKEN` | `1234567890-change-in-production` | ChromaDB authentication token (optional) |
| `SECRET_KEY` | `change-this-in-production-...` | Session encryption key |

### Initial Admin User Setup

| Variable | Default | Description |
|----------|---------|-------------|
| `CREATE_INITIAL_ADMIN` | `true` | Create admin user on startup if no users exist |
| `INITIAL_ADMIN_USERNAME` | `admin` | Username for the initial admin user |
| `INITIAL_ADMIN_EMAIL` | `admin@localhost.com` | Email for the initial admin user |
| `INITIAL_ADMIN_PASSWORD` | `admin123` | Password for the initial admin user |

### Production Deployment

For production, create a `.env` file based on `.env.example`:

```bash
# Copy example file
cp .env.example .env

# Edit with your values
nano .env
```

Example production `.env`:

```bash
# Database Configuration
POSTGRES_USER=chromadb
POSTGRES_PASSWORD=your-super-secure-database-password

# Application Security  
SECRET_KEY=your-64-character-random-secret-key-here

# ChromaDB Configuration
CHROMADB_TOKEN=your-secure-chromadb-token

# Initial Admin User
CREATE_INITIAL_ADMIN=true
INITIAL_ADMIN_USERNAME=admin
INITIAL_ADMIN_EMAIL=admin@yourcompany.com  
INITIAL_ADMIN_PASSWORD=your-secure-admin-password

# Optional: Custom ports
WEB_PORT=8080
CHROMADB_PORT=8001
```

Then use the production compose file:

```bash
docker compose -f docker-compose.prod.yml --env-file .env up -d
```

## Recent Updates (v0.1.0)

### Fixed Issues
- **Bcrypt Compatibility**: Fixed bcrypt version compatibility issues that caused startup warnings
- **ChromaDB Authentication**: Added support for token-based authentication with ChromaDB
- **Local Development**: Improved local development setup with `.runtime` directories for data persistence

### New Features
- **Token Authentication**: Optional ChromaDB token authentication via `CHROMADB_TOKEN` environment variable
- **Better Error Handling**: Improved error messages and connection resilience
- **Development Setup**: Local data persistence with `.runtime/postgres` and `.runtime/chromadb` directories

### Technical Improvements
- **Dependencies**: Updated bcrypt to version 4.0.1 for Python 3.11 compatibility
- **ChromaDB Client**: Enhanced client with Bearer token authentication support
- **Docker Setup**: Optimized Docker configuration for both development and production

## Deployment Options

### Docker Compose (Development)

Default development setup with automatic admin creation:

```bash
docker compose up --build -d
```

### Docker Compose (Production) 

Secure production deployment with environment file:

```bash
# Create and configure .env file
cp .env.example .env
# Edit .env with your values

# Deploy with production settings
docker compose -f docker-compose.prod.yml --env-file .env up -d
```

### Kubernetes

Deploy to Kubernetes using the provided example:

```bash
# 1. Update the secret values in kubernetes-example.yaml
# Replace base64 encoded values with your own:
echo -n "your-secure-password" | base64
echo -n "your-secret-key" | base64  
echo -n "your-admin-password" | base64
echo -n "your-chromadb-token" | base64

# 2. Apply the configuration
kubectl apply -f kubernetes-example.yaml

# 3. Check deployment status
kubectl get pods -n chromadb-admin

# 4. Get external IP (if using LoadBalancer)
kubectl get service chromadb-admin-web-service -n chromadb-admin
```

### Manual Environment Variables

For other deployment methods, set these environment variables:

```bash
# Required for automatic admin creation
export CREATE_INITIAL_ADMIN=true
export INITIAL_ADMIN_USERNAME=admin
export INITIAL_ADMIN_EMAIL=admin@yourcompany.com
export INITIAL_ADMIN_PASSWORD=secure-password

# Application configuration
export DATABASE_URL=postgresql://user:pass@host:5432/chromadb_admin
export CHROMADB_URL=http://chromadb-host:8000
export CHROMADB_TOKEN=your-chromadb-token
export SECRET_KEY=your-secret-key

# Start application
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## User Roles & Permissions

### Super Admin
- Full system access
- Can manage other super admins and users
- All permissions enabled by default

### Regular Admin
- Can manage regular users (not super admins)
- Requires `admin` permission
- Can have other permissions as assigned

### Regular User
- Access based on assigned permissions:
  - **Search**: Access dashboard, search documents
  - **Create**: Create/delete collections
  - **Add**: Add documents to collections
  - **Admin**: User management (non-super admin users)

## Permission Matrix

| Action | Super Admin | Admin Permission | Create Permission | Add Permission | Search Permission |
|--------|-------------|------------------|-------------------|----------------|-------------------|
| View Dashboard | ✅ | ❌ | ❌ | ❌ | ✅ |
| Search Documents | ✅ | ❌ | ❌ | ❌ | ✅ |
| Create Collections | ✅ | ❌ | ✅ | ❌ | ❌ |
| Delete Collections | ✅ | ❌ | ✅ | ❌ | ❌ |
| Add Documents | ✅ | ❌ | ❌ | ✅ | ❌ |
| Manage Users | ✅ | ✅ | ❌ | ❌ | ❌ |
| Create Super Admin | ✅ | ❌ | ❌ | ❌ | ❌ |

## API Endpoints

### Authentication
- `GET /auth/login` - Login page
- `POST /auth/login` - Process login
- `GET /auth/logout` - Logout and clear session

### Main Application
- `GET /` - Dashboard (requires search permission)
- `GET /collections` - Collections management
- `POST /collections/create` - Create collection (requires create permission)
- `POST /collections/{name}/delete` - Delete collection (requires create permission)
- `GET /collections/{name}` - Collection details
- `GET /query` - Search interface (requires search permission)
- `POST /query/execute` - Execute search (requires search permission)
- `GET /add-documents/{name}` - Add documents form (requires add permission)
- `POST /add-documents/{name}` - Add documents (requires add permission)

### Administration
- `GET /admin` - User management (requires admin permission)
- `POST /admin/users/create` - Create user (super admin only)
- `POST /admin/users/update` - Update user (admin permission)
- `POST /admin/users/delete` - Delete user (admin permission)

## User Management

### Automatic Admin Creation

The application automatically creates an initial admin user on startup if:
1. `CREATE_INITIAL_ADMIN=true` environment variable is set
2. No users exist in the database
3. Required environment variables are provided

This happens during the application startup event, making it perfect for containerized deployments.

### Adding Additional Users

#### Via Web Interface (Recommended)
1. Login as super admin
2. Navigate to User Management
3. Click "Create User"
4. Set username, email, password, and permissions

#### Via Environment Variables (Kubernetes/Docker)
Set the initial admin environment variables before deployment:

```yaml
# In Kubernetes ConfigMap/Secret
CREATE_INITIAL_ADMIN: "true"
INITIAL_ADMIN_USERNAME: "admin"
INITIAL_ADMIN_EMAIL: "admin@company.com"
INITIAL_ADMIN_PASSWORD: "secure-password"
```

#### Via Command Line (Existing Container)
```bash
docker exec -it chromadb-admin-web-1 python3 -c "
from app.database import SessionLocal
from app.models import User

db = SessionLocal()
user = User(
    username='newuser',
    email='user@example.com',
    can_search=True,
    can_create=False,
    can_add=True,
    can_admin=False
)
user.set_password('userpassword')
db.add(user)
db.commit()
print('User created successfully!')
"
```

## Development

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL="postgresql://chromadb:password@localhost:5432/chromadb_admin"
export CHROMADB_URL="http://localhost:8001"
export CHROMADB_TOKEN="your-token-here"
export CREATE_INITIAL_ADMIN=true
export INITIAL_ADMIN_USERNAME=admin
export INITIAL_ADMIN_EMAIL=admin@localhost.com
export INITIAL_ADMIN_PASSWORD=admin123

# Run application
uvicorn app.main:app --reload --host 0.0.0.0 --port 8080
```

### Database Management

The application automatically creates all necessary tables on startup. The database schema includes:

- `users` - User accounts and permissions
- `user_sessions` - Active user sessions
- `collections` - Collection metadata and tracking
- `query_logs` - Search and operation history
- `system_metrics` - System statistics

## Security Features

- **Password Hashing**: Bcrypt with secure salting (v4.0.1 compatibility)
- **Session Management**: Secure HTTP-only cookies
- **Permission Validation**: Server-side permission checks on all endpoints
- **SQL Injection Protection**: SQLAlchemy ORM with parameterized queries
- **XSS Protection**: Template escaping and content security
- **Authentication Required**: All functional endpoints require valid authentication
- **Environment-based Configuration**: Sensitive data managed via environment variables
- **ChromaDB Token Support**: Optional Bearer token authentication for ChromaDB

## Troubleshooting

### Common Issues

1. **Cannot connect to ChromaDB**
   ```bash
   # Check ChromaDB service status
   docker compose logs chromadb
   
   # Restart services
   docker compose restart chromadb web
   ```

2. **Admin user not created**
   ```bash
   # Check environment variables
   docker compose logs web | grep "CREATE_INITIAL_ADMIN"
   
   # Verify no users exist
   docker exec -it chromadb-admin-web-1 python3 -c "
   from app.database import SessionLocal
   from app.models import User
   db = SessionLocal()
   print(f'Users in database: {db.query(User).count()}')
   "
   ```

3. **Permission denied errors**
   - Verify user has correct permissions in User Management
   - Check user's active status
   - Ensure session hasn't expired (7 days)

4. **Environment variables not working**
   ```bash
   # Check if variables are loaded
   docker exec -it chromadb-admin-web-1 env | grep INITIAL_ADMIN
   
   # Check startup logs
   docker compose logs web | grep "admin"
   ```

5. **Bcrypt errors (resolved in v0.1.0)**
   - Update to the latest version which includes bcrypt 4.0.1
   - Rebuild containers: `docker compose build --no-cache`

### Reset Admin Password

```bash
docker exec -it chromadb-admin-web-1 python3 -c "
from app.database import SessionLocal
from app.models import User

db = SessionLocal()
admin = db.query(User).filter(User.username == 'admin').first()
if admin:
    admin.set_password('newpassword')
    db.commit()
    print('Admin password updated!')
else:
    print('Admin user not found!')
"
```

### Force Create New Admin

If you need to create a new admin user in an existing deployment:

```bash
# Set environment variables and restart
export CREATE_INITIAL_ADMIN=true
export INITIAL_ADMIN_USERNAME=newadmin
export INITIAL_ADMIN_EMAIL=newadmin@company.com
export INITIAL_ADMIN_PASSWORD=newpassword

# Delete existing users first (if needed)
docker exec -it chromadb-admin-web-1 python3 -c "
from app.database import SessionLocal
from app.models import User
db = SessionLocal()
db.query(User).delete()
db.commit()
print('All users deleted!')
"

# Restart to trigger admin creation
docker compose restart web
```

## ChromaDB 1.0.12 Compatibility

This application is specifically designed for ChromaDB 1.0.12 and includes:

- **Modern API Support**: Uses the latest ChromaDB Python client
- **Token Authentication**: Bearer token support for secured ChromaDB instances
- **Improved Performance**: Enhanced connection handling and query optimization
- **Better Error Handling**: Comprehensive error management for all ChromaDB operations
- **Metadata Validation**: Proper handling of empty metadata to avoid validation errors

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

---

**Built with ❤️ by YARANDIN-inc for the ChromaDB community** 