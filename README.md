# Census - User Management & OTP Authentication Service

A comprehensive FastAPI-based microservice for user management, authentication, and authorization with PostgreSQL backend.

## 🚀 Features

- **🔐 Multi-mode Authentication**
  - Email-based OTP authentication
  - Domain-based anonymous access
  - JWT token-based session management

- **👥 User Management**
  - UUID-based user identification
  - Normalized email storage
  - Custom user fields system
  - Group membership management

- **🏢 Group Management**
  - Domain-based group assignment
  - Anonymous access control per domain
  - Hierarchical permission system

- **⚙️ Custom Fields System**
  - Dynamic field creation and management
  - Field-by-name updates (create-or-update)
  - Flexible field types and validation

- **🔑 Granular Permissions**
  - Resource-action based permissions
  - User-level and group-level permissions
  - Permission inheritance from groups

## ⚡ Quick Start

```bash
# Install dependencies
poetry install

# Start development server
poetry run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Run tests
poetry run pytest tests/ -v
```

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [API Endpoints](#api-endpoints)
- [Authentication Flow](#authentication-flow)
- [Microservice Integration](#microservice-integration)
- [Testing](#testing)
- [Development](#development)

## 🛠 Installation

### Prerequisites
- Python 3.11+
- PostgreSQL 12+
- Poetry

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd census
   ```

2. **Install dependencies**
   ```bash
   poetry install
   ```

3. **Environment setup**
   ```bash
   cp .env.example .env
   # Edit .env with your database credentials
   ```

4. **Database migration**
   ```bash
   alembic upgrade head
   ```

5. **Run the service**
   ```bash
   poetry run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   # Server runs on http://localhost:8000
   ```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `SECRET_KEY` | JWT signing secret | Required |
| `ALGORITHM` | JWT algorithm | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token expiry time | `30` |
| `OTP_EXPIRE_MINUTES` | OTP validity period | `5` |

### Example `.env`
```env
DATABASE_URL=postgresql://username:password@localhost/census_db
SECRET_KEY=your-super-secret-key-here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
OTP_EXPIRE_MINUTES=5
```

## 🔌 API Endpoints

### Authentication
- `POST /auth/login` - Request OTP for email
- `POST /auth/verify-otp` - Verify OTP and get access token
- `POST /auth/anonymous-login` - Anonymous login for allowed domains
- `POST /auth/refresh-token` - Refresh access token
- `POST /auth/logout` - Logout user

### Users
- `GET /users/` - List all users
- `POST /users/` - Create new user
- `GET /users/me` - Get current user info
- `GET /users/{user_id}` - Get user by ID
- `PUT /users/{user_id}` - Update user
- `DELETE /users/{user_id}` - Delete user
- `POST /users/{user_id}/field-values` - Set user field values
- `GET /users/{user_id}/field-values` - Get user field values

### Groups
- `GET /groups/` - List all groups
- `POST /groups/` - Create new group
- `GET /groups/{group_id}` - Get group by ID
- `PUT /groups/{group_id}` - Update group
- `DELETE /groups/{group_id}` - Delete group
- `GET /groups/{group_id}/users` - Get group members

### Fields
- `GET /fields/` - List all fields
- `POST /fields/` - Create new field
- `GET /fields/{field_id}` - Get field by ID
- `PUT /fields/{field_id}` - Update field by ID
- `PUT /fields/by-name/{field_name}` - **Create or update field by name**
- `DELETE /fields/{field_id}` - Delete field

### Permissions
- `GET /permissions/` - List all permissions
- `POST /permissions/` - Create new permission
- `GET /permissions/{permission_id}` - Get permission by ID
- `DELETE /permissions/{permission_id}` - Delete permission
- `POST /permissions/users/{user_id}` - Grant permission to user
- `GET /permissions/users/{user_id}` - Get user permissions

## 🔐 Authentication Flow

### Regular Authentication
1. **Request OTP**: `POST /auth/login` with email
2. **Verify OTP**: `POST /auth/verify-otp` with session_id and OTP code
3. **Use Token**: Include `Authorization: Bearer <token>` in subsequent requests

### Anonymous Authentication
1. **Check Domain**: Ensure email domain allows anonymous access
2. **Anonymous Login**: `POST /auth/anonymous-login` with email
3. **Use Token**: Include `Authorization: Bearer <token>` in subsequent requests

### Example Usage
```bash
# Request OTP
curl -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# Verify OTP (use session_id from previous response)
curl -X POST "http://localhost:8000/auth/verify-otp" \
  -H "Content-Type: application/json" \
  -d '{"session_id": "uuid-here", "otp_code": "123456"}'

# Use authenticated endpoints
curl -X GET "http://localhost:8000/users/me" \
  -H "Authorization: Bearer your-jwt-token"
```

## 🔗 Microservice Integration

The Census service is designed as a central authentication and user management hub for a microservice architecture. It seamlessly integrates with other services through a **subtenant system**.

### Architecture Overview

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Lingua    │    │   Lambda    │    │   Other     │
│ (LLM Chat)  │    │(Automation) │    │  Services   │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                    ┌─────────────┐
                    │   Census    │
                    │(User Auth)  │
                    └─────────────┘
```

### Subtenant System

Each user in Census can have **subtenants** - service-specific identifiers that link their Census identity to accounts in other microservices.

#### How Subtenants Work

1. **User Identification**: Every user has a primary UUID in Census
2. **Service Linking**: Each service (lingua, lambda, etc.) gets its own subtenant UUID per user
3. **Lazy Creation**: Subtenants are created on-demand when first accessing a service
4. **Field Storage**: Subtenants are stored as custom fields: `subtenant:lingua`, `subtenant:lambda`

#### Implementation Pattern

##### 1. Check for Existing Subtenant
```bash
# Check if user has subtenant for 'lingua' service
GET /users/{user_id}/field-values
# Look for field with name "subtenant:lingua"
```

##### 2. Create Subtenant if Missing
```bash
# Create subtenant field for lingua service
PUT /fields/by-name/subtenant:lingua
{
  "field_type": "text",
  "description": "Lingua service subtenant UUID",
  "is_required": false
}

# Set subtenant value for user
POST /users/{user_id}/field-values
{
  "field_id": "field-uuid-here",
  "value": "new-subtenant-uuid-for-lingua"
}
```

##### 3. Update Service with Subtenant
```bash
# In the lingua service API
POST /lingua/users
{
  "subtenant_id": "new-subtenant-uuid-for-lingua",
  "census_user_id": "original-user-uuid"
}
```

### Integration Example: Lingua Service

```python
# In your lingua service
async def ensure_user_subtenant(census_user_id: str) -> str:
    # Check if subtenant exists in census
    field_values = await census_client.get_user_field_values(census_user_id)
    lingua_subtenant = None
    
    for field_value in field_values:
        if field_value.field.name == "subtenant:lingua":
            lingua_subtenant = field_value.value
            break
    
    if not lingua_subtenant:
        # Create new subtenant
        lingua_subtenant = str(uuid.uuid4())
        
        # Ensure field exists in census
        await census_client.upsert_field_by_name(
            "subtenant:lingua",
            {
                "field_type": "text",
                "description": "Lingua service subtenant UUID"
            }
        )
        
        # Set field value for user
        await census_client.set_user_field_value(
            census_user_id,
            "subtenant:lingua",
            lingua_subtenant
        )
        
        # Create user in lingua service
        await create_lingua_user(lingua_subtenant, census_user_id)
    
    return lingua_subtenant
```

### Service Registration Pattern

Each microservice should register its subtenant field on startup:

```bash
# Register subtenant field for your service
PUT /fields/by-name/subtenant:myservice
{
  "field_type": "text",
  "description": "MyService subtenant UUID",
  "is_required": false
}
```

### Best Practices

1. **Naming Convention**: Use `subtenant:{service_name}` for consistency
2. **UUID Format**: Always use UUID4 for subtenant identifiers
3. **Lazy Creation**: Only create subtenants when users first access the service
4. **Idempotent Operations**: Use the by-name field endpoint for safe upserts
5. **Error Handling**: Gracefully handle missing subtenants and census connectivity issues

### Authentication Flow with Services

1. User authenticates with Census → gets JWT
2. User accesses Lingua/Lambda service → service validates JWT with Census
3. Service checks for user's subtenant → creates if missing
4. Service processes request using subtenant context

This architecture ensures:
- **Single Source of Truth** for user identity (Census)
- **Service Isolation** through unique subtenants
- **Scalable Integration** as new services are added
- **Consistent User Experience** across all services

## 🧪 Testing

### Run Tests
```bash
# Run all tests
poetry run pytest tests/ -v

# Run specific test
poetry run pytest tests/test_api.py::test_create_user -v

# Run with coverage
poetry run pytest tests/ --cov=api
```

### Test Coverage
- ✅ Authentication flows (OTP + Anonymous)
- ✅ User management (CRUD operations)
- ✅ Group management and permissions
- ✅ Field management (including by-name operations)
- ✅ Authorization and access control
- ✅ Error handling and edge cases

## 🔧 Development

### Project Structure
```
census/
├── api/v1/
│   ├── __init__.py
│   ├── main.py              # FastAPI app
│   ├── models.py            # Database models
│   ├── schemas.py           # Pydantic schemas
│   ├── database.py          # Database connection
│   ├── config.py            # Configuration
│   ├── auth.py              # Authentication logic
│   ├── users.py             # User endpoints
│   ├── groups.py            # Group endpoints
│   ├── fields.py            # Field endpoints
│   ├── permissions.py       # Permission endpoints
│   └── authentication.py    # Auth endpoints
├── alembic/                 # Database migrations
├── tests/
│   └── test_api.py         # Test suite
├── pyproject.toml           # Poetry configuration
├── alembic.ini
├── main.py
└── README.md
```

### Adding New Features
1. Update models in `models.py`
2. Create/update schemas in `schemas.py`
3. Add business logic to appropriate endpoint file
4. Write tests in `tests/test_api.py`
5. Create database migration: `poetry run alembic revision --autogenerate -m "description"`
6. Run tests: `poetry run pytest`

### Database Migrations
```bash
# Create migration
poetry run alembic revision --autogenerate -m "Add new feature"

# Apply migrations
poetry run alembic upgrade head

# Rollback migration
poetry run alembic downgrade -1
```

## 📚 API Documentation

Once the service is running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
