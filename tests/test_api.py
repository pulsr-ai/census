import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import app
from app.core.database import get_db
from app.core.models import Base
from app.core import models

# Create test database - use the same PostgreSQL database as the main app
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost:5432/census_test")
engine = create_engine(SQLALCHEMY_DATABASE_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def test_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        # Clean up all tables after each test
        for table in reversed(Base.metadata.sorted_tables):
            db.execute(table.delete())
        db.commit()
        db.close()

def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["message"] == "Welcome to Census User Management API"

def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_login_creates_otp_session(client, test_db):
    response = client.post("/api/v1/auth/login", json={"email": "test@example.com"})
    assert response.status_code == 200
    data = response.json()
    assert "OTP sent" in data["message"]
    assert "session_id" in data

def test_login_without_anonymous_group(client, test_db):
    # User without anonymous group domain - should create user and send OTP
    response = client.post("/api/v1/auth/login", json={"email": "test@example.com"})
    assert response.status_code == 200
    data = response.json()
    assert "OTP sent" in data["message"]
    assert "session_id" in data

def test_login_with_new_user_gets_otp(client, test_db):
    # New users now always get OTP (no more anonymous bypass)
    response = client.post("/api/v1/auth/login", json={"email": "user@example.com"})
    assert response.status_code == 200
    data = response.json()
    assert "session_id" in data
    assert data["message"] == "OTP sent to your email"
    assert data["access_token"] is None  # No immediate access

def get_auth_headers(client, test_db):
    # Since everyone now needs OTP, we'll create a mock token for testing
    from app.core import auth
    from datetime import timedelta
    import uuid
    
    # Create a mock token for testing
    access_token = auth.create_access_token(
        data={"sub": str(uuid.uuid4()), "email": "admin@example.com"},
        expires_delta=timedelta(minutes=30)
    )
    return {"Authorization": f"Bearer {access_token}"}

def test_create_user(client, test_db):
    headers = get_auth_headers(client, test_db)
    
    response = client.post("/api/v1/users/", json={
        "email": "newuser@example.com",
        "is_active": True,
        "is_anonymous": False
    }, headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "newuser@example.com"
    assert data["is_active"] is True
    assert data["is_anonymous"] is False

def test_create_duplicate_user(client, test_db):
    headers = get_auth_headers(client, test_db)
    
    # Create first user
    client.post("/api/v1/users/", json={"email": "duplicate@example.com"}, headers=headers)
    
    # Try to create duplicate
    response = client.post("/api/v1/users/", json={
        "email": "Duplicate@example.com"  # Different case should still be caught
    }, headers=headers)
    
    assert response.status_code == 400
    assert "Email already registered" in response.json()["detail"]

def test_get_current_user(client, test_db):
    headers = get_auth_headers(client, test_db)
    
    response = client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "admin@example.com"
    assert data["is_anonymous"] is True

def test_list_users(client, test_db):
    headers = get_auth_headers(client, test_db)
    
    response = client.get("/api/v1/users/", headers=headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_create_group(client, test_db):
    headers = get_auth_headers(client, test_db)
    
    response = client.post("/api/v1/groups/", json={
        "name": "New Group",
        "description": "A test group",
        "email_domain": "newgroup.com",
        "allow_anonymous": False
    }, headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "New Group"
    assert data["email_domain"] == "newgroup.com"
    assert data["allow_anonymous"] is False

def test_create_field(client, test_db):
    headers = get_auth_headers(client, test_db)
    
    response = client.post("/api/v1/fields/", json={
        "name": "Department",
        "field_type": "text",
        "description": "Employee department",
        "is_required": False,
        "default_value": "General"
    }, headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Department"
    assert data["field_type"] == "text"
    assert data["is_required"] is False

def test_create_permission(client, test_db):
    headers = get_auth_headers(client, test_db)
    
    response = client.post("/api/v1/permissions/", json={
        "name": "users:read",
        "description": "Read user information",
        "resource": "users",
        "action": "read"
    }, headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "users:read"
    assert data["resource"] == "users"
    assert data["action"] == "read"

def test_otp_verification_invalid_session(client, test_db):
    # Test OTP verification with invalid session (valid UUID format but non-existent)
    fake_uuid = "550e8400-e29b-41d4-a716-446655440000"
    response = client.post("/api/v1/auth/verify-otp", json={
        "session_id": fake_uuid,
        "otp_code": "123456"
    })
    assert response.status_code == 400
    assert "Invalid or expired OTP" in response.json()["detail"]

def test_create_duplicate_group(client, test_db):
    headers = get_auth_headers(client, test_db)
    
    # Create first group
    client.post("/api/v1/groups/", json={"name": "Duplicate Group"}, headers=headers)
    
    # Try to create duplicate
    response = client.post("/api/v1/groups/", json={"name": "Duplicate Group"}, headers=headers)
    
    assert response.status_code == 400
    assert "Group name already exists" in response.json()["detail"]

def test_list_groups(client, test_db):
    headers = get_auth_headers(client, test_db)
    
    response = client.get("/api/v1/groups/", headers=headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    # Should have at least the test group we created for auth
    assert len(response.json()) >= 1

def test_list_fields(client, test_db):
    headers = get_auth_headers(client, test_db)
    
    response = client.get("/api/v1/fields/", headers=headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_list_permissions(client, test_db):
    headers = get_auth_headers(client, test_db)
    
    response = client.get("/api/v1/permissions/", headers=headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_unauthorized_access_users(client, test_db):
    response = client.get("/api/v1/users/")
    assert response.status_code in [401, 403]

def test_unauthorized_access_groups(client, test_db):
    response = client.get("/api/v1/groups/")
    assert response.status_code in [401, 403]

def test_unauthorized_access_fields(client, test_db):
    response = client.get("/api/v1/fields/")
    assert response.status_code in [401, 403]

def test_unauthorized_access_permissions(client, test_db):
    response = client.get("/api/v1/permissions/")
    assert response.status_code in [401, 403]

def test_update_or_create_field_by_name_create(client, test_db):
    headers = get_auth_headers(client, test_db)
    
    # Test creating a new field by name
    response = client.put("/api/v1/fields/by-name/NewField", json={
        "field_type": "number",
        "description": "A dynamically created field",
        "is_required": True,
        "default_value": "0"
    }, headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "NewField"
    assert data["field_type"] == "number"
    assert data["description"] == "A dynamically created field"
    assert data["is_required"] is True
    assert data["default_value"] == "0"

def test_update_or_create_field_by_name_update(client, test_db):
    headers = get_auth_headers(client, test_db)
    
    # First create a field
    client.post("/api/v1/fields/", json={
        "name": "ExistingField",
        "field_type": "text",
        "description": "Original description"
    }, headers=headers)
    
    # Then update it by name
    response = client.put("/api/v1/fields/by-name/ExistingField", json={
        "description": "Updated description",
        "is_required": True
    }, headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "ExistingField"
    assert data["field_type"] == "text"  # Should remain unchanged
    assert data["description"] == "Updated description"
    assert data["is_required"] is True

def test_update_or_create_field_by_name_defaults(client, test_db):
    headers = get_auth_headers(client, test_db)
    
    # Test creating a field with minimal data (should use defaults)
    response = client.put("/api/v1/fields/by-name/MinimalField", json={
        "description": "Just a description"
    }, headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "MinimalField"
    assert data["field_type"] == "text"  # Default type
    assert data["description"] == "Just a description"
    assert data["is_required"] is False  # Default value

def test_domain_group_auto_creation(client, test_db):
    """Test that signing up creates a domain group automatically"""
    # Test user login with a new domain
    response = client.post("/api/v1/auth/login", json={"email": "newuser@newcompany.com"})
    assert response.status_code == 200
    
    # Check that domain group was created
    domain_group = test_db.query(models.Group).filter(
        models.Group.email_domain == "newcompany.com"
    ).first()
    
    assert domain_group is not None
    assert domain_group.name == "newcompany.com"
    assert domain_group.description == "Auto-created group for newcompany.com domain"
    assert domain_group.email_domain == "newcompany.com"
    
    # Check that user was added to the domain group
    user = test_db.query(models.User).filter(
        models.User.email == "newuser@newcompany.com"
    ).first()
    
    assert user is not None
    group_names = [group.name for group in user.groups]
    assert "newcompany.com" in group_names

def test_domain_group_reuse_existing(client, test_db):
    """Test that existing domain groups are reused"""
    # Create a user with a domain
    response1 = client.post("/api/v1/auth/login", json={"email": "user1@testdomain.com"})
    assert response1.status_code == 200
    
    # Create another user with the same domain
    response2 = client.post("/api/v1/auth/login", json={"email": "user2@testdomain.com"})
    assert response2.status_code == 200
    
    # Check that only one domain group exists
    domain_groups = test_db.query(models.Group).filter(
        models.Group.email_domain == "testdomain.com"
    ).all()
    
    assert len(domain_groups) == 1
    domain_group = domain_groups[0]
    
    # Check that both users are in the same domain group
    user1 = test_db.query(models.User).filter(
        models.User.email == "user1@testdomain.com"
    ).first()
    user2 = test_db.query(models.User).filter(
        models.User.email == "user2@testdomain.com"
    ).first()
    
    assert domain_group in user1.groups
    assert domain_group in user2.groups

def test_domain_group_security_setting(client, test_db):
    """Test that domain groups are created with proper security settings"""
    # All domain groups should now have allow_anonymous=False (no security bypass)
    response = client.post("/api/v1/auth/login", json={"email": "regularuser@regularcompany.com"})
    assert response.status_code == 200  # Should get OTP
    
    # Check that domain group was created with allow_anonymous=False
    domain_group = test_db.query(models.Group).filter(
        models.Group.email_domain == "regularcompany.com"
    ).first()
    
    assert domain_group is not None
    assert domain_group.allow_anonymous is False  # All domain groups are secure now

if __name__ == "__main__":
    pytest.main([__file__, "-v"])