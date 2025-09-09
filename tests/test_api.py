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
    # Create an admin user for testing
    from app.core import auth, models
    from datetime import timedelta
    
    # Create or get admin user
    admin_email = "testadmin@example.com"
    admin_user = test_db.query(models.User).filter(models.User.email == admin_email).first()
    
    if not admin_user:
        admin_user = models.User(
            email=admin_email,
            is_active=True,
            is_anonymous=False,
            otp_verified=True
        )
        test_db.add(admin_user)
        test_db.commit()
        test_db.refresh(admin_user)
        
        # Add to admin group
        admin_group = test_db.query(models.Group).filter(models.Group.name == "Admins").first()
        if admin_group:
            group_member = models.GroupMember(
                user_id=admin_user.id,
                group_id=admin_group.id,
                role="admin",
                active=True,
                added_by=admin_user.id
            )
            test_db.add(group_member)
            test_db.commit()
    
    # Create token with real user ID
    access_token = auth.create_access_token(
        data={"sub": str(admin_user.id), "email": admin_user.email},
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
    
    if response.status_code != 200:
        print(f"Error response: {response.status_code} - {response.json()}")
    
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
    assert data["email"] == "testadmin@example.com"
    assert data["is_anonymous"] is False

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

def test_list_fields(client, test_db):
    headers = get_auth_headers(client, test_db)
    
    response = client.get("/api/v1/fields/", headers=headers)
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
    
    # Check that user was added to the domain group via GroupMember
    user = test_db.query(models.User).filter(
        models.User.email == "newuser@newcompany.com"
    ).first()
    
    assert user is not None
    
    # Check active group memberships
    memberships = test_db.query(models.GroupMember).filter(
        models.GroupMember.user_id == user.id,
        models.GroupMember.active == True
    ).all()
    
    group_ids = [m.group_id for m in memberships]
    assert domain_group.id in group_ids

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
    
    # Check that both users are in the same domain group via membership
    user1 = test_db.query(models.User).filter(
        models.User.email == "user1@testdomain.com"
    ).first()
    user2 = test_db.query(models.User).filter(
        models.User.email == "user2@testdomain.com"
    ).first()
    
    # Check via GroupMember relationships
    user1_memberships = test_db.query(models.GroupMember).filter(
        models.GroupMember.user_id == user1.id,
        models.GroupMember.active == True
    ).all()
    user2_memberships = test_db.query(models.GroupMember).filter(
        models.GroupMember.user_id == user2.id,
        models.GroupMember.active == True
    ).all()
    
    user1_group_ids = [m.group_id for m in user1_memberships]
    user2_group_ids = [m.group_id for m in user2_memberships]
    
    assert domain_group.id in user1_group_ids
    assert domain_group.id in user2_group_ids

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

# ===== NEW SERVICE ACCESS CONTROL TESTS =====

def test_grant_user_service_access(client, test_db):
    """Test granting service access to a user"""
    headers = get_auth_headers(client, test_db)
    
    # Create a user first
    user_response = client.post("/api/v1/users/", json={
        "email": "serviceuser@example.com",
        "is_active": True
    }, headers=headers)
    assert user_response.status_code == 200
    user_id = user_response.json()["id"]
    
    # Grant service access
    response = client.post(f"/api/v1/users/{user_id}/service-access", json={
        "service": "analytics",
        "subtenant_id": "tenant123"
    }, headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "analytics"
    assert data["subtenant_id"] == "tenant123"
    assert data["active"] is True
    assert data["user_id"] == user_id
    assert data["granted_by"] is not None

def test_grant_duplicate_service_access_fails(client, test_db):
    """Test that granting duplicate active service access fails"""
    headers = get_auth_headers(client, test_db)
    
    # Create a user
    user_response = client.post("/api/v1/users/", json={
        "email": "duplicateuser@example.com"
    }, headers=headers)
    user_id = user_response.json()["id"]
    
    # Grant service access first time
    client.post(f"/api/v1/users/{user_id}/service-access", json={
        "service": "analytics",
        "subtenant_id": "tenant123"
    }, headers=headers)
    
    # Try to grant same service access again
    response = client.post(f"/api/v1/users/{user_id}/service-access", json={
        "service": "analytics",
        "subtenant_id": "tenant456"  # Different subtenant, but same service
    }, headers=headers)
    
    assert response.status_code == 400
    assert "already has active access" in response.json()["detail"]

def test_revoke_user_service_access(client, test_db):
    """Test revoking user service access"""
    headers = get_auth_headers(client, test_db)
    
    # Create user and grant access
    user_response = client.post("/api/v1/users/", json={
        "email": "revokeuser@example.com"
    }, headers=headers)
    user_id = user_response.json()["id"]
    
    client.post(f"/api/v1/users/{user_id}/service-access", json={
        "service": "billing",
        "subtenant_id": "billing123"
    }, headers=headers)
    
    # Revoke access
    response = client.delete(f"/api/v1/users/{user_id}/service-access/billing/billing123", headers=headers)
    assert response.status_code == 200
    assert "revoked successfully" in response.json()["message"]
    
    # Verify access is revoked
    access_check = client.get(f"/api/v1/users/{user_id}/access/billing/billing123", headers=headers)
    assert access_check.status_code == 200
    assert access_check.json()["has_access"] is False

def test_list_user_service_access(client, test_db):
    """Test listing user's service access"""
    headers = get_auth_headers(client, test_db)
    
    # Create user and grant multiple accesses
    user_response = client.post("/api/v1/users/", json={
        "email": "listuser@example.com"
    }, headers=headers)
    user_id = user_response.json()["id"]
    
    # Grant access to multiple services
    client.post(f"/api/v1/users/{user_id}/service-access", json={
        "service": "analytics",
        "subtenant_id": "analytics123"
    }, headers=headers)
    
    client.post(f"/api/v1/users/{user_id}/service-access", json={
        "service": "reporting", 
        "subtenant_id": "reporting456"
    }, headers=headers)
    
    # List active access
    response = client.get(f"/api/v1/users/{user_id}/service-access", headers=headers)
    assert response.status_code == 200
    accesses = response.json()
    assert len(accesses) == 2
    
    services = [access["service"] for access in accesses]
    assert "analytics" in services
    assert "reporting" in services

def test_check_user_access_valid(client, test_db):
    """Test checking valid user access"""
    headers = get_auth_headers(client, test_db)
    
    user_response = client.post("/api/v1/users/", json={
        "email": "checkuser@example.com"
    }, headers=headers)
    user_id = user_response.json()["id"]
    
    # Grant access
    client.post(f"/api/v1/users/{user_id}/service-access", json={
        "service": "dashboard",
        "subtenant_id": "dash123"
    }, headers=headers)
    
    # Check access
    response = client.get(f"/api/v1/users/{user_id}/access/dashboard/dash123", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["has_access"] is True
    assert data["access_details"] is not None
    assert data["access_details"]["service"] == "dashboard"

def test_check_user_access_invalid(client, test_db):
    """Test checking invalid user access"""
    headers = get_auth_headers(client, test_db)
    
    user_response = client.post("/api/v1/users/", json={
        "email": "noaccessuser@example.com"
    }, headers=headers)
    user_id = user_response.json()["id"]
    
    # Check access without granting any
    response = client.get(f"/api/v1/users/{user_id}/access/nonexistent/service123", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["has_access"] is False
    assert data["access_details"] is None

# ===== NEW GROUP MEMBERSHIP TESTS =====

def test_get_user_groups(client, test_db):
    """Test getting user's group memberships"""
    headers = get_auth_headers(client, test_db)
    
    # Create user and group
    user_response = client.post("/api/v1/users/", json={
        "email": "groupuser@example.com"
    }, headers=headers)
    user_id = user_response.json()["id"]
    
    group_response = client.post("/api/v1/groups/", json={
        "name": "Test Group",
        "description": "A test group"
    }, headers=headers)
    group_id = group_response.json()["id"]
    
    # Add user to group
    client.post(f"/api/v1/groups/{group_id}/members", json={
        "user_id": user_id,
        "role": "member"
    }, headers=headers)
    
    # Get user's groups
    response = client.get(f"/api/v1/users/{user_id}/groups", headers=headers)
    assert response.status_code == 200
    groups = response.json()
    assert len(groups) >= 1  # May have domain group too
    
    test_group = next((g for g in groups if g["group_name"] == "Test Group"), None)
    assert test_group is not None
    assert test_group["role"] == "member"
    assert test_group["active"] is True

def test_add_group_member(client, test_db):
    """Test adding a member to a group"""
    headers = get_auth_headers(client, test_db)
    
    # Create user and group
    user_response = client.post("/api/v1/users/", json={"email": "newmember@example.com"}, headers=headers)
    user_id = user_response.json()["id"]
    
    group_response = client.post("/api/v1/groups/", json={"name": "Member Group"}, headers=headers)
    group_id = group_response.json()["id"]
    
    # Add member
    response = client.post(f"/api/v1/groups/{group_id}/members", json={
        "user_id": user_id,
        "role": "admin"
    }, headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["user_id"] == user_id
    assert data["group_id"] == group_id
    assert data["role"] == "admin"
    assert data["active"] is True
    assert data["added_by"] is not None

def test_remove_group_member(client, test_db):
    """Test removing a member from a group"""
    headers = get_auth_headers(client, test_db)
    
    # Create user and group, add member
    user_response = client.post("/api/v1/users/", json={"email": "removemember@example.com"}, headers=headers)
    user_id = user_response.json()["id"]
    
    group_response = client.post("/api/v1/groups/", json={"name": "Remove Group"}, headers=headers)
    group_id = group_response.json()["id"]
    
    client.post(f"/api/v1/groups/{group_id}/members", json={"user_id": user_id}, headers=headers)
    
    # Remove member
    response = client.delete(f"/api/v1/groups/{group_id}/members/{user_id}", headers=headers)
    assert response.status_code == 200
    assert "removed from group" in response.json()["message"]
    
    # Verify user no longer in active group members
    members_response = client.get(f"/api/v1/groups/{group_id}/members", headers=headers)
    active_members = [m for m in members_response.json() if m["active"]]
    member_user_ids = [m["user_id"] for m in active_members]
    assert user_id not in member_user_ids

def test_get_group_members(client, test_db):
    """Test getting group members"""
    headers = get_auth_headers(client, test_db)
    
    # Create group and users
    group_response = client.post("/api/v1/groups/", json={"name": "Members Group"}, headers=headers)
    group_id = group_response.json()["id"]
    
    user1_response = client.post("/api/v1/users/", json={"email": "member1@example.com"}, headers=headers)
    user1_id = user1_response.json()["id"]
    
    user2_response = client.post("/api/v1/users/", json={"email": "member2@example.com"}, headers=headers)
    user2_id = user2_response.json()["id"]
    
    # Add both users
    client.post(f"/api/v1/groups/{group_id}/members", json={"user_id": user1_id, "role": "admin"}, headers=headers)
    client.post(f"/api/v1/groups/{group_id}/members", json={"user_id": user2_id, "role": "member"}, headers=headers)
    
    # Get members
    response = client.get(f"/api/v1/groups/{group_id}/members", headers=headers)
    assert response.status_code == 200
    members = response.json()
    assert len(members) == 2
    
    # Check both users are present with correct roles
    user_roles = {m["user_id"]: m["role"] for m in members}
    assert user_roles[user1_id] == "admin"
    assert user_roles[user2_id] == "member"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])