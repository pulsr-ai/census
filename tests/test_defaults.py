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
from app.core import models, config

# Set up test admin credentials
os.environ["ADMIN_EMAIL"] = "testadmin@example.com"
config.ADMIN_EMAIL = "testadmin@example.com"

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

def get_admin_headers(client):
    """Helper function to get admin authentication headers via OTP flow"""
    # Step 1: Initiate login to get OTP session
    login_response = client.post("/api/v1/auth/login", json={
        "email": "testadmin@example.com"
    })
    assert login_response.status_code == 200
    login_data = login_response.json()
    session_id = login_data["session_id"]
    
    # Step 2: Verify OTP (we'll use a mock OTP code for testing)
    # In a real scenario, this would be sent via email
    otp_response = client.post("/api/v1/auth/verify-otp", json={
        "session_id": session_id,
        "otp_code": "123456"  # This should work with a test OTP
    })
    
    if otp_response.status_code == 200:
        token = otp_response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    
    # If OTP verification fails, we'll need to mock the token
    from app.core import auth
    from datetime import timedelta
    
    # Create a mock admin token for testing (using a valid UUID)
    import uuid
    access_token = auth.create_access_token(
        data={"sub": str(uuid.uuid4()), "email": "testadmin@example.com"},
        expires_delta=timedelta(minutes=30)
    )
    return {"Authorization": f"Bearer {access_token}"}

@pytest.fixture
def client():
    return TestClient(app)

def test_admin_group_created_via_api(client):
    """Test that Admins group is accessible via API"""
    headers = get_admin_headers(client)
    
    response = client.get("/api/v1/groups/", headers=headers)
    assert response.status_code == 200
    
    groups = response.json()
    admin_group = next((g for g in groups if g["name"] == "Admins"), None)
    
    assert admin_group is not None
    assert admin_group["name"] == "Admins"
    assert admin_group["description"] == "System administrators with full access"

def test_users_group_created_via_api(client):
    """Test that Users group is accessible via API"""
    headers = get_admin_headers(client)
    
    response = client.get("/api/v1/groups/", headers=headers)
    assert response.status_code == 200
    
    groups = response.json()
    users_group = next((g for g in groups if g["name"] == "Users"), None)
    
    assert users_group is not None
    assert users_group["name"] == "Users"
    assert users_group["description"] == "Regular users with basic permissions"

def test_admin_uses_otp_like_everyone_else(client):
    """Test that admin user uses OTP authentication (no password auth)"""
    # Admin should use regular login endpoint with OTP
    response = client.post("/api/v1/auth/login", json={
        "email": "testadmin@example.com"
    })
    
    assert response.status_code == 200
    data = response.json()
    assert "session_id" in data
    assert data["message"] == "OTP sent to your email"
    # No direct password login for admins

def test_permissions_created_via_api(client):
    """Test that all default permissions are created and accessible via API"""
    headers = get_admin_headers(client)
    
    response = client.get("/api/v1/permissions/", headers=headers)
    assert response.status_code == 200
    
    permissions = response.json()
    permission_names = [p["name"] for p in permissions]
    
    expected_permissions = [
        "users:create", "users:read", "users:update", "users:delete",
        "groups:create", "groups:read", "groups:update", "groups:delete", 
        "fields:create", "fields:read", "fields:update", "fields:delete",
        "field_values:set_own", "field_values:set_any",
        "field_values:read_own", "field_values:read_any",
        "permissions:manage"
    ]
    
    for perm_name in expected_permissions:
        assert perm_name in permission_names, f"Permission {perm_name} not found"

def test_domain_group_creation_via_api(client):
    """Test that domain groups are created when users sign up"""
    # Test user login with a new domain to trigger domain group creation
    response = client.post("/api/v1/auth/login", json={
        "email": "newuser@example.com"
    })
    assert response.status_code == 200
    
    # Get admin access to check if domain group was created
    headers = get_admin_headers(client)
    
    # Check that example.com domain group was created
    groups_response = client.get("/api/v1/groups/", headers=headers)
    assert groups_response.status_code == 200
    
    groups = groups_response.json()
    domain_group = next((g for g in groups if g["name"] == "example.com"), None)
    
    assert domain_group is not None
    assert domain_group["email_domain"] == "example.com"
    assert domain_group["description"] == "Auto-created group for example.com domain"

def test_domain_group_reuse_via_api(client):
    """Test that existing domain groups are reused"""
    # Create first user with testdomain.com
    response1 = client.post("/api/v1/auth/login", json={
        "email": "user1@testdomain.com" 
    })
    assert response1.status_code == 200
    
    # Create second user with same domain
    response2 = client.post("/api/v1/auth/login", json={
        "email": "user2@testdomain.com"
    })
    assert response2.status_code == 200
    
    # Check via API that only one testdomain.com group exists
    headers = get_admin_headers(client)
    groups_response = client.get("/api/v1/groups/", headers=headers)
    assert groups_response.status_code == 200
    
    groups = groups_response.json()
    testdomain_groups = [g for g in groups if g["name"] == "testdomain.com"]
    
    # Should only be one group for this domain
    assert len(testdomain_groups) == 1

if __name__ == "__main__":
    pytest.main([__file__, "-v"])