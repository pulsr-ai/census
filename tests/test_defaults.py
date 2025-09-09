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
    """Helper function to get admin authentication headers"""
    from app.core import auth, models
    from datetime import timedelta
    
    # Get database session
    db = TestingSessionLocal()
    try:
        # Get admin user (should exist from initialization)
        admin_user = db.query(models.User).filter(models.User.email == "admin@example.com").first()
        
        if not admin_user:
            # Create admin user if not exists
            admin_user = models.User(
                email="admin@example.com",
                is_active=True,
                is_anonymous=False,
                otp_verified=True
            )
            db.add(admin_user)
            db.commit()
            db.refresh(admin_user)
            
            # Add to admin group
            admin_group = db.query(models.Group).filter(models.Group.name == "Admins").first()
            if admin_group:
                group_member = models.GroupMember(
                    user_id=admin_user.id,
                    group_id=admin_group.id,
                    role="admin",
                    active=True,
                    added_by=admin_user.id
                )
                db.add(group_member)
                db.commit()
        
        # Create token with real user ID
        access_token = auth.create_access_token(
            data={"sub": str(admin_user.id), "email": admin_user.email},
            expires_delta=timedelta(minutes=30)
        )
        return {"Authorization": f"Bearer {access_token}"}
        
    finally:
        db.close()

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

def test_permissions_removed_from_api(client):
    """Test that permissions endpoints have been removed (moved to microservices)"""
    headers = get_admin_headers(client)
    
    # Permissions endpoints should no longer exist
    response = client.get("/api/v1/permissions/", headers=headers)
    assert response.status_code == 404  # Endpoint no longer exists

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