import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os
import sys
from dotenv import load_dotenv
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import app
from app.core.database import get_db
from app.core.models import Base
from app.core import models

# Create test database
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

def get_auth_headers(client, test_db):
    """Helper function to get authentication headers"""
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

class TestUserServiceAccess:
    """Test suite for UserServiceSubtenant functionality"""
    
    def test_grant_service_access_success(self, client, test_db):
        """Test successful service access grant"""
        headers = get_auth_headers(client, test_db)
        
        # Create user
        user_response = client.post("/api/v1/users/", json={
            "email": "serviceuser@example.com"
        }, headers=headers)
        user_id = user_response.json()["id"]
        
        # Grant access
        response = client.post(f"/api/v1/users/{user_id}/service-access", json={
            "service": "analytics",
            "subtenant_id": "tenant_123"
        }, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "analytics"
        assert data["subtenant_id"] == "tenant_123"
        assert data["active"] is True
        assert data["granted_by"] is not None
        assert data["granted_at"] is not None
        
    def test_grant_service_access_nonexistent_user(self, client, test_db):
        """Test granting access to non-existent user fails"""
        headers = get_auth_headers(client, test_db)
        fake_uuid = "550e8400-e29b-41d4-a716-446655440000"
        
        response = client.post(f"/api/v1/users/{fake_uuid}/service-access", json={
            "service": "analytics",
            "subtenant_id": "tenant_123"
        }, headers=headers)
        
        assert response.status_code == 404
        assert "User not found" in response.json()["detail"]
        
    def test_duplicate_active_service_access_fails(self, client, test_db):
        """Test that duplicate active service access is prevented"""
        headers = get_auth_headers(client, test_db)
        
        # Create user and grant access
        user_response = client.post("/api/v1/users/", json={
            "email": "duplicateuser@example.com"
        }, headers=headers)
        user_id = user_response.json()["id"]
        
        # First grant
        client.post(f"/api/v1/users/{user_id}/service-access", json={
            "service": "analytics",
            "subtenant_id": "tenant_123"
        }, headers=headers)
        
        # Second grant (should fail)
        response = client.post(f"/api/v1/users/{user_id}/service-access", json={
            "service": "analytics",
            "subtenant_id": "tenant_456"  # Different subtenant, same service
        }, headers=headers)
        
        assert response.status_code == 400
        assert "already has active access" in response.json()["detail"]
        
    def test_multiple_services_same_user(self, client, test_db):
        """Test user can have access to multiple services"""
        headers = get_auth_headers(client, test_db)
        
        user_response = client.post("/api/v1/users/", json={
            "email": "multiuser@example.com"
        }, headers=headers)
        user_id = user_response.json()["id"]
        
        # Grant access to multiple services
        services = ["analytics", "reporting", "dashboard"]
        for service in services:
            response = client.post(f"/api/v1/users/{user_id}/service-access", json={
                "service": service,
                "subtenant_id": f"{service}_tenant"
            }, headers=headers)
            assert response.status_code == 200
        
        # Verify all accesses
        response = client.get(f"/api/v1/users/{user_id}/service-access", headers=headers)
        assert response.status_code == 200
        accesses = response.json()
        assert len(accesses) == 3
        
        granted_services = [access["service"] for access in accesses]
        for service in services:
            assert service in granted_services
            
    def test_revoke_service_access_success(self, client, test_db):
        """Test successful service access revocation"""
        headers = get_auth_headers(client, test_db)
        
        # Create user and grant access
        user_response = client.post("/api/v1/users/", json={
            "email": "revokeuser@example.com"
        }, headers=headers)
        user_id = user_response.json()["id"]
        
        client.post(f"/api/v1/users/{user_id}/service-access", json={
            "service": "billing",
            "subtenant_id": "billing_123"
        }, headers=headers)
        
        # Revoke access
        response = client.delete(f"/api/v1/users/{user_id}/service-access/billing/billing_123", headers=headers)
        assert response.status_code == 200
        assert "revoked successfully" in response.json()["message"]
        
        # Verify access is revoked in database
        access_record = test_db.query(models.UserServiceSubtenant).filter(
            models.UserServiceSubtenant.user_id == user_id,
            models.UserServiceSubtenant.service == "billing"
        ).first()
        
        assert access_record is not None
        assert access_record.active is False
        assert access_record.revoked_at is not None
        assert access_record.revoked_by is not None
        
    def test_revoke_nonexistent_access(self, client, test_db):
        """Test revoking non-existent access fails gracefully"""
        headers = get_auth_headers(client, test_db)
        
        user_response = client.post("/api/v1/users/", json={
            "email": "noaccessuser@example.com"
        }, headers=headers)
        user_id = user_response.json()["id"]
        
        response = client.delete(f"/api/v1/users/{user_id}/service-access/nonexistent/service123", headers=headers)
        assert response.status_code == 404
        assert "not found" in response.json()["detail"]
        
    def test_access_validation_positive(self, client, test_db):
        """Test access validation returns true for valid access"""
        headers = get_auth_headers(client, test_db)
        
        user_response = client.post("/api/v1/users/", json={
            "email": "validuser@example.com"
        }, headers=headers)
        user_id = user_response.json()["id"]
        
        # Grant access
        client.post(f"/api/v1/users/{user_id}/service-access", json={
            "service": "dashboard",
            "subtenant_id": "dash_123"
        }, headers=headers)
        
        # Check access
        response = client.get(f"/api/v1/users/{user_id}/access/dashboard/dash_123", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["has_access"] is True
        assert data["access_details"] is not None
        assert data["access_details"]["service"] == "dashboard"
        assert data["access_details"]["subtenant_id"] == "dash_123"
        assert data["access_details"]["active"] is True
        
    def test_access_validation_negative(self, client, test_db):
        """Test access validation returns false for invalid access"""
        headers = get_auth_headers(client, test_db)
        
        user_response = client.post("/api/v1/users/", json={
            "email": "invaliduser@example.com"
        }, headers=headers)
        user_id = user_response.json()["id"]
        
        # Check access without granting any
        response = client.get(f"/api/v1/users/{user_id}/access/dashboard/dash_123", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["has_access"] is False
        assert data["access_details"] is None
        
    def test_access_validation_revoked(self, client, test_db):
        """Test access validation returns false for revoked access"""
        headers = get_auth_headers(client, test_db)
        
        user_response = client.post("/api/v1/users/", json={
            "email": "revokeduser@example.com"
        }, headers=headers)
        user_id = user_response.json()["id"]
        
        # Grant and then revoke access
        client.post(f"/api/v1/users/{user_id}/service-access", json={
            "service": "reports",
            "subtenant_id": "report_123"
        }, headers=headers)
        
        client.delete(f"/api/v1/users/{user_id}/service-access/reports/report_123", headers=headers)
        
        # Check access
        response = client.get(f"/api/v1/users/{user_id}/access/reports/report_123", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["has_access"] is False
        # access_details might be None or contain revoked record
        
    def test_list_service_access_active_only(self, client, test_db):
        """Test listing only active service access"""
        headers = get_auth_headers(client, test_db)
        
        user_response = client.post("/api/v1/users/", json={
            "email": "listuser@example.com"
        }, headers=headers)
        user_id = user_response.json()["id"]
        
        # Grant multiple accesses
        services = ["analytics", "billing", "reports"]
        for service in services:
            client.post(f"/api/v1/users/{user_id}/service-access", json={
                "service": service,
                "subtenant_id": f"{service}_tenant"
            }, headers=headers)
        
        # Revoke one
        client.delete(f"/api/v1/users/{user_id}/service-access/billing/billing_tenant", headers=headers)
        
        # List active only (default)
        response = client.get(f"/api/v1/users/{user_id}/service-access", headers=headers)
        assert response.status_code == 200
        accesses = response.json()
        assert len(accesses) == 2  # Only active ones
        
        active_services = [access["service"] for access in accesses]
        assert "analytics" in active_services
        assert "reports" in active_services
        assert "billing" not in active_services
        
    def test_list_service_access_all(self, client, test_db):
        """Test listing all service access including inactive"""
        headers = get_auth_headers(client, test_db)
        
        user_response = client.post("/api/v1/users/", json={
            "email": "listalluser@example.com"
        }, headers=headers)
        user_id = user_response.json()["id"]
        
        # Grant and revoke an access
        client.post(f"/api/v1/users/{user_id}/service-access", json={
            "service": "test_service",
            "subtenant_id": "test_tenant"
        }, headers=headers)
        
        client.delete(f"/api/v1/users/{user_id}/service-access/test_service/test_tenant", headers=headers)
        
        # List all access
        response = client.get(f"/api/v1/users/{user_id}/service-access?active_only=false", headers=headers)
        assert response.status_code == 200
        accesses = response.json()
        assert len(accesses) == 1
        assert accesses[0]["service"] == "test_service"
        assert accesses[0]["active"] is False
        assert accesses[0]["revoked_at"] is not None


class TestGroupMembership:
    """Test suite for GroupMember functionality"""
    
    def test_add_group_member_success(self, client, test_db):
        """Test successfully adding a member to a group"""
        headers = get_auth_headers(client, test_db)
        
        # Create user and group
        user_response = client.post("/api/v1/users/", json={"email": "member@example.com"}, headers=headers)
        user_id = user_response.json()["id"]
        
        group_response = client.post("/api/v1/groups/", json={"name": "Test Group"}, headers=headers)
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
        assert data["added_at"] is not None
        
    def test_add_duplicate_member_fails(self, client, test_db):
        """Test adding duplicate active member fails"""
        headers = get_auth_headers(client, test_db)
        
        user_response = client.post("/api/v1/users/", json={"email": "duplicate@example.com"}, headers=headers)
        user_id = user_response.json()["id"]
        
        group_response = client.post("/api/v1/groups/", json={"name": "Duplicate Group"}, headers=headers)
        group_id = group_response.json()["id"]
        
        # Add member first time
        client.post(f"/api/v1/groups/{group_id}/members", json={"user_id": user_id}, headers=headers)
        
        # Try to add again
        response = client.post(f"/api/v1/groups/{group_id}/members", json={"user_id": user_id}, headers=headers)
        assert response.status_code == 400
        assert "already an active member" in response.json()["detail"]
        
    def test_remove_group_member_success(self, client, test_db):
        """Test successfully removing a group member"""
        headers = get_auth_headers(client, test_db)
        
        user_response = client.post("/api/v1/users/", json={"email": "removeme@example.com"}, headers=headers)
        user_id = user_response.json()["id"]
        
        group_response = client.post("/api/v1/groups/", json={"name": "Remove Group"}, headers=headers)
        group_id = group_response.json()["id"]
        
        # Add then remove member
        client.post(f"/api/v1/groups/{group_id}/members", json={"user_id": user_id}, headers=headers)
        
        response = client.delete(f"/api/v1/groups/{group_id}/members/{user_id}", headers=headers)
        assert response.status_code == 200
        assert "removed from group" in response.json()["message"]
        
        # Verify member is inactive in database
        membership = test_db.query(models.GroupMember).filter(
            models.GroupMember.user_id == user_id,
            models.GroupMember.group_id == group_id
        ).first()
        
        assert membership is not None
        assert membership.active is False
        assert membership.removed_at is not None
        assert membership.removed_by is not None
        
    def test_get_group_members(self, client, test_db):
        """Test getting group members"""
        headers = get_auth_headers(client, test_db)
        
        group_response = client.post("/api/v1/groups/", json={"name": "Members Group"}, headers=headers)
        group_id = group_response.json()["id"]
        
        # Add multiple members
        user_ids = []
        for i in range(3):
            user_response = client.post("/api/v1/users/", json={
                "email": f"member{i}@example.com"
            }, headers=headers)
            user_id = user_response.json()["id"]
            user_ids.append(user_id)
            
            client.post(f"/api/v1/groups/{group_id}/members", json={
                "user_id": user_id,
                "role": f"role{i}"
            }, headers=headers)
        
        # Remove one member
        client.delete(f"/api/v1/groups/{group_id}/members/{user_ids[1]}", headers=headers)
        
        # Get active members
        response = client.get(f"/api/v1/groups/{group_id}/members", headers=headers)
        assert response.status_code == 200
        members = response.json()
        assert len(members) == 2  # Only active members
        
        active_user_ids = [m["user_id"] for m in members]
        assert user_ids[0] in active_user_ids
        assert user_ids[2] in active_user_ids
        assert user_ids[1] not in active_user_ids
        
    def test_get_user_groups_summary(self, client, test_db):
        """Test getting user's group summary"""
        headers = get_auth_headers(client, test_db)
        
        user_response = client.post("/api/v1/users/", json={"email": "groupuser@example.com"}, headers=headers)
        user_id = user_response.json()["id"]
        
        # Create groups and add user
        groups = []
        for i in range(2):
            group_response = client.post("/api/v1/groups/", json={
                "name": f"Group {i}"
            }, headers=headers)
            group_id = group_response.json()["id"]
            groups.append(group_id)
            
            client.post(f"/api/v1/groups/{group_id}/members", json={
                "user_id": user_id,
                "role": f"role{i}"
            }, headers=headers)
        
        # Remove from one group
        client.delete(f"/api/v1/groups/{groups[0]}/members/{user_id}", headers=headers)
        
        # Get user's active groups
        response = client.get(f"/api/v1/users/{user_id}/groups", headers=headers)
        assert response.status_code == 200
        user_groups = response.json()
        
        # Should have one active group plus potentially domain group
        active_groups = [g for g in user_groups if g["active"]]
        test_groups = [g for g in active_groups if g["group_name"].startswith("Group")]
        assert len(test_groups) == 1
        assert test_groups[0]["group_name"] == "Group 1"
        assert test_groups[0]["role"] == "role1"


class TestAuditTrailsAndConstraints:
    """Test audit trails and database constraints"""
    
    def test_service_access_audit_trail(self, client, test_db):
        """Test that service access maintains proper audit trail"""
        headers = get_auth_headers(client, test_db)
        
        user_response = client.post("/api/v1/users/", json={"email": "audituser@example.com"}, headers=headers)
        user_id = user_response.json()["id"]
        
        # Grant access
        grant_response = client.post(f"/api/v1/users/{user_id}/service-access", json={
            "service": "audit_service",
            "subtenant_id": "audit_tenant"
        }, headers=headers)
        access_id = grant_response.json()["id"]
        
        # Revoke access
        client.delete(f"/api/v1/users/{user_id}/service-access/audit_service/audit_tenant", headers=headers)
        
        # Check audit trail in database
        access_record = test_db.query(models.UserServiceSubtenant).filter(
            models.UserServiceSubtenant.id == access_id
        ).first()
        
        assert access_record is not None
        # Granted fields
        assert access_record.granted_at is not None
        assert access_record.granted_by is not None
        # Revoked fields
        assert access_record.revoked_at is not None
        assert access_record.revoked_by is not None
        assert access_record.active is False
        
    def test_group_membership_audit_trail(self, client, test_db):
        """Test that group membership maintains proper audit trail"""
        headers = get_auth_headers(client, test_db)
        
        user_response = client.post("/api/v1/users/", json={"email": "memberaudit@example.com"}, headers=headers)
        user_id = user_response.json()["id"]
        
        group_response = client.post("/api/v1/groups/", json={"name": "Audit Group"}, headers=headers)
        group_id = group_response.json()["id"]
        
        # Add member
        add_response = client.post(f"/api/v1/groups/{group_id}/members", json={
            "user_id": user_id,
            "role": "member"
        }, headers=headers)
        membership_id = add_response.json()["id"]
        
        # Remove member
        client.delete(f"/api/v1/groups/{group_id}/members/{user_id}", headers=headers)
        
        # Check audit trail
        membership = test_db.query(models.GroupMember).filter(
            models.GroupMember.id == membership_id
        ).first()
        
        assert membership is not None
        # Added fields
        assert membership.added_at is not None
        assert membership.added_by is not None
        # Removed fields
        assert membership.removed_at is not None
        assert membership.removed_by is not None
        assert membership.active is False
        
    def test_unique_constraint_database_level(self, client, test_db):
        """Test that unique constraint is enforced at database level"""
        from sqlalchemy.exc import IntegrityError
        
        # Create user directly in database
        user = models.User(email="constraintuser@example.com")
        test_db.add(user)
        test_db.commit()
        test_db.refresh(user)
        
        # Create first service access
        access1 = models.UserServiceSubtenant(
            user_id=user.id,
            service="constraint_service",
            subtenant_id="tenant1",
            active=True
        )
        test_db.add(access1)
        test_db.commit()
        
        # Try to create duplicate active access (should fail)
        access2 = models.UserServiceSubtenant(
            user_id=user.id,
            service="constraint_service",
            subtenant_id="tenant2",  # Different subtenant, same service
            active=True
        )
        test_db.add(access2)
        
        with pytest.raises(IntegrityError):
            test_db.commit()
        
        test_db.rollback()
        
        # But should be able to create inactive duplicate
        access3 = models.UserServiceSubtenant(
            user_id=user.id,
            service="constraint_service",
            subtenant_id="tenant3",
            active=False  # Inactive
        )
        test_db.add(access3)
        test_db.commit()  # Should succeed
        
    def test_reactivation_after_revocation(self, client, test_db):
        """Test that user can be re-granted access after revocation"""
        headers = get_auth_headers(client, test_db)
        
        user_response = client.post("/api/v1/users/", json={"email": "reactivate@example.com"}, headers=headers)
        user_id = user_response.json()["id"]
        
        # Grant access
        client.post(f"/api/v1/users/{user_id}/service-access", json={
            "service": "reactivate_service",
            "subtenant_id": "reactivate_tenant"
        }, headers=headers)
        
        # Revoke access
        client.delete(f"/api/v1/users/{user_id}/service-access/reactivate_service/reactivate_tenant", headers=headers)
        
        # Grant access again (should work)
        response = client.post(f"/api/v1/users/{user_id}/service-access", json={
            "service": "reactivate_service",
            "subtenant_id": "reactivate_tenant_new"
        }, headers=headers)
        
        assert response.status_code == 200
        assert response.json()["service"] == "reactivate_service"
        assert response.json()["active"] is True

if __name__ == "__main__":
    pytest.main([__file__, "-v"])