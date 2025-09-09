from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import and_
from sqlalchemy.sql import func
from typing import List
from ....core import models, auth
from ....core.database import get_db
from .. import schemas

router = APIRouter(prefix="/users", tags=["users"])

@router.post("/", response_model=schemas.User)
def create_user(
    user: schemas.UserCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    normalized_email = auth.normalize_email(user.email)
    existing_user = db.query(models.User).filter(
        models.User.email == normalized_email
    ).first()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    db_user = models.User(
        email=normalized_email,
        is_active=user.is_active,
        is_anonymous=user.is_anonymous
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@router.get("/", response_model=List[schemas.User])
def read_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    users = db.query(models.User).offset(skip).limit(limit).all()
    return users

@router.get("/me", response_model=schemas.UserWithDetails)
def read_current_user(current_user: models.User = Depends(auth.get_current_active_user)):
    return current_user

@router.get("/{user_id}", response_model=schemas.UserWithDetails)
def read_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user

@router.put("/{user_id}", response_model=schemas.User)
def update_user(
    user_id: str,
    user_update: schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    update_data = user_update.model_dump(exclude_unset=True)
    
    if "email" in update_data:
        normalized_email = auth.normalize_email(update_data["email"])
        existing_user = db.query(models.User).filter(
            models.User.email == normalized_email,
            models.User.id != user_id
        ).first()
        
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use"
            )
        
        update_data["email"] = normalized_email
    
    for field, value in update_data.items():
        setattr(user, field, value)
    
    db.commit()
    db.refresh(user)
    return user

@router.delete("/{user_id}")
def delete_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}

@router.post("/{user_id}/field-values", response_model=schemas.FieldValue)
def create_user_field_value(
    user_id: str,
    field_value: schemas.FieldValueCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    # Check if user exists
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Allow users to set their own field values, or any if they're admin
    if str(current_user.id) != user_id:
        if not auth.is_admin(db, current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only set your own field values"
            )
    
    # Check if field exists
    field = db.query(models.Field).filter(models.Field.id == field_value.field_id).first()
    if not field:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Field not found"
        )
    
    # Check if field value already exists for this user
    existing_field_value = db.query(models.FieldValue).filter(
        models.FieldValue.user_id == user_id,
        models.FieldValue.field_id == field_value.field_id
    ).first()
    
    if existing_field_value:
        existing_field_value.value = field_value.value
        db.commit()
        db.refresh(existing_field_value)
        return existing_field_value
    
    db_field_value = models.FieldValue(
        user_id=user_id,
        field_id=field_value.field_id,
        value=field_value.value
    )
    db.add(db_field_value)
    db.commit()
    db.refresh(db_field_value)
    return db_field_value

@router.get("/{user_id}/field-values", response_model=List[schemas.FieldValue])
def read_user_field_values(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    field_values = db.query(models.FieldValue).filter(
        models.FieldValue.user_id == user_id
    ).all()
    return field_values

@router.post("/{user_id}/groups/{group_id}")
def add_user_to_group(
    user_id: str,
    group_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Group not found"
        )
    
    if group not in user.groups:
        user.groups.append(group)
        db.commit()
    
    return {"message": "User added to group successfully"}

@router.delete("/{user_id}/groups/{group_id}")
def remove_user_from_group(
    user_id: str,
    group_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Group not found"
        )
    
    if group in user.groups:
        user.groups.remove(group)
        db.commit()
    
    return {"message": "User removed from group successfully"}

@router.post("/{user_id}/service-access", response_model=schemas.UserServiceSubtenant)
def grant_user_service_access(
    user_id: str,
    service_access: schemas.UserServiceSubtenantGrant,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Check if user already has active access to this service
    existing_access = db.query(models.UserServiceSubtenant).filter(
        and_(
            models.UserServiceSubtenant.user_id == user_id,
            models.UserServiceSubtenant.service == service_access.service,
            models.UserServiceSubtenant.active == True
        )
    ).first()
    
    if existing_access:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User already has active access to service {service_access.service}"
        )
    
    db_service_access = models.UserServiceSubtenant(
        user_id=user_id,
        service=service_access.service,
        subtenant_id=service_access.subtenant_id,
        granted_by=service_access.granted_by or current_user.id
    )
    
    db.add(db_service_access)
    db.commit()
    db.refresh(db_service_access)
    return db_service_access

@router.delete("/{user_id}/service-access/{service}/{subtenant_id}")
def revoke_user_service_access(
    user_id: str,
    service: str,
    subtenant_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    service_access = db.query(models.UserServiceSubtenant).filter(
        and_(
            models.UserServiceSubtenant.user_id == user_id,
            models.UserServiceSubtenant.service == service,
            models.UserServiceSubtenant.subtenant_id == subtenant_id,
            models.UserServiceSubtenant.active == True
        )
    ).first()
    
    if not service_access:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Service access not found or already revoked"
        )
    
    service_access.active = False
    service_access.revoked_at = func.now()
    service_access.revoked_by = current_user.id
    
    db.commit()
    return {"message": "Service access revoked successfully"}

@router.get("/{user_id}/service-access", response_model=List[schemas.UserServiceSubtenant])
def list_user_service_access(
    user_id: str,
    active_only: bool = True,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    query = db.query(models.UserServiceSubtenant).filter(
        models.UserServiceSubtenant.user_id == user_id
    )
    
    if active_only:
        query = query.filter(models.UserServiceSubtenant.active == True)
    
    service_access_list = query.order_by(models.UserServiceSubtenant.granted_at.desc()).all()
    return service_access_list

@router.get("/{user_id}/access/{service}/{subtenant_id}", response_model=schemas.UserAccessCheck)
def check_user_access(
    user_id: str,
    service: str,
    subtenant_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    service_access = db.query(models.UserServiceSubtenant).filter(
        and_(
            models.UserServiceSubtenant.user_id == user_id,
            models.UserServiceSubtenant.service == service,
            models.UserServiceSubtenant.subtenant_id == subtenant_id,
            models.UserServiceSubtenant.active == True
        )
    ).first()
    
    return schemas.UserAccessCheck(
        has_access=service_access is not None,
        access_details=service_access
    )

@router.get("/{user_id}/groups", response_model=List[schemas.UserGroupSummary])
def get_user_groups(
    user_id: str,
    active_only: bool = True,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    query = db.query(
        models.GroupMember.group_id,
        models.Group.name.label('group_name'),
        models.GroupMember.role,
        models.GroupMember.added_at,
        models.GroupMember.active
    ).join(
        models.Group, models.GroupMember.group_id == models.Group.id
    ).filter(
        models.GroupMember.user_id == user_id
    )
    
    if active_only:
        query = query.filter(models.GroupMember.active == True)
    
    memberships = query.order_by(models.GroupMember.added_at.desc()).all()
    
    return [
        schemas.UserGroupSummary(
            group_id=membership.group_id,
            group_name=membership.group_name,
            role=membership.role,
            added_at=membership.added_at,
            active=membership.active
        )
        for membership in memberships
    ]