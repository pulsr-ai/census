from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from ....core import models, auth
from ....core.database import get_db
from .. import schemas

router = APIRouter(prefix="/permissions", tags=["permissions"])

@router.post("/", response_model=schemas.Permission)
def create_permission(
    permission: schemas.PermissionCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    existing_permission = db.query(models.Permission).filter(
        models.Permission.name == permission.name
    ).first()
    
    if existing_permission:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Permission name already exists"
        )
    
    db_permission = models.Permission(
        name=permission.name,
        description=permission.description,
        resource=permission.resource,
        action=permission.action
    )
    db.add(db_permission)
    db.commit()
    db.refresh(db_permission)
    return db_permission

@router.get("/", response_model=List[schemas.Permission])
def read_permissions(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    permissions = db.query(models.Permission).offset(skip).limit(limit).all()
    return permissions

@router.get("/{permission_id}", response_model=schemas.Permission)
def read_permission(
    permission_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    permission = db.query(models.Permission).filter(
        models.Permission.id == permission_id
    ).first()
    if permission is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found"
        )
    return permission

@router.delete("/{permission_id}")
def delete_permission(
    permission_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    permission = db.query(models.Permission).filter(
        models.Permission.id == permission_id
    ).first()
    if permission is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found"
        )
    
    db.delete(permission)
    db.commit()
    return {"message": "Permission deleted successfully"}

@router.post("/users/{user_id}", response_model=schemas.UserPermission)
def create_user_permission(
    user_id: str,
    permission: schemas.UserPermissionCreate,
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
    
    # Check if permission exists
    perm = db.query(models.Permission).filter(
        models.Permission.id == permission.permission_id
    ).first()
    if not perm:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found"
        )
    
    # Check if user permission already exists
    existing_permission = db.query(models.UserPermission).filter(
        models.UserPermission.user_id == user_id,
        models.UserPermission.permission_id == permission.permission_id
    ).first()
    
    if existing_permission:
        existing_permission.value = permission.value
        db.commit()
        db.refresh(existing_permission)
        return existing_permission
    
    db_permission = models.UserPermission(
        user_id=user_id,
        permission_id=permission.permission_id,
        value=permission.value
    )
    db.add(db_permission)
    db.commit()
    db.refresh(db_permission)
    return db_permission

@router.get("/users/{user_id}", response_model=List[schemas.UserPermission])
def get_user_permissions(
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
    
    permissions = db.query(models.UserPermission).filter(
        models.UserPermission.user_id == user_id
    ).all()
    return permissions

@router.delete("/users/{user_id}/{permission_id}")
def delete_user_permission(
    user_id: str,
    permission_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    user_permission = db.query(models.UserPermission).filter(
        models.UserPermission.user_id == user_id,
        models.UserPermission.permission_id == permission_id
    ).first()
    
    if not user_permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User permission not found"
        )
    
    db.delete(user_permission)
    db.commit()
    return {"message": "User permission deleted successfully"}