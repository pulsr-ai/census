from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from ....core import models, auth
from ....core.database import get_db
from .. import schemas

router = APIRouter(prefix="/groups", tags=["groups"])

@router.post("/", response_model=schemas.Group)
def create_group(
    group: schemas.GroupCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    existing_group = db.query(models.Group).filter(
        models.Group.name == group.name
    ).first()
    
    if existing_group:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Group name already exists"
        )
    
    db_group = models.Group(
        name=group.name,
        description=group.description,
        email_domain=group.email_domain.lower() if group.email_domain else None,
        allow_anonymous=group.allow_anonymous
    )
    db.add(db_group)
    db.commit()
    db.refresh(db_group)
    return db_group

@router.get("/", response_model=List[schemas.Group])
def read_groups(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    groups = db.query(models.Group).offset(skip).limit(limit).all()
    return groups

@router.get("/{group_id}", response_model=schemas.Group)
def read_group(
    group_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if group is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Group not found"
        )
    return group

@router.put("/{group_id}", response_model=schemas.Group)
def update_group(
    group_id: str,
    group_update: schemas.GroupUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if group is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Group not found"
        )
    
    update_data = group_update.model_dump(exclude_unset=True)
    
    if "name" in update_data:
        existing_group = db.query(models.Group).filter(
            models.Group.name == update_data["name"],
            models.Group.id != group_id
        ).first()
        
        if existing_group:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Group name already exists"
            )
    
    if "email_domain" in update_data and update_data["email_domain"]:
        update_data["email_domain"] = update_data["email_domain"].lower()
    
    for field, value in update_data.items():
        setattr(group, field, value)
    
    db.commit()
    db.refresh(group)
    return group

@router.delete("/{group_id}")
def delete_group(
    group_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if group is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Group not found"
        )
    
    db.delete(group)
    db.commit()
    return {"message": "Group deleted successfully"}

@router.get("/{group_id}/users", response_model=List[schemas.User])
def get_group_users(
    group_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Group not found"
        )
    
    return group.users

@router.post("/{group_id}/permissions", response_model=schemas.GroupPermission)
def create_group_permission(
    group_id: str,
    permission: schemas.GroupPermissionCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    # Check if group exists
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Group not found"
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
    
    # Check if group permission already exists
    existing_permission = db.query(models.GroupPermission).filter(
        models.GroupPermission.group_id == group_id,
        models.GroupPermission.permission_id == permission.permission_id
    ).first()
    
    if existing_permission:
        existing_permission.value = permission.value
        db.commit()
        db.refresh(existing_permission)
        return existing_permission
    
    db_permission = models.GroupPermission(
        group_id=group_id,
        permission_id=permission.permission_id,
        value=permission.value
    )
    db.add(db_permission)
    db.commit()
    db.refresh(db_permission)
    return db_permission

@router.get("/{group_id}/permissions", response_model=List[schemas.GroupPermission])
def get_group_permissions(
    group_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Group not found"
        )
    
    permissions = db.query(models.GroupPermission).filter(
        models.GroupPermission.group_id == group_id
    ).all()
    return permissions

@router.delete("/{group_id}/permissions/{permission_id}")
def delete_group_permission(
    group_id: str,
    permission_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    group_permission = db.query(models.GroupPermission).filter(
        models.GroupPermission.group_id == group_id,
        models.GroupPermission.permission_id == permission_id
    ).first()
    
    if not group_permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Group permission not found"
        )
    
    db.delete(group_permission)
    db.commit()
    return {"message": "Group permission deleted successfully"}