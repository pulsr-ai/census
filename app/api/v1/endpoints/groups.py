from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import and_
from sqlalchemy.sql import func
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

@router.get("/{group_id}/members", response_model=List[schemas.GroupMember])
def get_group_members(
    group_id: str,
    active_only: bool = True,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    group = db.query(models.Group).filter(models.Group.id == group_id).first()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Group not found"
        )
    
    query = db.query(models.GroupMember).filter(
        models.GroupMember.group_id == group_id
    )
    
    if active_only:
        query = query.filter(models.GroupMember.active == True)
    
    members = query.order_by(models.GroupMember.added_at.desc()).all()
    return members

@router.post("/{group_id}/members", response_model=schemas.GroupMember)
def add_group_member(
    group_id: str,
    member: schemas.GroupMemberCreate,
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
    
    # Check if user exists
    user = db.query(models.User).filter(models.User.id == member.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Check if user already has active membership
    existing_membership = db.query(models.GroupMember).filter(
        and_(
            models.GroupMember.group_id == group_id,
            models.GroupMember.user_id == member.user_id,
            models.GroupMember.active == True
        )
    ).first()
    
    if existing_membership:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already an active member of this group"
        )
    
    db_member = models.GroupMember(
        group_id=group_id,
        user_id=member.user_id,
        role=member.role,
        added_by=member.added_by or current_user.id
    )
    
    db.add(db_member)
    db.commit()
    db.refresh(db_member)
    return db_member

@router.delete("/{group_id}/members/{user_id}")
def remove_group_member(
    group_id: str,
    user_id: str,
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
    
    # Find active membership
    membership = db.query(models.GroupMember).filter(
        and_(
            models.GroupMember.group_id == group_id,
            models.GroupMember.user_id == user_id,
            models.GroupMember.active == True
        )
    ).first()
    
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Active group membership not found"
        )
    
    membership.active = False
    membership.removed_at = func.now()
    membership.removed_by = current_user.id
    
    db.commit()
    return {"message": "User removed from group successfully"}

