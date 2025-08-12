from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
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
    
    # Check permissions: users can only set their own fields unless they have set_any permission
    if str(current_user.id) != user_id:
        if not auth.check_user_permission(db, current_user, "field_values:set_any"):
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