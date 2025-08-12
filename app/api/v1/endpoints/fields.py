from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from ....core import models, auth
from ....core.database import get_db
from .. import schemas

router = APIRouter(prefix="/fields", tags=["fields"])

@router.post("/", response_model=schemas.Field)
def create_field(
    field: schemas.FieldCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    existing_field = db.query(models.Field).filter(
        models.Field.name == field.name
    ).first()
    
    if existing_field:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Field name already exists"
        )
    
    db_field = models.Field(
        name=field.name,
        field_type=field.field_type,
        description=field.description,
        is_required=field.is_required,
        default_value=field.default_value
    )
    db.add(db_field)
    db.commit()
    db.refresh(db_field)
    return db_field

@router.get("/", response_model=List[schemas.Field])
def read_fields(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    fields = db.query(models.Field).offset(skip).limit(limit).all()
    return fields

@router.get("/{field_id}", response_model=schemas.Field)
def read_field(
    field_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    field = db.query(models.Field).filter(models.Field.id == field_id).first()
    if field is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Field not found"
        )
    return field

@router.put("/{field_id}", response_model=schemas.Field)
def update_field(
    field_id: str,
    field_update: schemas.FieldUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    field = db.query(models.Field).filter(models.Field.id == field_id).first()
    if field is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Field not found"
        )
    
    update_data = field_update.model_dump(exclude_unset=True)
    
    if "name" in update_data:
        existing_field = db.query(models.Field).filter(
            models.Field.name == update_data["name"],
            models.Field.id != field_id
        ).first()
        
        if existing_field:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Field name already exists"
            )
    
    for field_name, value in update_data.items():
        setattr(field, field_name, value)
    
    db.commit()
    db.refresh(field)
    return field

@router.delete("/{field_id}")
def delete_field(
    field_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    field = db.query(models.Field).filter(models.Field.id == field_id).first()
    if field is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Field not found"
        )
    
    db.delete(field)
    db.commit()
    return {"message": "Field deleted successfully"}

@router.put("/by-name/{field_name}", response_model=schemas.Field)
def update_or_create_field_by_name(
    field_name: str,
    field_update: schemas.FieldUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    # Try to find existing field by name
    field = db.query(models.Field).filter(models.Field.name == field_name).first()
    
    update_data = field_update.model_dump(exclude_unset=True)
    
    if field:
        # Update existing field
        for field_attr, value in update_data.items():
            setattr(field, field_attr, value)
        
        db.commit()
        db.refresh(field)
        return field
    else:
        # Create new field if it doesn't exist
        # field_type is required for new fields, so set a default if not provided
        if "field_type" not in update_data:
            update_data["field_type"] = "text"  # Default field type
        
        db_field = models.Field(
            name=field_name,
            field_type=update_data.get("field_type", "text"),
            description=update_data.get("description"),
            is_required=update_data.get("is_required", False),
            default_value=update_data.get("default_value")
        )
        db.add(db_field)
        db.commit()
        db.refresh(db_field)
        return db_field