from pydantic import BaseModel, EmailStr, UUID4
from typing import Optional, List
from datetime import datetime

class UserBase(BaseModel):
    email: EmailStr
    is_active: Optional[bool] = True
    is_anonymous: Optional[bool] = False

class UserCreate(UserBase):
    pass

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    is_active: Optional[bool] = None

class User(UserBase):
    id: UUID4
    otp_verified: bool
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class GroupBase(BaseModel):
    name: str
    description: Optional[str] = None
    email_domain: Optional[str] = None
    allow_anonymous: Optional[bool] = False

class GroupCreate(GroupBase):
    pass

class GroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    email_domain: Optional[str] = None
    allow_anonymous: Optional[bool] = None

class Group(GroupBase):
    id: UUID4
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class FieldBase(BaseModel):
    name: str
    field_type: str
    description: Optional[str] = None
    is_required: Optional[bool] = False
    default_value: Optional[str] = None

class FieldCreate(FieldBase):
    pass

class FieldUpdate(BaseModel):
    name: Optional[str] = None
    field_type: Optional[str] = None
    description: Optional[str] = None
    is_required: Optional[bool] = None
    default_value: Optional[str] = None

class Field(FieldBase):
    id: UUID4
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class FieldValueBase(BaseModel):
    value: Optional[str] = None

class FieldValueCreate(FieldValueBase):
    field_id: UUID4

class FieldValueUpdate(FieldValueBase):
    pass

class FieldValue(FieldValueBase):
    id: UUID4
    user_id: UUID4
    field_id: UUID4
    created_at: datetime
    updated_at: Optional[datetime] = None
    field: Optional[Field] = None

    class Config:
        from_attributes = True

class PermissionBase(BaseModel):
    name: str
    description: Optional[str] = None
    resource: str
    action: str

class PermissionCreate(PermissionBase):
    pass

class Permission(PermissionBase):
    id: UUID4
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class UserPermissionBase(BaseModel):
    value: Optional[str] = None

class UserPermissionCreate(UserPermissionBase):
    permission_id: UUID4

class UserPermission(UserPermissionBase):
    id: UUID4
    user_id: UUID4
    permission_id: UUID4
    granted_at: datetime
    permission: Optional[Permission] = None

    class Config:
        from_attributes = True

class GroupPermissionBase(BaseModel):
    value: Optional[str] = None

class GroupPermissionCreate(GroupPermissionBase):
    permission_id: UUID4

class GroupPermission(GroupPermissionBase):
    id: UUID4
    group_id: UUID4
    permission_id: UUID4
    granted_at: datetime
    permission: Optional[Permission] = None

    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    email: EmailStr

class LoginResponse(BaseModel):
    message: str
    session_id: Optional[UUID4] = None
    access_token: Optional[str] = None
    token_type: Optional[str] = None
    user: Optional[User] = None

class OTPVerifyRequest(BaseModel):
    session_id: UUID4
    otp_code: str

class OTPVerifyResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: User

class AnonymousLoginRequest(BaseModel):
    email: EmailStr


class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: Optional[UUID4] = None
    email: Optional[str] = None

class UserWithDetails(User):
    groups: List[Group] = []
    field_values: List[FieldValue] = []
    user_permissions: List[UserPermission] = []

    class Config:
        from_attributes = True