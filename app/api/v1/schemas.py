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

class GroupMemberBase(BaseModel):
    role: Optional[str] = None

class GroupMemberCreate(GroupMemberBase):
    user_id: UUID4
    added_by: Optional[UUID4] = None

class GroupMember(GroupMemberBase):
    id: UUID4
    group_id: UUID4
    user_id: UUID4
    added_at: datetime
    added_by: Optional[UUID4] = None
    active: bool
    removed_at: Optional[datetime] = None
    removed_by: Optional[UUID4] = None

    class Config:
        from_attributes = True

class UserServiceSubtenantBase(BaseModel):
    service: str
    subtenant_id: str

class UserServiceSubtenantCreate(UserServiceSubtenantBase):
    user_id: UUID4
    granted_by: Optional[UUID4] = None

class UserServiceSubtenantGrant(UserServiceSubtenantBase):
    granted_by: Optional[UUID4] = None

class UserServiceSubtenant(UserServiceSubtenantBase):
    id: UUID4
    user_id: UUID4
    granted_at: datetime
    granted_by: Optional[UUID4] = None
    active: bool
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[UUID4] = None

    class Config:
        from_attributes = True

class UserAccessCheck(BaseModel):
    has_access: bool
    access_details: Optional[UserServiceSubtenant] = None

class UserGroupSummary(BaseModel):
    group_id: UUID4
    group_name: str
    role: Optional[str] = None
    added_at: datetime
    active: bool

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
    field_values: List[FieldValue] = []
    group_memberships: List[GroupMember] = []
    service_access: List[UserServiceSubtenant] = []

    class Config:
        from_attributes = True