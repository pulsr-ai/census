from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text, Table, UUID as SQLAlchemyUUID
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func
import uuid

Base = declarative_base()

user_groups = Table(
    'user_groups',
    Base.metadata,
    Column('user_id', SQLAlchemyUUID(as_uuid=True), ForeignKey('users.id'), primary_key=True),
    Column('group_id', SQLAlchemyUUID(as_uuid=True), ForeignKey('groups.id'), primary_key=True)
)

class User(Base):
    __tablename__ = "users"

    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    is_active = Column(Boolean, default=True)
    is_anonymous = Column(Boolean, default=False)
    otp_secret = Column(String, nullable=True)
    otp_verified = Column(Boolean, default=False)
    last_otp_used = Column(DateTime, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    groups = relationship("Group", secondary=user_groups, back_populates="users")
    field_values = relationship("FieldValue", back_populates="user", cascade="all, delete-orphan")
    user_permissions = relationship("UserPermission", back_populates="user", cascade="all, delete-orphan")

class Group(Base):
    __tablename__ = "groups"

    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    email_domain = Column(String, nullable=True, index=True)
    allow_anonymous = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    users = relationship("User", secondary=user_groups, back_populates="groups")
    group_permissions = relationship("GroupPermission", back_populates="group", cascade="all, delete-orphan")

class Field(Base):
    __tablename__ = "fields"

    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    field_type = Column(String, nullable=False)  # text, number, boolean, date, etc.
    description = Column(Text, nullable=True)
    is_required = Column(Boolean, default=False)
    default_value = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    field_values = relationship("FieldValue", back_populates="field", cascade="all, delete-orphan")

class FieldValue(Base):
    __tablename__ = "field_values"

    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    field_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("fields.id"), nullable=False)
    value = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    user = relationship("User", back_populates="field_values")
    field = relationship("Field", back_populates="field_values")

class Permission(Base):
    __tablename__ = "permissions"

    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    resource = Column(String, nullable=False)  # users, groups, fields, etc.
    action = Column(String, nullable=False)    # create, read, update, delete, etc.
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    user_permissions = relationship("UserPermission", back_populates="permission", cascade="all, delete-orphan")
    group_permissions = relationship("GroupPermission", back_populates="permission", cascade="all, delete-orphan")

class UserPermission(Base):
    __tablename__ = "user_permissions"

    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    permission_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("permissions.id"), nullable=False)
    value = Column(Text, nullable=True)  # Permission-specific value or metadata
    granted_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="user_permissions")
    permission = relationship("Permission", back_populates="user_permissions")

class GroupPermission(Base):
    __tablename__ = "group_permissions"

    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    group_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("groups.id"), nullable=False)
    permission_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("permissions.id"), nullable=False)
    value = Column(Text, nullable=True)  # Permission-specific value or metadata
    granted_at = Column(DateTime(timezone=True), server_default=func.now())

    group = relationship("Group", back_populates="group_permissions")
    permission = relationship("Permission", back_populates="group_permissions")

class OTPSession(Base):
    __tablename__ = "otp_sessions"

    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    email = Column(String, index=True, nullable=False)
    otp_code = Column(String, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())