from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text, Table, UUID as SQLAlchemyUUID, Index
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func
import uuid

Base = declarative_base()


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

    field_values = relationship("FieldValue", back_populates="user", cascade="all, delete-orphan")
    group_memberships = relationship("GroupMember", back_populates="user", foreign_keys="GroupMember.user_id", cascade="all, delete-orphan")
    service_access = relationship("UserServiceSubtenant", back_populates="user", foreign_keys="UserServiceSubtenant.user_id", cascade="all, delete-orphan")

class Group(Base):
    __tablename__ = "groups"

    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    email_domain = Column(String, nullable=True, index=True)
    allow_anonymous = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    members = relationship("GroupMember", back_populates="group", cascade="all, delete-orphan")

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

class GroupMember(Base):
    __tablename__ = "group_members"

    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    group_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("groups.id"), nullable=False)
    user_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    role = Column(String, nullable=True)  # Optional role within the group
    added_at = Column(DateTime(timezone=True), server_default=func.now())
    added_by = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    active = Column(Boolean, default=True, nullable=False)
    removed_at = Column(DateTime(timezone=True), nullable=True)
    removed_by = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    group = relationship("Group", back_populates="members")
    user = relationship("User", back_populates="group_memberships", foreign_keys=[user_id])
    added_by_user = relationship("User", foreign_keys=[added_by], post_update=True)
    removed_by_user = relationship("User", foreign_keys=[removed_by], post_update=True)

class UserServiceSubtenant(Base):
    __tablename__ = "user_service_subtenants"
    __table_args__ = (
        # Partial unique index: only one active service access per user per service
        Index('ix_user_service_active_unique', 'user_id', 'service', 
              unique=True, postgresql_where=Column('active') == True),
        {'extend_existing': True}
    )

    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    service = Column(String, nullable=False, index=True)
    subtenant_id = Column(String, nullable=False, index=True)
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    granted_by = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    active = Column(Boolean, default=True, nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_by = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    user = relationship("User", back_populates="service_access", foreign_keys=[user_id])
    granted_by_user = relationship("User", foreign_keys=[granted_by], post_update=True)
    revoked_by_user = relationship("User", foreign_keys=[revoked_by], post_update=True)

class OTPSession(Base):
    __tablename__ = "otp_sessions"

    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    email = Column(String, index=True, nullable=False)
    otp_code = Column(String, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())