from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import pyotp
import random
import string
import requests
import logging
from . import models, config
from ..api.v1 import schemas
from .database import get_db

logger = logging.getLogger(__name__)

security = HTTPBearer()

def normalize_email(email: str) -> str:
    return email.lower().strip()

def generate_otp_code(length: int = 6) -> str:
    return ''.join(random.choices(string.digits, k=length))

def send_otp_email(email: str, otp_code: str) -> bool:
    """Send OTP code via Hermes email service"""
    
    # Check if Hermes is configured
    if not all([config.HERMES_BASE, config.HERMES_API_KEY, config.HERMES_FROM_EMAIL]):
        logger.warning("Hermes email service not configured - printing OTP to console")
        print(f"OTP Code for {email}: {otp_code}")
        return True
    
    try:
        # Prepare email content
        subject = "Your Login Code"
        html_content = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #333;">Your Login Code</h2>
            <p>Hello,</p>
            <p>Your login verification code is:</p>
            <div style="background-color: #f8f9fa; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px;">
                <h1 style="color: #007bff; font-size: 32px; margin: 0; letter-spacing: 8px;">{otp_code}</h1>
            </div>
            <p>This code will expire in {config.OTP_EXPIRE_MINUTES} minutes.</p>
            <p>If you didn't request this code, please ignore this email.</p>
            <p>Best regards,<br>Census Team</p>
        </div>
        """
        
        text_content = f"""
Your Login Code

Hello,

Your login verification code is: {otp_code}

This code will expire in {config.OTP_EXPIRE_MINUTES} minutes.

If you didn't request this code, please ignore this email.

Best regards,
Census Team
        """
        
        # Send email via Hermes
        hermes_url = f"{config.HERMES_BASE.rstrip('/')}/api/v1/emails/send"
        headers = {
            "X-API-Key": config.HERMES_API_KEY,
            "Content-Type": "application/json"
        }
        
        payload = {
            "to_email": email,
            "from_email": config.HERMES_FROM_EMAIL,
            "subject": subject,
            "html_content": html_content,
            "text_content": text_content
        }
        
        response = requests.post(hermes_url, json=payload, headers=headers, timeout=10)
        
        if response.status_code == 200:
            logger.info(f"OTP email sent successfully to {email}")
            return True
        else:
            logger.error(f"Failed to send OTP email to {email}: {response.status_code} - {response.text}")
            # Fallback to console logging
            print(f"OTP Code for {email}: {otp_code}")
            return True
            
    except requests.RequestException as e:
        logger.error(f"Error sending OTP email to {email}: {e}")
        # Fallback to console logging
        print(f"OTP Code for {email}: {otp_code}")
        return True
    except Exception as e:
        logger.error(f"Unexpected error sending OTP email to {email}: {e}")
        # Fallback to console logging
        print(f"OTP Code for {email}: {otp_code}")
        return True

def create_otp_session(db: Session, email: str) -> models.OTPSession:
    otp_code = generate_otp_code()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=config.OTP_EXPIRE_MINUTES)
    
    # Delete any existing OTP sessions for this email
    db.query(models.OTPSession).filter(
        models.OTPSession.email == normalize_email(email)
    ).delete()
    
    otp_session = models.OTPSession(
        email=normalize_email(email),
        otp_code=otp_code,
        expires_at=expires_at
    )
    db.add(otp_session)
    db.commit()
    db.refresh(otp_session)
    
    # Send OTP email
    send_otp_email(email, otp_code)
    
    return otp_session

def verify_otp_code(db: Session, session_id: str, otp_code: str) -> Optional[models.OTPSession]:
    otp_session = db.query(models.OTPSession).filter(
        models.OTPSession.id == session_id,
        models.OTPSession.verified == False,
        models.OTPSession.expires_at > datetime.now(timezone.utc)
    ).first()
    
    if not otp_session:
        return None
    
    if otp_session.otp_code == otp_code:
        otp_session.verified = True
        db.commit()
        return otp_session
    
    return None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, config.SECRET_KEY, algorithm=config.ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> schemas.TokenData:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(credentials.credentials, config.SECRET_KEY, algorithms=[config.ALGORITHM])
        user_id: str = payload.get("sub")
        email: str = payload.get("email")
        if user_id is None:
            raise credentials_exception
        token_data = schemas.TokenData(user_id=user_id, email=email)
    except JWTError:
        raise credentials_exception
    
    return token_data

def get_current_user(token_data: schemas.TokenData = Depends(verify_token), 
                     db: Session = Depends(get_db)) -> models.User:
    user = db.query(models.User).filter(models.User.id == token_data.user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    return user

def get_current_active_user(current_user: models.User = Depends(get_current_user)) -> models.User:
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user

def get_or_create_user(db: Session, email: str, is_anonymous: bool = False) -> models.User:
    normalized_email = normalize_email(email)
    
    user = db.query(models.User).filter(
        models.User.email == normalized_email
    ).first()
    
    if user:
        return user
    
    # Create new user
    user = models.User(
        email=normalized_email,
        is_anonymous=is_anonymous,
        otp_verified=False  # All users need OTP verification
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Auto-create and assign domain-based group for all new users
    email_domain = email.split('@')[1].lower()
    
    # Check if domain group already exists
    domain_group = db.query(models.Group).filter(
        models.Group.email_domain == email_domain
    ).first()
    
    # If no domain group exists, create one
    if not domain_group:
        domain_group = models.Group(
            name=email_domain,
            description=f"Auto-created group for {email_domain} domain",
            email_domain=email_domain,
            allow_anonymous=False  # Domain groups don't bypass security
        )
        db.add(domain_group)
        db.commit()
        db.refresh(domain_group)
        
        db.commit()
    
    # Add user to the domain group using new GroupMember model
    existing_membership = db.query(models.GroupMember).filter(
        models.GroupMember.user_id == user.id,
        models.GroupMember.group_id == domain_group.id,
        models.GroupMember.active == True
    ).first()
    
    if not existing_membership:
        group_member = models.GroupMember(
            user_id=user.id,
            group_id=domain_group.id,
            role="member",
            active=True,
            added_by=user.id  # Self-assigned
        )
        db.add(group_member)
        db.commit()
    
    return user


def is_admin(db: Session, user: models.User) -> bool:
    """Check if user is in the Admins group using new GroupMember model"""
    admin_membership = db.query(models.GroupMember).join(
        models.Group, models.GroupMember.group_id == models.Group.id
    ).filter(
        models.GroupMember.user_id == user.id,
        models.Group.name == "Admins",
        models.GroupMember.active == True
    ).first()
    
    return admin_membership is not None