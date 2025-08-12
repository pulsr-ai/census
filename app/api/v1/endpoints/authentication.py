from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import timedelta
from ....core import models, auth, config
from ....core.database import get_db
from .. import schemas

router = APIRouter(prefix="/auth", tags=["authentication"])

@router.post("/login", response_model=schemas.LoginResponse)
def login(
    login_request: schemas.LoginRequest,
    db: Session = Depends(get_db)
):
    """
    Universal login endpoint - EVERYONE gets OTP verification:
    1. Existing users → OTP authentication
    2. New users → Auto-create user + OTP authentication
    
    The only difference is user type (regular vs anonymous = auto-created)
    """
    normalized_email = auth.normalize_email(login_request.email)
    
    # Check if user exists
    user = db.query(models.User).filter(
        models.User.email == normalized_email
    ).first()
    
    if not user:
        # New user - create them automatically
        # Determine if they should be "anonymous" (auto-created) or regular
        is_auto_created = True  # All new users are auto-created unless manually created by admin
        user = auth.get_or_create_user(db, login_request.email, is_anonymous=is_auto_created)
        
        # If this is the ADMIN_EMAIL, add to Admins group
        if config.ADMIN_EMAIL and normalized_email == auth.normalize_email(config.ADMIN_EMAIL):
            admin_group = db.query(models.Group).filter(
                models.Group.name == "Admins"
            ).first()
            if admin_group and admin_group not in user.groups:
                user.groups.append(admin_group)
                db.commit()
    
    # EVERYONE gets OTP verification - no exceptions
    otp_session = auth.create_otp_session(db, login_request.email)
    
    return schemas.LoginResponse(
        message="OTP sent to your email",
        session_id=otp_session.id
    )

@router.post("/verify-otp", response_model=schemas.OTPVerifyResponse)
def verify_otp(
    verify_request: schemas.OTPVerifyRequest,
    db: Session = Depends(get_db)
):
    otp_session = auth.verify_otp_code(
        db, 
        str(verify_request.session_id), 
        verify_request.otp_code
    )
    
    if not otp_session:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OTP"
        )
    
    # Get or create user
    user = auth.get_or_create_user(db, otp_session.email)
    user.otp_verified = True
    db.commit()
    
    # Create access token
    access_token_expires = timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": str(user.id), "email": user.email},
        expires_delta=access_token_expires
    )
    
    return schemas.OTPVerifyResponse(
        access_token=access_token,
        token_type="bearer",
        user=user
    )


@router.post("/refresh-token", response_model=schemas.Token)
def refresh_token(
    current_user: models.User = Depends(auth.get_current_active_user)
):
    access_token_expires = timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": str(current_user.id), "email": current_user.email},
        expires_delta=access_token_expires
    )
    
    return schemas.Token(
        access_token=access_token,
        token_type="bearer"
    )

@router.post("/logout")
def logout(
    current_user: models.User = Depends(auth.get_current_active_user)
):
    return {"message": "Successfully logged out"}

