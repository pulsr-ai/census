from sqlalchemy.orm import Session
from . import models, auth, config
import logging

logger = logging.getLogger(__name__)

def initialize_defaults(db: Session):
    """Initialize default admin user and groups on startup (permissions now handled by microservices)"""
    
    # Check if we have admin email configured
    if not config.ADMIN_EMAIL:
        logger.warning("ADMIN_EMAIL not configured. Skipping admin user initialization.")
    
    try:
        # 1. Create or get Admins group
        admin_group = db.query(models.Group).filter(
            models.Group.name == "Admins"
        ).first()
        
        if not admin_group:
            admin_group = models.Group(
                name="Admins",
                description="System administrators with full access",
                allow_anonymous=False
            )
            db.add(admin_group)
            db.commit()
            db.refresh(admin_group)
            logger.info("Created 'Admins' group")
        
        # 2. Create or update admin user (if ADMIN_EMAIL is configured)
        if config.ADMIN_EMAIL:
            normalized_email = auth.normalize_email(config.ADMIN_EMAIL)
            admin_user = db.query(models.User).filter(
                models.User.email == normalized_email
            ).first()
            
            if not admin_user:
                # Create admin user
                admin_user = models.User(
                    email=normalized_email,
                    is_active=True,
                    is_anonymous=False,
                    otp_verified=False  # Admin also needs OTP verification like everyone else
                )
                
                db.add(admin_user)
                db.commit()
                db.refresh(admin_user)
                logger.info(f"Created admin user: {config.ADMIN_EMAIL}")
            
            # 3. Ensure admin user is in Admins group using new GroupMember model
            existing_membership = db.query(models.GroupMember).filter(
                models.GroupMember.user_id == admin_user.id,
                models.GroupMember.group_id == admin_group.id,
                models.GroupMember.active == True
            ).first()
            
            if not existing_membership:
                group_member = models.GroupMember(
                    user_id=admin_user.id,
                    group_id=admin_group.id,
                    role="admin",
                    active=True,
                    added_by=admin_user.id  # Self-assigned
                )
                db.add(group_member)
                db.commit()
                logger.info(f"Added admin user to Admins group")
        
        # 4. Create default "Users" group for regular users
        users_group = db.query(models.Group).filter(
            models.Group.name == "Users"
        ).first()
        
        if not users_group:
            users_group = models.Group(
                name="Users",
                description="Regular users with basic permissions",
                allow_anonymous=False
            )
            db.add(users_group)
            db.commit()
            db.refresh(users_group)
            logger.info("Created 'Users' group")
        
        logger.info("Default initialization completed successfully (permissions now handled by microservices)")
        
    except Exception as e:
        logger.error(f"Error during default initialization: {e}")
        db.rollback()
        raise