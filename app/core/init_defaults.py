from sqlalchemy.orm import Session
from . import models, auth, config
import logging

logger = logging.getLogger(__name__)

def initialize_defaults(db: Session):
    """Initialize default admin user, groups, and permissions on startup"""
    
    # Check if we have admin email configured
    if not config.ADMIN_EMAIL:
        logger.warning("ADMIN_EMAIL not configured. Skipping admin user initialization.")
        # Still create groups and permissions even without admin email
        pass
    
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
        
        # 2. Create default permissions if they don't exist
        permissions_to_create = [
            # User management permissions
            {"name": "users:create", "resource": "users", "action": "create", 
             "description": "Create new users"},
            {"name": "users:read", "resource": "users", "action": "read", 
             "description": "Read user information"},
            {"name": "users:update", "resource": "users", "action": "update", 
             "description": "Update user information"},
            {"name": "users:delete", "resource": "users", "action": "delete", 
             "description": "Delete users"},
            
            # Group management permissions
            {"name": "groups:create", "resource": "groups", "action": "create", 
             "description": "Create new groups"},
            {"name": "groups:read", "resource": "groups", "action": "read", 
             "description": "Read group information"},
            {"name": "groups:update", "resource": "groups", "action": "update", 
             "description": "Update group information"},
            {"name": "groups:delete", "resource": "groups", "action": "delete", 
             "description": "Delete groups"},
            
            # Field management permissions
            {"name": "fields:create", "resource": "fields", "action": "create", 
             "description": "Create new fields"},
            {"name": "fields:read", "resource": "fields", "action": "read", 
             "description": "Read field definitions"},
            {"name": "fields:update", "resource": "fields", "action": "update", 
             "description": "Update field definitions"},
            {"name": "fields:delete", "resource": "fields", "action": "delete", 
             "description": "Delete fields"},
            
            # Field value permissions
            {"name": "field_values:set_own", "resource": "field_values", "action": "set_own", 
             "description": "Set own field values"},
            {"name": "field_values:set_any", "resource": "field_values", "action": "set_any", 
             "description": "Set field values for any user"},
            {"name": "field_values:read_own", "resource": "field_values", "action": "read_own", 
             "description": "Read own field values"},
            {"name": "field_values:read_any", "resource": "field_values", "action": "read_any", 
             "description": "Read field values for any user"},
            
            # Permission management
            {"name": "permissions:manage", "resource": "permissions", "action": "manage", 
             "description": "Manage permissions"},
        ]
        
        created_permissions = []
        for perm_data in permissions_to_create:
            permission = db.query(models.Permission).filter(
                models.Permission.name == perm_data["name"]
            ).first()
            
            if not permission:
                permission = models.Permission(**perm_data)
                db.add(permission)
                db.commit()
                db.refresh(permission)
                logger.info(f"Created permission: {perm_data['name']}")
            
            created_permissions.append(permission)
        
        # 3. Grant all permissions to Admins group
        for permission in created_permissions:
            # Check if group already has this permission
            existing_group_perm = db.query(models.GroupPermission).filter(
                models.GroupPermission.group_id == admin_group.id,
                models.GroupPermission.permission_id == permission.id
            ).first()
            
            if not existing_group_perm:
                group_permission = models.GroupPermission(
                    group_id=admin_group.id,
                    permission_id=permission.id,
                    value="granted"
                )
                db.add(group_permission)
                logger.info(f"Granted permission '{permission.name}' to Admins group")
        
        db.commit()
        
        # 4. Create or update admin user (if ADMIN_EMAIL is configured)
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
            
            # 5. Ensure admin user is in Admins group
            if admin_group not in admin_user.groups:
                admin_user.groups.append(admin_group)
                db.commit()
                logger.info(f"Added admin user to Admins group")
        
        # 6. Create default "Users" group for regular users
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
            
            # Grant basic permissions to Users group
            basic_permissions = [
                "users:read",  # Read users
                "fields:read",  # Read field definitions
                "field_values:set_own",  # Set own field values
                "field_values:read_own",  # Read own field values
            ]
            
            for perm_name in basic_permissions:
                permission = db.query(models.Permission).filter(
                    models.Permission.name == perm_name
                ).first()
                
                if permission:
                    group_permission = models.GroupPermission(
                        group_id=users_group.id,
                        permission_id=permission.id,
                        value="granted"
                    )
                    db.add(group_permission)
                    logger.info(f"Granted permission '{perm_name}' to Users group")
            
            db.commit()
        
        logger.info("Default initialization completed successfully")
        
    except Exception as e:
        logger.error(f"Error during default initialization: {e}")
        db.rollback()
        raise