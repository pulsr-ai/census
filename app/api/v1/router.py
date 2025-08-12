from fastapi import APIRouter

from .endpoints import authentication, users, groups, permissions, fields

api_router = APIRouter()
api_router.include_router(authentication.router)
api_router.include_router(users.router)
api_router.include_router(groups.router)
api_router.include_router(permissions.router)
api_router.include_router(fields.router)