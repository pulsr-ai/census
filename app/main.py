from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .core import models
from .core.database import engine, SessionLocal
from .core.init_defaults import initialize_defaults
from .api.v1.router import api_router
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    # Create all tables
    models.Base.metadata.create_all(bind=engine)
    
    # Initialize defaults
    db = SessionLocal()
    try:
        initialize_defaults(db)
        logger.info("Application startup completed")
    finally:
        db.close()
    
    yield
    
    # Shutdown (if needed)
    logger.info("Application shutdown")

app = FastAPI(
    title="Census User Management API",
    description="A FastAPI-based user management and OTP authentication service",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure based on your needs
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router with prefix
app.include_router(api_router, prefix="/api/v1")

@app.get("/")
def read_root():
    return {"message": "Welcome to Census User Management API"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)