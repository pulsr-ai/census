import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
OTP_EXPIRE_MINUTES = int(os.getenv("OTP_EXPIRE_MINUTES", "5"))
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")

# Hermes email service configuration
HERMES_BASE = os.getenv("HERMES_BASE")
HERMES_API_KEY = os.getenv("HERMES_API_KEY") 
HERMES_FROM_EMAIL = os.getenv("HERMES_FROM_EMAIL")