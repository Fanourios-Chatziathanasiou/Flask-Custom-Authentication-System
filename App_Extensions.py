from flask_sqlalchemy import SQLAlchemy
import redis
import os
from dotenv import load_dotenv
from flask import Flask


load_dotenv(".env")


# Database Initializations
# in a seperate file to avoid circular imports
# and to make it accessible from everywhere
class Extensions:
    app: Flask | None = None
    db: SQLAlchemy | None = SQLAlchemy(app)
    redis_db: redis.Redis | None = None

    CONTENT_SECURITY_POLICY = {
        "default-src": "'self'",
        "script-src": ["'self'", os.getenv("HOST_URL") + "/js/"],
        "style-src": ["'self'", os.getenv("HOST_URL") + "/css/"],
    }
    auth_limiter = None
