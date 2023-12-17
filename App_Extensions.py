from flask_sqlalchemy import SQLAlchemy
import redis
from dotenv import load_dotenv
from flask import Flask
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address



load_dotenv(".env")


# Database Initializations
# in a seperate file to avoid circular imports
# and to make it accessible from everywhere
class Extensions:
    app: Flask | None = None
    db: SQLAlchemy | None = SQLAlchemy(app)
    redis_db: redis.Redis | None = None
    auth_limiter: Limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=f'{os.getenv("REDIS_STORAGE_URI")}',
)
