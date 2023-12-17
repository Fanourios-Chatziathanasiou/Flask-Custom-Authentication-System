from flask import Flask
import redis
import os
from dotenv import load_dotenv
from Routes.auth.auth import bp as auth_bp
from App_Extensions import Extensions




def create_app():
    return Flask(
        __name__,
        static_folder="static",
        static_url_path="/static",
    )


def _configure_app(app):
    # load the environment variables

    # Set the secret key. Keep this really secret!
    app.secret_key = os.getenv("APP_SECRET_KEY")
    # configure the PostgreSQL database URI
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URI")
    # prevent cookie tampering
    app.config["SESSION_COOKIE_HTTPONLY"] =True if os.getenv("SESSION_COOKIE_HTTPONLY")=="True" else False
    # prevent XSS attacks
    app.config["SESSION_COOKIE_SECURE"] = True if os.getenv("SESSION_COOKIE_SECURE")=="True" else False
    # prevent CSRF attacks
    app.config["SESSION_COOKIE_SAMESITE"] =True if  os.getenv("SESSION_COOKIE_SAMESITE")=="True" else False
    Extensions.auth_limiter.init_app(app)

    return app


if __name__ == "__main__":
    # load the environment variables
    load_dotenv(".env")
    Extensions.app = _configure_app(
        Flask(__name__, static_folder="static", static_url_path="/static")
    )

    # Setup SQLAlchemy db
    with Extensions.app.app_context():

        Extensions.db.init_app(Extensions.app)
        Extensions.db.create_all()

    # Setup redis db
    Extensions.redis_db = redis.Redis(
        host=str(os.getenv("REDIS_HOST")),
        port=int(os.getenv("REDIS_PORT")),
        db=0,
        decode_responses=True,
    )

    Extensions.app.register_blueprint(auth_bp)
    Extensions.app.run(debug=True)
