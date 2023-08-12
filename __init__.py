from flask import Flask
import redis
import os
from dotenv import load_dotenv
from Routes.auth.auth import bp as auth_bp
from App_Extensions import Extensions
from flask_limiter.util import get_remote_address



def create_app():
    return Flask(
        __name__,
        static_folder="static",
        static_url_path="/static",
    )


def _configure_app(app):
    # load the environment variables

    # Set the secret key to some random bytes. Keep this really secret!
    app.secret_key = os.getenv("APP_SECRET_KEY")
    # set the app salt
    APP_SALT = os.getenv("APP_SALT").encode("utf-8")
    # configure the PogreSQL database URI
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URI")
    # prevent cookie tampering
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    # prevent XSS attacks
    app.config["SESSION_COOKIE_SECURE"] = True
    # prevent CSRF attacks
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"

    return app


if __name__ == "__main__":
    # load the environment variables
    load_dotenv(".env")
    Extensions.app = _configure_app(
        Flask(__name__, static_folder="static", static_url_path="/static")
    )

    with Extensions.app.app_context():
        #
        from Models import User

        Extensions.db.init_app(Extensions.app)
        Extensions.db.create_all()

    # Extensions.db.create_all()
    Extensions.redis_db = redis.Redis(
        host=str(os.getenv("REDIS_HOST")),
        port=int(os.getenv("REDIS_PORT")),
        db=0,
        decode_responses=True,
    )

    Extensions.app.register_blueprint(auth_bp)
    Extensions.app.run(debug=True)
