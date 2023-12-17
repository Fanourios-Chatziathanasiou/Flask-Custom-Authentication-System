from flask import Blueprint, Response
from flask import request, redirect, url_for, make_response, render_template
from datetime import timedelta
import datetime
import os
from dotenv import load_dotenv
from App_Extensions import Extensions
from middleware.auth.auth_middleware import (
    require_login,
)
from utils import Utils
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from Routes.auth.auth_utils.auth_utils import (
    checkUserExistsInSessions,
    generate_AuthCookies,
    storeSessionInRedis,
)
from Models import User


load_dotenv(".env")
APP_SALT = os.getenv("APP_SALT").encode("utf-8")


bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/",
)
# make the rate limiter stored in redis db
Extensions.auth_limiter = Limiter(
    get_remote_address,
    app=Extensions.app,
    default_limits=["200 per day", "100 per hour"],
    storage_uri=os.getenv("REDIS_STORAGE_URI"),
)


@bp.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@bp.route("/", methods=["GET"])
@require_login
def index() -> Response | str:
    if checkUserExistsInSessions(request=request):
        username = Extensions.redis_db.hget(
            f"{os.getenv('SESSION_COOKIE_PREFIX')}:{request.cookies.get('session')}",
            "username",
        )
        user: User = User.findUserWithUsernameOrEmail(usernameOrEmail=username)
        return f'Logged in !!! <a href="/logout">   Logout</a> <br> Username :{user.username} <br> Email : {user.email} <br> created_at = {user.created_at.strftime("%d/%m/%Y, %H:%M:%S")}'
    return redirect(url_for("auth.login"))


@bp.route("/login", methods=["GET", "POST"])
@Extensions.auth_limiter.limit("100 per hour")
def login() -> Response:
    messages = []
    if request.method == "POST":
        # sanitize the username and password
        # for possible XSS attacks
        sanitized_username = Utils.escape_output(request.form["usernameOrEmail"])
        sanitized_password = Utils.escape_output(request.form["password"])
        # check if the user exists in the database by username or email

        if sanitized_password == "" or sanitized_username == "":
            messages.append("ERROR: please provide all the required fields to login!")
            return render_template("./login/login.html", context={"messages": messages})

        user = User.findUserWithUsernameOrEmail(sanitized_username)

        # Check if the user exists in the database
        # if the user exists in the database, check if the password matches the hashed password in the database
        if (
            user is None
            or Utils.check_password(sanitized_password, user.password) == False
        ):
            messages.append(
                "ERROR: The provided credentials do not match the records in our database!"
            )
            return render_template("./login/login.html", context={"messages": messages})
        # if the password matches the hashed password in the database
        # generate the session key and the session id
        resp = make_response(redirect(url_for("auth.index")))
        session_key = Utils.generate_StrongSecretKey()
        s_id = Utils.generate_StrongSecretKey()

        cookies_result = generate_AuthCookies(
            request=request,
            resp=resp,
            session_key=session_key,
            s_id=s_id,
            username=sanitized_username,
        )
        redis_result = storeSessionInRedis(
            session_key=session_key, s_id=s_id, username=sanitized_username
        )
        # if the cookies and redis db were set successfully
        if cookies_result == True and redis_result == True:
            # redirect to the index page
            return resp
        else:
            # 401 is the proper response code to send when a failed login has happened.
            # 401 Unauthorized Similar to 403 Forbidden, but specifically for use when
            # authentication is required and has failed or has not yet been provided.
            messages.append(
                "ERROR: Something went wrong while trying to log you in. Please try again later. Code: 401"
            )
            return make_response(
                render_template("./login/login.html", context={"messages": messages})
            )
    if request.method == "GET":
        if (
            request.cookies.get(os.getenv("SESSION_COOKIE_PREFIX")) not in [None, ""]
        ) and (
            request.cookies.get(os.getenv("SESSION_COOKIE_ID_PREFIX")) not in [None, ""]
        ):
            if checkUserExistsInSessions(request=request):
                return redirect(url_for("auth.index"))
        csrf_token = Utils.generate_StrongSecretKey()
        resp = make_response(
            render_template(
                "./login/login.html",
                csrf_token=csrf_token,
                error=None,
                context={"messages": messages},
            )
        )
        resp.headers["Content-Security-Policy"] = ";".join(
            [
                f"{key} {value}"
                for key, value in Extensions.CONTENT_SECURITY_POLICY.items()
            ]
        )

        # store the csrf tokens in redis db
        Extensions.redis_db.set(
            f"{os.getenv('CSRF_PREFIX')}:{csrf_token}",
            csrf_token,
            ex=timedelta(minutes=5),
        )
        return resp


@bp.route("/logout", methods=["GET"])
def logout() -> Response:
    # clear the cookie session
    resp = make_response(redirect(url_for("auth.index")))
    resp.headers["Content-Security-Policy"] = ";".join(
        [f"{key} {value}" for key, value in Extensions.CONTENT_SECURITY_POLICY.items()]
    )

    # check if there's a session cookie
    if os.getenv("SESSION_COOKIE_PREFIX") in request.cookies:
        # get the session cookie
        session_cookie = request.cookies.get(os.getenv("SESSION_COOKIE_PREFIX"))
        # check if the session exists in redis db
        session_title = f"{os.getenv('SESSION_COOKIE_PREFIX')}:{session_cookie}"
        if Extensions.redis_db.exists(session_title):
            # remove the session from redis db
            Extensions.redis_db.delete(session_title)
        # clear the cookie named session

        resp.set_cookie(
            os.getenv("SESSION_COOKIE_PREFIX"), "", expires=datetime.datetime.now()
        )
        resp.set_cookie(
            os.getenv("SESSION_COOKIE_ID_PREFIX"), "", expires=datetime.datetime.now()
        )

    return resp


@bp.route("/register", methods=["GET", "POST"])
@Extensions.auth_limiter.limit("100 per hour")
def register() -> Response:
    resp: Response | None = None
    register_template_path = "./register/register.html"
    messages: list[str] = []
    # check if the user reloaded the page to prevent form resubmission
    if request.method == "POST":
        # sanitize the username and password and email fields
        # for possible XSS attacks
        sanitized_username = Utils.escape_output(request.form["username"])
        sanitized_password = Utils.escape_output(request.form["password"])
        sanitized_email = Utils.escape_output(request.form["email"])

        csrf_token = Utils.generate_StrongSecretKey()
        # check if the user filled in all the fields
        if (
            (sanitized_username in [None, ""])
            or (sanitized_password in [None, ""])
            or (sanitized_email in [None, ""])
        ):
            messages.append("Please fill in all the fields!")
            resp = make_response(
                render_template(
                    register_template_path,
                    csrf_token=csrf_token,
                    error=None,
                    context={"messages": messages},
                )
            )
            return resp

        # check if the username is already taken
        if (
            User.findUserWithUsernameOrEmail(username=sanitized_username) is not None
            or User.findUserWithUsernameOrEmail(email=sanitized_email) is not None
        ) is not None:
            messages.append("Username or email already taken!")
            resp = make_response(
                render_template(
                    register_template_path,
                    csrf_token=csrf_token,
                    error=None,
                    context={"messages": messages},
                )
            )
            return resp

        # create a new user
        new_user = User(
            username=sanitized_username,
            password=Utils.hash_password(sanitized_password),
            email=sanitized_email,
        )
        # add the new user to the database
        try:
            Extensions.db.session.add(new_user)
            Extensions.db.session.commit()
        except Exception as e:
            Extensions.db.session.rollback()
            messages.append("ERROR: Something went wrong while trying to register you!")
            resp = make_response(
                render_template(
                    register_template_path,
                    csrf_token=csrf_token,
                    error=None,
                    context={"messages": messages},
                )
            )
            return resp

        messages.append("Account created successfully!")
        resp = make_response(
            render_template(
                register_template_path,
                csrf_token=csrf_token,
                error=None,
                context={"messages": messages},
            )
        )
        return resp
    elif request.method == "GET":
        try:
            csrf_token = Utils.generate_StrongSecretKey()
            # store the csrf tokens in redis db
            Extensions.redis_db.set(
                f"{os.getenv('CSRF_PREFIX')}:{csrf_token}",
                csrf_token,
                ex=timedelta(minutes=5),
            )

            # reload the page without resubmitting the form
            resp = make_response(
                render_template(
                    register_template_path,
                    csrf_token=csrf_token,
                    error=None,
                    context={"messages": messages},
                )
            )
            return resp
        except Exception as e:
            messages.append("An error occurred! Please try again later.")
            resp = make_response(
                render_template(
                    register_template_path,
                    csrf_token=csrf_token,
                    error=None,
                    context={"messages": messages},
                )
            )
            return resp

    else:
        messages.append(
            f"An error occurred! Please try again later.(Invalid method) ${request.method}"
        )
        resp = make_response(
            render_template(
                register_template_path,
                csrf_token=csrf_token,
                error=None,
                context={"messages": messages},
            )
        )
        return resp


@bp.errorhandler(404)
def page_not_found(e) -> Response:
    # serve the static page for 404 errors.
    return redirect(url_for("static", filename="404/404.html"))
