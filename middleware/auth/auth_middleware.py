from functools import wraps
from flask import request, redirect, url_for
from Routes.auth.auth_utils.auth_utils import (
    checkUserExistsInSessions,
)


def require_login(view_func):
    """
    This decorator checks if the user is logged in or not

    Args-(view_func): the view function to be decorated

    Returns -> the decorated function

    """

    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        # check if the session cookie exists
        if not "session" in request.cookies:
            return redirect(url_for("auth.login"))
        # check if the user exists in the sessions
        if not checkUserExistsInSessions(request):
            return redirect(url_for("auth.login"))
        return view_func(*args, **kwargs)

    return decorated_function
