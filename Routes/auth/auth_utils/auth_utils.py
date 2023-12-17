from flask import Request, Response, render_template
import datetime
import os
from App_Extensions import Extensions


def generate_AuthCookies(
    request: Request, resp: Response, session_key, s_id, **kwArgs
) -> bool:
    """
    This function generates the authentication cookies
    and sets them in the response object

    Args-
        request: the request object
        resp: the response object
        session_key: the session key
        s_id: the session id
        **kwArgs: the keyword arguments, could be username and/or email

    Returns -> True if the cookies were generated successfully, else False

    """

    try:
        resp.set_cookie(
            os.getenv("SESSION_COOKIE_PREFIX"),
            value=session_key,
            secure=True,
            samesite="Strict",
            expires=datetime.datetime.now() + datetime.timedelta(days=365),
        )
        resp.set_cookie(
            os.getenv("SESSION_COOKIE_ID_PREFIX"),
            value=s_id,
            secure=True,
            samesite="Strict",
            expires=datetime.datetime.now() + datetime.timedelta(days=365),
        )

        
    except Exception as e:
        print(e)
        return False

    return True


def storeSessionInRedis(session_key, s_id, **kwArgs) -> bool:
    """
    This function stores the session in the redis database

    Args-
        session_key: the session key
        s_id: the session id
        **kwArgs: the keyword arguments, could be username and/or email

    Returns -> True if the session was stored successfully, else False

    """
    try:
        Extensions.redis_db.hmset(
            f"{os.getenv('SESSION_COOKIE_PREFIX')}:{session_key}",
            mapping={
                os.getenv("SESSION_COOKIE_PREFIX"): session_key,
                os.getenv("SESSION_COOKIE_ID_PREFIX"): s_id,
                **kwArgs,
            },
        )
        # set to the session an expiration time of 1 year
        Extensions.redis_db.expire(
            f"{os.getenv('SESSION_COOKIE_PREFIX')}:{session_key}",
            datetime.timedelta(days=365),
        )
    except Exception as e:
        print(e)
        return False

    return True


def checkUserExistsInSessions(request: Request) -> bool:
    # get the session cookie
    session_cookie = request.cookies.get("session")
    s_id = request.cookies.get("s_id")
    # check if the session exists in redis db
    session_title = f"{os.getenv('SESSION_COOKIE_PREFIX')}:{session_cookie}"
    if Extensions.redis_db.hexists(
        key=os.getenv("SESSION_COOKIE_PREFIX"), name=session_title
    ):
        if Extensions.redis_db.hexists(session_title, "s_id"):
            if Extensions.redis_db.hget(session_title, "s_id") == s_id:
                return True
    return False
