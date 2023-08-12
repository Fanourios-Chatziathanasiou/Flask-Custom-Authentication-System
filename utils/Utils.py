import secrets
import random
from datetime import datetime
import bcrypt
import os
from dotenv import load_dotenv

# load the environment variables
load_dotenv(".env")


def generate_StrongSecretKey():
    """Generates a strong secret key. based on the secrets module and the current timestamp.

    Returns:
        The strong secret key in String format.
    """
    step = random.randint(1, len(str(datetime.now().timestamp())))
    step2 = random.randint(1, len(str(datetime.now().timestamp())))
    timestamp = str(datetime.now().timestamp())
    randomized_timestamp = str(timestamp[::step])
    randomized_timestamp2 = str(timestamp[::step2])
    strongSecretKey = (
        timestamp[::-step]
        + randomized_timestamp
        + secrets.token_urlsafe(32)
        + timestamp[::-step]
        + randomized_timestamp2
    )

    return strongSecretKey


def escape_output(input_string: str) -> str:
    """Escapes all special characters in the input string.

    Args:
        input_string: The string to be escaped.

    Returns:
        The escaped string.
    """

    escaped_string = ""
    for character in input_string:
        if character == "<":
            escaped_string += "&lt;"
        elif character == ">":
            escaped_string += "&gt;"
        elif character == '"':
            escaped_string += "&quot;"
        elif character == "'":
            escaped_string += "&apos;"
        else:
            escaped_string += character

    return escaped_string


def check_password(passwordInput: str, passwordFormDB: str) -> bool:
    """Checks if the password matches the hashed password in the database.

    Args:
        passwordInput : The password input from the user.
        passwordFormDB: The hashed password from the database.

    Returns:
        True if the password matches the hashed password in the database, False otherwise.
    """

    # hash the password input from the user with bcrypt and the app salt from the .env file
    passwordInput_hashed = bcrypt.hashpw(
        passwordInput.encode("utf-8"), salt=os.getenv("APP_SALT").encode("utf-8")
    ).decode("utf-8")
    # convert bytes to string
    # check if password matches and return true or false

    return passwordInput_hashed == passwordFormDB


def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"), salt=os.getenv("APP_SALT").encode("utf-8")
    ).decode("utf-8")
