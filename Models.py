import datetime
from App_Extensions import Extensions
import uuid


# User table
class User(Extensions.db.Model):
    __tablename__ = "users"
    # id field of uuid type, primary key
    id = Extensions.db.Column(
        Extensions.db.String(100),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    username: str = Extensions.db.Column(
        Extensions.db.String(30), nullable=False, unique=True
    )
    # password field, hashed with bcrypt
    password: str = Extensions.db.Column(Extensions.db.String(100), nullable=False)
    email: str = Extensions.db.Column(
        Extensions.db.String(60),
        nullable=False,
        unique=True,
    )
    created_at: datetime = Extensions.db.Column(
        Extensions.db.DateTime, nullable=False, default=datetime.datetime.now()
    )

    def __repr__(self) -> str:
        return f"<User {self.username} | {self.email} | Created at:{self.created_at}>"

    def __str__(self) -> str:
        return f"<User {self.username} | {self.email} | Created at:{self.created_at}>"

    @staticmethod
    def findUserWithUsernameOrEmail(usernameOrEmail: str) -> "User":
        """
        This function finds a user with the username or email

        Args-
            username: the username of the user or the email of the user

        Returns -> the user if found, else None

        """
        return (
            Extensions.db.session.query(User)
            .filter(
                (User.username == usernameOrEmail) | (User.email == usernameOrEmail)
            )
            .first()
        )
