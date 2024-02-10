import hashlib
import secrets
from sqlite3 import Connection, Cursor
import time


class User:

    def __init__(
        self,
        email: str,
        partially_hashed_password: str,
        registration_epoch_seconds: str,
        activated=False,
        salt="",
    ):
        self.email = email
        self.password = partially_hashed_password
        self.salt = salt
        self.registration_epoch_seconds = registration_epoch_seconds
        self.activated = activated

    def hash_password_and_set_salt(self):
        salt = secrets.token_bytes(16)
        combined = self.password.encode("utf-8") + salt
        hashed_password = hashlib.blake2b(combined).hexdigest()
        self.password = hashed_password
        self.salt = salt

    def authenticate(self, password):
        combined = password.encode("utf-8") + self.salt
        hashed_password = hashlib.blake2b(combined).hexdigest()
        return hashed_password == self.password


class UserRepository:

    def __init__(self, connection: Connection, cursor: Cursor):
        self.connection = connection
        self.cursor = cursor

    def persist_user(self, user: User) -> User | None:
        if self.user_exists(user):
            return None

        self.cursor.execute(
            "INSERT INTO user VALUES (?, ?, ?, ?, ?)",
            (
                user.email,
                user.password,
                user.salt,
                user.activated,
                user.registration_epoch_seconds,
            ),
        )
        self.connection.commit()
        return self.get_user_by_email(user.email)

    def get_user_by_email(self, email):
        res = self.cursor.execute("SELECT * FROM user WHERE email = ?", (email,))
        # If it is domain knowledge that the email is a primary key, this is fine
        fetched_user = res.fetchone()
        return User(*fetched_user) if fetched_user else None

    def user_exists(self, user: User):
        return True if self.get_user_by_email(user.email) is not None else False

    def update_user(self, user: User) -> User:
        # Test this
        self.cursor.execute(
            "UPDATE user SET activated = ?, registration_date = ?, password = ?, salt = ? WHERE email = ?",
            (
                user.activated,
                user.registration_epoch_seconds,
                user.password,
                user.salt,
                user.email,
            ),
        )
        self.connection.commit()
        return self.get_user_by_email(user.email)


class ActivationLinkRepository:

    def __init__(self, connection: Connection, cursor: Cursor):
        self.connection = connection
        self.cursor = cursor

    def delete_activation_link_by_email(self, email):
        self.cursor.execute("DELETE FROM activation_link WHERE email = ?", (email,))
        self.connection.commit()

    def persist_activation_link(self, email, activation_link, epochSeconds) -> str:
        self.cursor.execute(
            "INSERT INTO activation_link VALUES (?, ?, ?)",
            (email, activation_link, epochSeconds),
        )
        self.connection.commit()
        return self.get_email_by_activation_link(activation_link)

    def get_email_by_activation_link(self, activation_link):
        # I assume that only one activation link per email can be active at a time
        res = self.cursor.execute(
            "SELECT email FROM activation_link WHERE activation_link = ?",
            (activation_link,),
        )
        fetched_email = res.fetchone()
        return fetched_email[0] if fetched_email else None


class UserService:

    def __init__(
        self,
        user_repository: UserRepository,
        activation_link_repository: ActivationLinkRepository,
    ):
        self.user_repository = user_repository
        self.activation_link_repository = activation_link_repository
        pass

    def register(self, email, partially_hashed_password):
        """
        Returns an an activation link
        """
        epoch_seconds = str(int(time.time()))
        new_user = User(email, partially_hashed_password, epoch_seconds)
        new_user.hash_password_and_set_salt()
        self.user_repository.persist_user(new_user)
        return self.create_and_persist_activation_link(new_user)

    def authenticate(self, email, partially_hashed_password):
        """
        Returns True if the user is authenticated
        Returns False if there is no such a user OR if the user is not authenticated
        This method could benefit from a refactor to use an enum
        """
        retrieved_user = self.user_repository.get_user_by_email(email)
        if retrieved_user is None:
            return False
        if not retrieved_user.activated:
            return False
        return retrieved_user.authenticate(partially_hashed_password)

    def create_and_persist_activation_link(self, user: User) -> str:
        epoch_seconds = str(int(time.time()))
        activation_link = hashlib.blake2b(
            (user.email + epoch_seconds).encode()
        ).hexdigest()
        self.activation_link_repository.persist_activation_link(
            user.email, activation_link, epoch_seconds
        )
        return activation_link

    def activate_user(self, activation_token) -> User | None:
        email = self.activation_link_repository.get_email_by_activation_link(
            activation_token
        )
        if email is None:
            return None
        user = self.user_repository.get_user_by_email(email)
        if user.activated:
            return None
        user.activated = True
        updated_user = self.user_repository.update_user(user)
        return updated_user if updated_user.activated else None
