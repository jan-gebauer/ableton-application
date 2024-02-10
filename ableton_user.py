import hashlib
import secrets
from sqlite3 import Connection, Cursor
import time


class User:

    def __init__(
        self,
        email,
        partially_hashed_password,
        registration_epoch_seconds,
        activated=False,
        salt="",
    ):
        self.email = email
        self.password, self.salt = self.hash_and_salt(partially_hashed_password)
        self.registration_epoch_seconds = registration_epoch_seconds
        self.activated = activated

    def hash_and_salt(self, password):
        salt = secrets.token_bytes(16)
        combined = password.encode("utf-8") + salt
        hashed_password = hashlib.blake2b(combined).hexdigest()
        return hashed_password, salt


class UserRepository:

    def __init__(self, connection: Connection, cursor: Cursor):
        self.connection = connection
        self.cursor = cursor

    def persist_user(self, user: User):
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

    def get_all_users(self):
        res = self.cursor.execute("SELECT * FROM user")
        return res.fetchall()

    def user_exists(self, user: User):
        return True if self.get_user_by_email(user.email) is not None else False

    def update_user(self, user: User):
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

    def persist_activation_link(self, email, activation_link, epochSeconds):
        self.cursor.execute(
            "INSERT INTO activation_link VALUES (?, ?, ?)",
            (email, activation_link, epochSeconds),
        )
        self.connection.commit()

    def get_email_by_activation_link(self, activation_link):
        # I assume that only one activation link per email can be active at a time
        res = self.cursor.execute(
            "SELECT email FROM activation_link WHERE activation_link = ?",
            (activation_link,),
        )
        fetched_email = res.fetchone()
        return fetched_email


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
        epoch_seconds = time.gmtime(time.time())
        new_user = User(email, partially_hashed_password, epoch_seconds)
        self.user_repository.persist_user(new_user)
        self.create_activation_link(new_user)

    def authenticate(self, email, partially_hashed_password):
        retrieved_user = self.user_repository.get_user_by_email(email)
        if retrieved_user is None:
            return False
        # This could be handled differently by informing the user that they are not activated
        # For example, do a secondary check after this method is called,
        # given that it returned True
        if not retrieved_user.activated:
            return False
        attempt_hashed_password, _ = retrieved_user.hash_and_salt(
            partially_hashed_password
        )
        return True if attempt_hashed_password == retrieved_user.password else False

    def create_activation_link(self, user: User):
        epoch_seconds = str(time.gmtime(time.time()))
        activation_link = hashlib.blake2b(user.email + epoch_seconds).hexdigest()
        self.activation_link_repository.persist_activation_link(
            user.email, activation_link, epoch_seconds
        )

    def activate_user(self, activation_token):
        email = self.activation_link_repository.get_email_by_activation_link(
            activation_token
        )
        if email is None:
            return False
        user = self.user_repository.get_user_by_email(email)
        if not user.activated:
            return False
        updated_user = self.user_repository.update_user(user)
        return updated_user if updated_user.activated else False
