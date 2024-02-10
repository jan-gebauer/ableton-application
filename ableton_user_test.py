import sqlite3
import unittest

from ableton_user import ActivationLinkRepository, User, UserRepository, UserService


class TestUserRepository(unittest.TestCase):

    def setUp(self):
        self.con = sqlite3.connect("ableton_user.db")
        self.cur = self.con.cursor()
        self.cur.execute("DROP TABLE IF EXISTS user")
        self.cur.execute(
            "CREATE TABLE user (email PRIMARY KEY, password, salt, activated, registration_date)"
        )

    def tearDown(self):
        self.cur.execute("DROP TABLE IF EXISTS user")
        self.cur.close()
        self.con.close()

    def test_repository(self):
        user = User("email", "password", 123)
        repository = UserRepository(self.con, self.cur)
        repository.persist_user(user)
        retrieved_user = repository.get_user_by_email(user.email)
        self.assertIsNotNone(retrieved_user)


class TestUserService(unittest.TestCase):
    def setUp(self):
        self.con = sqlite3.connect("ableton_user.db")
        self.cur = self.con.cursor()
        self.cur.execute("DROP TABLE IF EXISTS user")
        self.cur.execute(
            "CREATE TABLE user (email PRIMARY KEY, password, salt, activated, registration_date)"
        )
        self.cur.execute("DROP TABLE IF EXISTS activation_link")
        self.cur.execute(
            "CREATE TABLE activation_link (email PRIMARY KEY, activation_link, registration_date)"
        )

    def tearDown(self):
        self.cur.execute("DROP TABLE IF EXISTS user")
        self.cur.execute("DROP TABLE IF EXISTS activation_link")
        self.cur.close()
        self.con.close()

    def test_registration(self):
        user = User("email", "password", "123")
        user_repository = UserRepository(self.con, self.cur)
        activation_link_repository = ActivationLinkRepository(self.con, self.cur)
        service = UserService(user_repository, activation_link_repository)
        service.register("email", "password")
        retrieved_user = user_repository.get_user_by_email(user.email)
        self.assertIsNotNone(retrieved_user)

    def test_authentication(self):
        user_repository = UserRepository(self.con, self.cur)
        activation_link_repository = ActivationLinkRepository(self.con, self.cur)
        service = UserService(user_repository, activation_link_repository)
        activation_link = service.register("email", "password")
        service.activate_user(activation_link)
        authentication_result = service.authenticate("email", "password")
        self.assertTrue(authentication_result)


if __name__ == "__main__":
    unittest.main()
