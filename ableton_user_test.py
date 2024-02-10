import sqlite3
import unittest

from ableton_user import User, UserRepository


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


if __name__ == "__main__":
    unittest.main()
