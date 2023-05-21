from main import Password
import unittest


class TestEncryptPassword(unittest.TestCase):
    def setUp(self) -> None:
        self.password = "kevin dueñas"
        self.encrypted_password = Password.encrypt(self.password)

    def test_length_password(self) -> None:
        self.assertGreater(
            len(self.encrypted_password),
            len(self.password),
            "Encryption length is not \
                           greater than original length",
        )

    def test_valid_encrypt(self) -> None:
        self.assertNotEqual(
            self.password,
            self.encrypted_password,
            "Encrypted password is equal to \
                           original password",
        )
        self.assertTrue(
            Password.verify(self.password, self.encrypted_password),
            "Encrypted password is not equal \
                       to original password",
        )

    def test_invalid_encrypt(self) -> None:
        password2 = "juan perez"
        encrypted_password2 = Password.encrypt(password2)
        self.assertNotEqual(self.encrypted_password, encrypted_password2)


class TestVerifyPassword(unittest.TestCase):
    def setUp(self) -> None:
        self.password = "kevin dueñas"
        self.encrypted_password = Password.encrypt(self.password)

    def test_valid_verify(self) -> None:
        self.assertTrue(
            Password.verify(password=self.password, hash=self.encrypted_password),
            "Invalid password",
        )

    def test_invalid_verify(self) -> None:
        password2 = "juan perez"
        self.assertFalse(
            Password.verify(password=password2, hash=self.encrypted_password)
        )


if __name__ == "__main__":
    unittest.main()
