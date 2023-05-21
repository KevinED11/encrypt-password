from passlib.hash import bcrypt

class Password:
    @staticmethod
    def encrypt(password: str) -> str:
        return bcrypt.hash(password)

    @staticmethod
    def verify(password: str, hash: str) -> bool:
        return bcrypt.verify(password, hash)

   
if __name__ == "__main__":
    password = Password.encrypt("Kevin dueñas")
    print(password)

    print(Password.verify("Kevin dueñas", password))
