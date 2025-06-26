# generate_password_hashes.py

import bcrypt

def hash_password(plain_password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(plain_password.encode("utf-8"), salt).decode("utf-8")

if __name__ == "__main__":
    # EXAMPLE: change these to whatever usernames/passwords you want
    users = {
        "alice": "alice_password123",
        "bob":   "bob_secret456",
        "carol": "carol_pw789"
    }

    print("USER_CREDENTIALS = {")
    for username, pw in users.items():
        h = hash_password(pw)
        print(f'    "{username}": "{h}",')
    print("}")
