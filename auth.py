import bcrypt
from db import get_user, create_user

def register(username: str, password: str):
    if get_user(username):
        return False, "Username already exists."
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    create_user({"username": username, "password": hashed_pw, "vault": []})
    return True, "User registered successfully."

def login(username: str, password: str):
    user = get_user(username)
    if user and bcrypt.checkpw(password.encode(), user['password']):
        return True, user
    return False, "Invalid credentials."
