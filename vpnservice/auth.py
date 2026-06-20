import hashlib
from getpass import getpass

from core.connection import Database
from models.user import Users

DB_PATH = "db.sqlite"
REGISTER = "REGISTER"
LOGIN = "LOGIN"
OK = "OK"
ERR = "ERR"


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def prompt_action() -> str:
    while True:
        action = input("Action [register/login]: ").strip().lower()
        if action in ("register", "login"):
            return action
        print("Please enter register or login.")


def prompt_credentials():
    username = input("Username: ").strip()
    password = getpass("Password: ").strip()
    return username, password


def build_request(action: str, username: str, password: str) -> bytes:
    action_name = REGISTER if action == "register" else LOGIN
    payload = f"{action_name}|{username}|{hash_password(password)}"
    return payload.encode("utf-8")


def parse_request(data: bytes):
    try:
        action_name, username, password_hash = data.decode("utf-8").strip().split("|", 2)
    except ValueError:
        return None

    if action_name not in (REGISTER, LOGIN):
        return None

    return action_name, username.strip(), password_hash.strip()


def build_response(status: str, message: str) -> bytes:
    return f"{status}|{message}".encode("utf-8")


def parse_response(data: bytes):
    try:
        status, message = data.decode("utf-8").strip().split("|", 1)
    except ValueError:
        return None
    return status, message


def register_user(db: Database, username: str, password_hash: str):
    if not username or not password_hash:
        return False, "Username and password are required"

    if Users.find_by_username(db, username) is not None:
        return False, "User already exists"

    db.execute(
        '''
        INSERT INTO "Users" ("Username", "Password", "HashType", "Author", "Change_cnt")
        VALUES (?, ?, ?, ?, ?)
        ''',
        (username, password_hash, "sha256", "cli", 0)
    )
    return True, "Registration completed"


def login_user(db: Database, username: str, password_hash: str):
    if not username or not password_hash:
        return False, "Username and password are required"

    user = Users.find_by_username(db, username)
    if user is None:
        return False, "User not found"

    if user.Password != password_hash:
        return False, "Wrong password"

    return True, "Login successful"


def handle_auth_packet(db: Database, data: bytes):
    parsed = parse_request(data)
    if parsed is None:
        return False, build_response(ERR, "Invalid request")

    action_name, username, password_hash = parsed

    if action_name == REGISTER:
        ok, message = register_user(db, username, password_hash)
    else:
        ok, message = login_user(db, username, password_hash)

    if ok:
        return True, build_response(OK, message)
    return False, build_response(ERR, message)
