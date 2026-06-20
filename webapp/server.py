from flask import Flask, render_template, url_for, request, redirect, session
from models.user import Users
from core.connection import Database
import hashlib

app = Flask(__name__)
app.secret_key = "super_secret_key"

db = Database("db.sqlite")

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username")
    password = request.form.get("password")

    user = Users.find_by_username(db, username)

    if user is None:
        return render_template("login.html", error="Пользователь не найден")

    if user.Password != hash_password(password):
        return render_template("login.html", error="Неверный пароль")

    session["user_id"] = user.ID
    session["username"] = user.Username

    return redirect(url_for("mainpage"))


@app.route("/")
def mainpage():
    username = session.get("username")
    return render_template("home.html", username=username)


@app.route("/user/<int:id>")
def get_user(id: int):
    if "username" not in session:
        return redirect(url_for("login"))

    try:
        user = Users(db, ID=id)
    except ValueError:
        return "Пользователь не найден", 404

    return f"User ID: {user.ID}, Username: {user.Username}"


@app.route("/user/config", methods=["GET", "POST"])
def user_config():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session.get("username")

    if request.method == "GET":
        return f"Страница конфигурации пользователя {username}"

    return f"Конфигурация пользователя {username} обновлена"


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("mainpage"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username")
    password = request.form.get("password")

    existing_user = Users.find_by_username(db, username)
    if existing_user is not None:
        return render_template("register.html", error="Такой пользователь уже существует")

    hashed_password = hash_password(password)

    cursor = db.execute(
        '''
        INSERT INTO "Users" ("Username", "Password", "HashType", "Author", "Change_cnt")
        VALUES (?, ?, ?, ?, ?)
        ''',
        (username, hashed_password, "sha256", "system", 0)
    )

    session["user_id"] = cursor.lastrowid
    session["username"] = username

    return redirect(url_for("mainpage"))


if __name__ == "__main__":
    app.run(debug=True)