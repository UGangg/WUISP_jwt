from flask import Flask, request, make_response, redirect, render_template
import sqlite3, os
import datetime
import jwt  # PyJWT

app = Flask(__name__)
DB_PATH = "app.db"

# JWT용 비밀키 (실제론 .env나 환경변수로 분리하는 게 좋음)
app.config["JWT_SECRET"] = "change-this-secret-key"
app.config["JWT_ALGORITHM"] = "HS256"
app.config["JWT_EXPIRES_HOURS"] = 1


def get_conn():
    return sqlite3.connect(DB_PATH)


def init_db():
    if not os.path.exists(DB_PATH):
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0
        );
        """)
        # 데모 계정
        cur.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin','admin123',1)")
        cur.execute("INSERT INTO users (username, password, is_admin) VALUES ('alice','alice123',0)")
        conn.commit()
        conn.close()


# -------------------- JWT 유틸 --------------------
def create_jwt(user_id, username):
    payload = {
        "uid": user_id,
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=app.config["JWT_EXPIRES_HOURS"])
    }
    token = jwt.encode(payload, app.config["JWT_SECRET"], algorithm=app.config["JWT_ALGORITHM"])
    # PyJWT 2.x에서는 str로, 1.x에서는 bytes일 수 있으니 str로 강제
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def decode_jwt(token):
    try:
        payload = jwt.decode(
            token,
            app.config["JWT_SECRET"],
            algorithms=[app.config["JWT_ALGORITHM"]]
        )
        return payload
    except jwt.ExpiredSignatureError:
        # 토큰 만료
        return None
    except jwt.InvalidTokenError:
        # 위조/변조 등
        return None


# -------------------- 홈 --------------------
@app.route("/")
def index():
    username = None

    token = request.cookies.get("access_token")
    if token:
        payload = decode_jwt(token)
        if payload:
            username = payload.get("username")

    # uid 파라미터로 계정 전환하던 취약 로직은 제거하고,
    # JWT에 있는 username만 신뢰하도록 변경
    resp = make_response(render_template("index.html", username=username))
    return resp


# -------------------- 회원가입 --------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if not username or not password:
        return render_template("signup.html", err="아이디와 비밀번호를 모두 입력해주세요."), 400

    try:
        conn = get_conn()
        cur = conn.cursor()
        # 안전하게 바인딩 사용
        cur.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, password)
        )
        conn.commit()
        conn.close()
        return redirect("/login")
    except sqlite3.IntegrityError:
        # UNIQUE 제약조건 위반 (이미 존재하는 아이디)
        return render_template("signup.html", err="이미 존재하는 아이디입니다."), 400
    except Exception:
        return render_template("signup.html", err="가입에 실패했습니다. 다시 시도해 주세요."), 400


# -------------------- 로그인 + JWT 발급 --------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    conn = get_conn()
    cur = conn.cursor()
    try:
        # 바인딩 사용 (이제는 SQLi 방어)
        cur.execute(
            "SELECT id, username FROM users WHERE username = ? AND password = ?",
            (username, password)
        )
        row = cur.fetchone()
    except Exception:
        conn.close()
        return render_template("login.html", err="오류가 발생했습니다. 잠시 후 다시 시도해 주세요."), 400
    conn.close()

    if row:
        user_id, username = row
        token = create_jwt(user_id, username)

        resp = make_response(redirect("/"))
        # JWT를 쿠키에 저장 (HttpOnly로 JS 접근 차단)
        resp.set_cookie(
            "access_token",
            token,
            httponly=True,
            samesite="Lax"  # 로컬 실습이니 Secure는 생략
        )
        return resp

    return render_template("login.html", err="아이디 또는 비밀번호가 올바르지 않습니다."), 401


# -------------------- 로그아웃 (JWT 쿠키 제거) --------------------
@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie("access_token")
    return resp


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
