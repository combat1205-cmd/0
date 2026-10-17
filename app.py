ㅇimport os
import re
import hmac
import hashlib
import secrets
import sqlite3
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from urllib.parse import urlencode

import requests
from flask import (
    Flask, request, session, redirect, url_for,
    render_template_string, abort
)

# ==================================================
# 1. 환경변수 설정
# ==================================================

app = Flask(__name__)

def required_env(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"환경변수 {name} 이(가) 설정되지 않았습니다.")
    return value

app.secret_key = required_env("SESSION_SECRET")

CLIENT_ID = required_env("DISCORD_CLIENT_ID")
CLIENT_SECRET = required_env("DISCORD_CLIENT_SECRET")
BOT_TOKEN = required_env("DISCORD_BOT_TOKEN")
GUILD_ID = required_env("DISCORD_GUILD_ID")
ROLE_ID = required_env("DISCORD_ROLE_ID")
BASE_URL = required_env("BASE_URL").rstrip("/")

DATABASE = os.getenv("DATABASE_PATH", "verification.db")
EMAIL_HASH_SECRET = required_env("EMAIL_HASH_SECRET")

SMTP_HOST = required_env("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = required_env("SMTP_USER")
SMTP_PASSWORD = required_env("SMTP_PASSWORD")
MAIL_FROM = required_env("MAIL_FROM")

OWNER_USER = required_env("OWNER_USER")
OWNER_PASSWORD = required_env("OWNER_PASSWORD")

# 운영 환경에서는 반드시 HTTPS를 사용하세요.
# 로컬 HTTP 테스트에서만 COOKIE_SECURE=0 으로 설정하세요.
app.config.update(
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "1") == "1",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=16 * 1024,
)

DISCORD_API = "https://discord.com/api/v10"
REDIRECT_URI = BASE_URL + "/callback"
CONSENT_VERSION = "2026-10-18-v1"
IP_RETENTION_DAYS = 30
CODE_LIFETIME_MINUTES = 10
RESEND_COOLDOWN_SECONDS = 60
MAX_CODE_ATTEMPTS = 5


# ==================================================
# 2. 데이터베이스
# ==================================================

def now_utc():
    return datetime.now(timezone.utc)


def now_text():
    return now_utc().isoformat()


def connect_db():
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connect_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS verified_users (
                discord_id TEXT PRIMARY KEY,
                email_hash TEXT UNIQUE NOT NULL,
                ip_address TEXT,
                verified_at TEXT NOT NULL,
                consent_version TEXT NOT NULL,
                consent_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS pending_codes (
                discord_id TEXT PRIMARY KEY,
                email_hash TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_sent_at TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS owner_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


def cleanup_old_data():
    cutoff = (now_utc() - timedelta(days=IP_RETENTION_DAYS)).isoformat()

    with connect_db() as conn:
        # 인증 완료 후 보관 기간이 지난 기록 삭제
        conn.execute(
            "DELETE FROM verified_users WHERE verified_at < ?",
            (cutoff,)
        )

        # 만료된 인증번호 삭제
        conn.execute(
            "DELETE FROM pending_codes WHERE expires_at < ?",
            (now_text(),)
        )


init_db()


# ==================================================
# 3. 공통 보안 함수
# ==================================================

def email_digest(email):
    normalized = email.strip().lower().encode("utf-8")
    return hmac.new(
        EMAIL_HASH_SECRET.encode("utf-8"),
        normalized,
        hashlib.sha256
    ).hexdigest()


def code_digest(discord_id, code):
    value = f"{discord_id}:{code}".encode("utf-8")
    return hmac.new(
        EMAIL_HASH_SECRET.encode("utf-8"),
        value,
        hashlib.sha256
    ).hexdigest()


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf():
    sent = request.form.get("csrf", "")
    saved = session.get("csrf", "")
    if not saved or not hmac.compare_digest(sent, saved):
        abort(400, "요청이 만료되었습니다. 페이지를 새로고침하세요.")


def page(title, body, **kwargs):
    return render_template_string("""
    <!doctype html>
    <html lang="ko">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>{{ title }}</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          max-width: 650px;
          margin: 35px auto;
          padding: 0 16px;
          line-height: 1.6;
          background: #f5f6fa;
          color: #20232a;
        }
        main {
          background: white;
          padding: 24px;
          border-radius: 14px;
          box-shadow: 0 3px 14px #0001;
        }
        input, button {
          box-sizing: border-box;
          width: 100%;
          padding: 12px;
          margin: 8px 0;
          font-size: 16px;
        }
        button {
          border: 0;
          border-radius: 8px;
          background: #5865f2;
          color: white;
          cursor: pointer;
        }
        .muted { color: #666; font-size: 14px; }
        .notice { background: #f0f2ff; padding: 12px; border-radius: 8px; }
        table { width: 100%; border-collapse: collapse; overflow-wrap: anywhere; }
        td, th { border-bottom: 1px solid #ddd; padding: 8px; text-align: left; }
      </style>
    </head>
    <body><main>
      <h1>{{ title }}</h1>
      {{ body }}
    </main></body>
    </html>
    """, title=title, body=body, **kwargs)


def csrf_field():
    # 입력값을 HTML 문자열로 직접 이어 붙이지 않음
    return render_template_string(
        '<input type="hidden" name="csrf" value="{{ token }}">',
        token=csrf_token()
    )


def discord_request(method, path, **kwargs):
    headers = kwargs.pop("headers", {})
    headers["Authorization"] = f"Bot {BOT_TOKEN}"
    return requests.request(
        method,
        DISCORD_API + path,
        headers=headers,
        timeout=15,
        **kwargs
    )


def send_email_code(email, code):
    message = EmailMessage()
    message["Subject"] = "디스코드 이메일 인증번호"
    message["From"] = MAIL_FROM
    message["To"] = email
    message.set_content(
        f"""디스코드 이메일 인증번호: {code}

인증번호는 {CODE_LIFETIME_MINUTES}분 동안 유효합니다.
본인이 요청하지 않았다면 이 메일을 무시하세요.
"""
    )

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
        smtp.starttls()
        smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.send_message(message)


def owner_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        auth = request.authorization
        if not auth:
            response = app.make_response(("관리자 로그인 필요", 401))
            response.headers["WWW-Authenticate"] = 'Basic realm="Owner only"'
            return response

        user_ok = hmac.compare_digest(auth.username or "", OWNER_USER)
        pass_ok = hmac.compare_digest(auth.password or "", OWNER_PASSWORD)

        if not (user_ok and pass_ok):
            response = app.make_response(("접근 거부", 401))
            response.headers["WWW-Authenticate"] = 'Basic realm="Owner only"'
            return response

        return fn(*args, **kwargs)
    return wrapped


# ==================================================
# 4. 첫 화면 및 디스코드 로그인
# ==================================================

@app.get("/")
def index():
    cleanup_old_data()

    if session.get("discord_id"):
        return redirect(url_for("consent"))

    return page(
        "디스코드 인증",
        """
        <p>디스코드 계정과 이메일을 이용한 서버 인증 페이지입니다.</p>
        <p class="notice">
          이메일과 IP 주소 처리에 관한 안내를 확인한 뒤 진행하세요.
          IP는 인증 완료 기록에만 저장되며 정해진 기간 후 삭제됩니다.
          이메일 원문은 데이터베이스에 저장하지 않습니다.
        </p>
        <a href="/login"><button>Discord로 로그인</button></a>
        <p class="muted">계속하기 전에 개인정보 안내를 확인하세요.</p>
        """
    )


@app.get("/login")
def login():
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state

    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "identify",
        "state": state,
    }

    return redirect(
        "https://discord.com/oauth2/authorize?" + urlencode(params)
    )


@app.get("/callback")
def callback():
    error = request.args.get("error")
    if error:
        return page("로그인 취소", "<p>디스코드 로그인이 취소되었습니다.</p>")

    returned_state = request.args.get("state", "")
    saved_state = session.get("oauth_state", "")

    if not saved_state or not hmac.compare_digest(
        returned_state, saved_state
    ):
        abort(400, "잘못된 로그인 요청입니다. 다시 시도하세요.")

    code = request.args.get("code")
    if not code:
        abort(400, "인증 코드가 없습니다.")

    try:
        token_response = requests.post(
            DISCORD_API + "/oauth2/token",
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
        )
        token_response.raise_for_status()
        access_token = token_response.json()["access_token"]

        user_response = requests.get(
            DISCORD_API + "/users/@me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=15,
        )
        user_response.raise_for_status()
        discord_user = user_response.json()

    except (requests.RequestException, KeyError, ValueError):
        return page(
            "로그인 실패",
            "<p>디스코드 로그인에 실패했습니다. 잠시 후 다시 시도하세요.</p>"
        )

    session.clear()
    session["discord_id"] = str(discord_user["id"])
    session["csrf"] = secrets.token_urlsafe(32)

    return redirect(url_for("consent"))


# ==================================================
# 5. 개인정보 안내 및 동의
# ==================================================

@app.route("/consent", methods=["GET", "POST"])
def consent():
    if not session.get("discord_id"):
        return redirect(url_for("login"))

    if request.method == "POST":
        check_csrf()

        if request.form.get("agree") != "yes":
            return page(
                "동의가 필요합니다",
                "<p>인증을 진행하려면 안내 내용을 확인하고 동의해야 합니다.</p>"
                '<a href="/consent">돌아가기</a>'
            )

        session["consented"] = True
        session["consent_at"] = now_text()
        session["consent_version"] = CONSENT_VERSION
        return redirect(url_for("email_form"))

    hidden = csrf_field()
    body = render_template_string("""
      <h2>개인정보 수집·이용 안내</h2>
      <p><b>목적:</b> 디스코드 서버의 이메일 인증 및 중복 인증 방지</p>
      <p><b>수집 항목:</b> 디스코드 사용자 ID, 이메일 인증용 해시값,
      인증 완료 시 접속 IP 주소, 동의 및 인증 시각</p>
      <p><b>이메일:</b> 이메일 원문은 데이터베이스에 저장하지 않습니다.
      인증 메일 발송에만 사용합니다.</p>
      <p><b>IP 주소:</b> 인증 완료 시 저장하고, 인증 후 30일이 지나면
      인증 기록과 함께 삭제합니다.</p>
      <p><b>보관:</b> 인증 기록은 최대 30일 보관합니다.
      법적 의무 등 별도 보관 근거가 있는 경우에는 해당 근거에 따릅니다.</p>
      <p><b>거부:</b> 동의를 거부할 수 있습니다. 다만 이 경우
      이 웹사이트의 인증 기능을 이용할 수 없습니다.</p>
      <p class="muted">안내 버전: {{ version }}</p>
      <form method="post">
        {{ hidden|safe }}
        <label>
          <input type="checkbox" name="agree" value="yes" required
                 style="width:auto">
          위 개인정보 수집·이용 안내를 확인했습니다.
        </label>
        <button type="submit">동의하고 계속</button>
      </form>
    """, hidden=hidden, version=CONSENT_VERSION)

    return page("개인정보 안내", body)


# ==================================================
# 6. 이메일 입력 및 인증번호 발송
# ==================================================

@app.route("/email", methods=["GET", "POST"])
def email_form():
    if not session.get("discord_id"):
        return redirect(url_for("login"))
    if not session.get("consented"):
        return redirect(url_for("consent"))

    if request.method == "POST":
        check_csrf()

        email = request.form.get("email", "").strip()
        if len(email) > 254 or not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+", email
        ):
            return page("이메일 확인", "<p>올바른 이메일 주소를 입력하세요.</p>")

        cleanup_old_data()
        digest = email_digest(email)
        discord_id = session["discord_id"]

        with connect_db() as conn:
            already = conn.execute(
                """SELECT 1 FROM verified_users
                   WHERE discord_id = ? OR email_hash = ?""",
                (discord_id, digest)
            ).fetchone()

            pending = conn.execute(
                "SELECT * FROM pending_codes WHERE discord_id = ?",
                (discord_id,)
            ).fetchone()

        if already:
            return page(
                "이미 인증됨",
                "<p>이 디스코드 계정 또는 이메일은 이미 인증 기록에 있습니다.</p>"
            )

        if pending:
            last_sent = datetime.fromisoformat(pending["last_sent_at"])
            if (now_utc() - last_sent).total_seconds() < RESEND_COOLDOWN_SECONDS:
                return page(
                    "잠시 기다려 주세요",
                    "<p>인증번호를 다시 보내기 전에 60초 기다려 주세요.</p>"
                )

        code = f"{secrets.randbelow(1_000_000):06d}"
        expires = (now_utc() + timedelta(
            minutes=CODE_LIFETIME_MINUTES
        )).isoformat()

        try:
            # 먼저 메일 발송. 성공했을 때만 새 인증번호를 저장합니다.
            send_email_code(email, code)
        except (smtplib.SMTPException, OSError):
            return page(
                "메일 발송 실패",
                "<p>이메일을 보낼 수 없습니다. 관리자에게 문의하세요.</p>"
            )

        with connect_db() as conn:
            conn.execute("""
                INSERT INTO pending_codes
                    (discord_id, email_hash, code_hash, expires_at,
                     last_sent_at, attempts)
                VALUES (?, ?, ?, ?, ?, 0)
                ON CONFLICT(discord_id) DO UPDATE SET
                    email_hash = excluded.email_hash,
                    code_hash = excluded.code_hash,
                    expires_at = excluded.expires_at,
                    last_sent_at = excluded.last_sent_at,
                    attempts = 0
            """, (
                discord_id, digest, code_digest(discord_id, code),
                expires, now_text()
            ))

        session["email_hash"] = digest
        return redirect(url_for("verify_code"))

    body = csrf_field() + """
      <p>인증번호를 받을 이메일 주소를 입력하세요.</p>
      <form method="post">
        FORM_CSRF
        <input type="email" name="email" maxlength="254"
               placeholder="name@example.com" required>
        <button type="submit">인증번호 보내기</button>
      </form>
    """.replace("FORM_CSRF", csrf_field())

    return page("이메일 인증", body)


# ==================================================
# 7. 인증번호 확인 및 디스코드 역할 부여
# ==================================================

@app.route("/verify", methods=["GET", "POST"])
def verify_code():
    if not session.get("discord_id") or not session.get("email_hash"):
        return redirect(url_for("email_form"))

    discord_id = session["discord_id"]

    if request.method == "POST":
        check_csrf()
        code = request.form.get("code", "").strip()

        if not re.fullmatch(r"\d{6}", code):
            return page("인증번호 확인", "<p>6자리 숫자를 입력하세요.</p>")

        with connect_db() as conn:
            pending = conn.execute(
                "SELECT * FROM pending_codes WHERE discord_id = ?",
                (discord_id,)
            ).fetchone()

        if not pending:
            return page("인증 만료", "<p>인증번호를 다시 요청하세요.</p>")

        if pending["attempts"] >= MAX_CODE_ATTEMPTS:
            with connect_db() as conn:
                conn.execute(
                    "DELETE FROM pending_codes WHERE discord_id = ?",
                    (discord_id,)
                )
            return page(
                "시도 횟수 초과",
                "<p>인증번호 입력 횟수를 초과했습니다. 다시 시작하세요.</p>"
            )

        if datetime.fromisoformat(pending["expires_at"]) < now_utc():
            with connect_db() as conn:
                conn.execute(
                    "DELETE FROM pending_codes WHERE discord_id = ?",
                    (discord_id,)
                )
            return page("인증 만료", "<p>인증번호가 만료되었습니다.</p>")

        submitted_hash = code_digest(discord_id, code)
        if not hmac.compare_digest(submitted_hash, pending["code_hash"]):
            with connect_db() as conn:
                conn.execute(
                    """UPDATE pending_codes SET attempts = attempts + 1
                       WHERE discord_id = ?""",
                    (discord_id,)
                )
            return page(
                "인증번호 오류",
                "<p>인증번호가 올바르지 않습니다. 다시 확인하세요.</p>"
            )

        # 사용자가 해당 디스코드 서버에 실제로 있는지 확인
        member = discord_request(
            "GET", f"/guilds/{GUILD_ID}/members/{discord_id}"
        )
        if member.status_code == 404:
            return page(
                "서버 가입 필요",
                "<p>먼저 인증할 디스코드 서버에 가입한 뒤 다시 시도하세요.</p>"
            )
        if member.status_code != 200:
            return page(
                "확인 실패",
                "<p>서버 멤버를 확인할 수 없습니다. 관리자 설정을 확인하세요.</p>"
            )

        # 인증 완료 전에 중복 이메일 여부를 다시 확인
        with connect_db() as conn:
            duplicate = conn.execute(
                """SELECT 1 FROM verified_users
                   WHERE discord_id = ? OR email_hash = ?""",
                (discord_id, pending["email_hash"])
            ).fetchone()

        if duplicate:
            return page("중복 인증", "<p>이미 인증된 계정 또는 이메일입니다.</p>")

        # Discord 역할 부여
        role_result = discord_request(
            "PUT",
            f"/guilds/{GUILD_ID}/members/{discord_id}/roles/{ROLE_ID}"
        )

        if role_result.status_code not in (200, 204):
            return page(
                "역할 부여 실패",
                "<p>봇 권한, 서버 ID, 역할 ID 및 역할 순서를 확인하세요.</p>"
            )

        # IP는 인증 완료 시에만 기록합니다.
        # 프록시 헤더(X-Forwarded-For)는 무조건 신뢰하지 않습니다.
        ip_address = request.remote_addr or "unknown"
        consent_at = session.get("consent_at", now_text())
        consent_version = session.get("consent_version", CONSENT_VERSION)

        try:
            with connect_db() as conn:
                conn.execute("""
                    INSERT INTO verified_users
                        (discord_id, email_hash, ip_address, verified_at,
                         consent_version, consent_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    discord_id, pending["email_hash"], ip_address,
                    now_text(), consent_version, consent_at
                ))
                conn.execute(
                    "DELETE FROM pending_codes WHERE discord_id = ?",
                    (discord_id,)
                )
        except sqlite3.IntegrityError:
            return page(
                "중복 인증",
                "<p>이미 인증된 계정 또는 이메일입니다.</p>"
            )

        session.clear()
        return page(
            "인증 완료",
            "<p>이메일 인증이 완료되었고 디스코드 역할이 부여되었습니다.</p>"
        )

    return page(
        "인증번호 입력",
        csrf_field() + """
        <p>이메일로 받은 6자리 인증번호를 입력하세요.</p>
        <form method="post">
          FORM_CSRF
          <input name="code" inputmode="numeric" pattern="[0-9]{6}"
                 maxlength="6" placeholder="123456" required>
          <button type="submit">인증하기</button>
        </form>
        """.replace("FORM_CSRF", csrf_field())
    )


# ==================================================
# 8. 소유자 전용 개인정보 조회
# ==================================================

@app.get("/owner/private-records")
@owner_required
def owner_records():
    cleanup_old_data()

    with connect_db() as conn:
        rows = conn.execute("""
            SELECT discord_id, email_hash, ip_address,
                   verified_at, consent_version, consent_at
            FROM verified_users
            ORDER BY verified_at DESC
            LIMIT 100
        """).fetchall()

        conn.execute(
            "INSERT INTO owner_audit (action, created_at) VALUES (?, ?)",
            ("view_records", now_text())
        )

    # Jinja 기본 HTML 자동 이스케이프를 사용합니다.
    body = render_template_string("""
      <p>최근 인증 기록 최대 100개입니다.</p>
      <p class="muted">
        이메일 원문은 저장하지 않습니다. 아래 값은 이메일 해시입니다.
        IP 주소는 프록시 환경에 따라 실제 이용자 IP가 아닐 수 있습니다.
      </p>
      <table>
        <tr>
          <th>Discord ID</th><th>이메일 해시</th><th>IP</th>
          <th>인증 시각</th><th>동의 버전</th><th>동의 시각</th>
        </tr>
        {% for r in rows %}
        <tr>
          <td>{{ r["discord_id"] }}</td>
          <td>{{ r["email_hash"] }}</td>
          <td>{{ r["ip_address"] }}</td>
          <td>{{ r["verified_at"] }}</td>
          <td>{{ r["consent_version"] }}</td>
          <td>{{ r["consent_at"] }}</td>
        </tr>
        {% endfor %}
      </table>
    """, rows=rows)

    return page("소유자 전용 인증 기록", body)


# ==================================================
# 9. 오류 처리 및 실행
# ==================================================

@app.errorhandler(400)
def bad_request(error):
    return page("요청 오류", "<p>요청이 올바르지 않습니다. 페이지를 새로고침하세요.</p>"), 400


@app.errorhandler(413)
def too_large(error):
    return page("요청 크기 초과", "<p>요청이 너무 큽니다.</p>"), 413


if __name__ == "__main__":
    # 로컬 테스트용. 공개 운영 시 gunicorn 등으로 실행하세요.
    app.run(host="127.0.0.1", port=5000, debug=False)
