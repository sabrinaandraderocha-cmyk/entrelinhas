import os
import sqlite3
import secrets
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "entrelinhas.db")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-me-now")


# =========================================================
# DB helpers
# =========================================================
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _has_column(conn, table: str, col: str) -> bool:
    cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(c["name"] == col for c in cols)


def _has_table(conn, table: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _now():
    # UTC para validade de token consistente
    return datetime.utcnow()


def _dt_to_str(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _str_to_dt(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")


def init_db():
    conn = get_db()
    cur = conn.cursor()

    # users
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # entries (schema novo)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT NOT NULL,
            year TEXT,
            director TEXT,
            keyword TEXT,
            reflection TEXT,
            q1 TEXT,
            q2 TEXT,
            q3 TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # ✅ MIGRAÇÃO: se banco antigo não tiver user_id, adiciona
    if not _has_column(conn, "entries", "user_id"):
        cur.execute("ALTER TABLE entries ADD COLUMN user_id INTEGER")

    # password reset tokens
    cur.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()


init_db()


# =========================================================
# AUTH helpers
# =========================================================
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def send_reset_email(to_email: str, reset_link: str) -> bool:
    """
    Envia e-mail via SMTP (TLS). Se não estiver configurado, retorna False.
    Variáveis de ambiente esperadas:
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM (opcional)
    """
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "0") or 0)
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_pass = os.getenv("SMTP_PASS", "").strip()
    smtp_from = os.getenv("SMTP_FROM", "").strip() or smtp_user

    if not (smtp_host and smtp_port and smtp_user and smtp_pass and smtp_from):
        return False

    msg = EmailMessage()
    msg["Subject"] = "Entrelinhas — redefinição de senha"
    msg["From"] = smtp_from
    msg["To"] = to_email
    msg.set_content(
        "Você pediu para redefinir sua senha no Entrelinhas.\n\n"
        f"Aqui está o link (válido por 30 minutos):\n{reset_link}\n\n"
        "Se você não pediu isso, pode ignorar este e-mail."
    )

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.ehlo()
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)

    return True


# =========================================================
# AUTH routes
# =========================================================
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("user_id"):
        return redirect(url_for("index"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()

        if not email or not password:
            flash("Preencha e-mail e senha.", "warn")
            return redirect(url_for("signup"))
        if len(password) < 6:
            flash("Sua senha precisa ter pelo menos 6 caracteres.", "warn")
            return redirect(url_for("signup"))

        pw_hash = generate_password_hash(password)

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                (email, pw_hash, datetime.now().strftime("%d/%m/%Y %H:%M")),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("Esse e-mail já está cadastrado. Entre com sua senha.", "warn")
            return redirect(url_for("login"))

        user = conn.execute(
            "SELECT id, email FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        # ✅ entradas antigas sem user_id vão para o primeiro usuário criado
        conn.execute(
            "UPDATE entries SET user_id = ? WHERE user_id IS NULL",
            (user["id"],)
        )
        conn.commit()
        conn.close()

        session["user_id"] = user["id"]
        session["user_email"] = user["email"]
        flash("Conta criada. Bem-vinda(o) ao Entrelinhas.", "ok")
        return redirect(url_for("index"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("index"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()

        conn = get_db()
        user = conn.execute(
            "SELECT id, email, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        conn.close()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("E-mail ou senha inválidos.", "warn")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        session["user_email"] = user["email"]

        nxt = request.args.get("next") or url_for("index")
        return redirect(nxt)

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Você saiu.", "ok")
    return redirect(url_for("login"))


# =========================================================
# Password reset (auto)
# =========================================================
@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()

        # não revela se email existe
        generic_msg = "Se esse e-mail estiver cadastrado, vamos enviar um link de redefinição."

        conn = get_db()
        user = conn.execute("SELECT id, email FROM users WHERE email = ?", (email,)).fetchone()

        if not user:
            conn.close()
            flash(generic_msg, "ok")
            return redirect(url_for("login"))

        token = secrets.token_urlsafe(32)
        expires = _now() + timedelta(minutes=30)

        conn.execute("""
            INSERT INTO password_resets (user_id, token, expires_at, used, created_at)
            VALUES (?, ?, ?, 0, ?)
        """, (user["id"], token, _dt_to_str(expires), _dt_to_str(_now())))
        conn.commit()
        conn.close()

        # link absoluto (produção via APP_BASE_URL; local via host_url)
        app_base_url = os.getenv("APP_BASE_URL", "").strip()
        if app_base_url:
            reset_link = app_base_url.rstrip("/") + url_for("reset_password", token=token)
        else:
            reset_link = request.host_url.rstrip("/") + url_for("reset_password", token=token)

        sent = send_reset_email(user["email"], reset_link)

        # teste local sem SMTP: mostra link na tela
        if not sent:
            flash("SMTP não configurado. Link de teste gerado abaixo:", "warn")
            return render_template("forgot_password.html", show_link=reset_link)

        flash(generic_msg, "ok")
        return redirect(url_for("login"))

    return render_template("forgot_password.html", show_link=None)


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token: str):
    conn = get_db()
    row = conn.execute("""
        SELECT pr.id, pr.user_id, pr.expires_at, pr.used
        FROM password_resets pr
        WHERE pr.token = ?
    """, (token,)).fetchone()

    if not row:
        conn.close()
        flash("Link inválido.", "warn")
        return redirect(url_for("login"))

    if row["used"] == 1:
        conn.close()
        flash("Esse link já foi usado.", "warn")
        return redirect(url_for("login"))

    expires_at = _str_to_dt(row["expires_at"])
    if _now() > expires_at:
        conn.close()
        flash("Esse link expirou. Peça um novo.", "warn")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = (request.form.get("password") or "").strip()
        confirm = (request.form.get("confirm") or "").strip()

        if len(password) < 6:
            conn.close()
            flash("A senha precisa ter pelo menos 6 caracteres.", "warn")
            return redirect(url_for("reset_password", token=token))

        if password != confirm:
            conn.close()
            flash("As senhas não coincidem.", "warn")
            return redirect(url_for("reset_password", token=token))

        pw_hash = generate_password_hash(password)

        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pw_hash, row["user_id"]))
        conn.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (row["id"],))
        conn.commit()
        conn.close()

        flash("Senha redefinida. Você já pode entrar.", "ok")
        return redirect(url_for("login"))

    conn.close()
    return render_template("reset_password.html")


# =========================================================
# App routes (protected)
# =========================================================
@app.route("/")
@login_required
def index():
    uid = session["user_id"]
    conn = get_db()
    entries = conn.execute("""
        SELECT id, title, year, director, keyword, created_at
        FROM entries
        WHERE user_id = ?
        ORDER BY id DESC
    """, (uid,)).fetchall()
    conn.close()
    return render_template("index.html", entries=entries)


@app.route("/new", methods=["GET", "POST"])
@login_required
def new_entry():
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        year = (request.form.get("year") or "").strip()
        director = (request.form.get("director") or "").strip()
        keyword = (request.form.get("keyword") or "").strip()
        reflection = (request.form.get("reflection") or "").strip()
        q1 = (request.form.get("q1") or "").strip()
        q2 = (request.form.get("q2") or "").strip()
        q3 = (request.form.get("q3") or "").strip()

        if not title:
            flash("Coloque pelo menos o título do filme.", "warn")
            return redirect(url_for("new_entry"))

        conn = get_db()
        conn.execute("""
            INSERT INTO entries
            (user_id, title, year, director, keyword, reflection, q1, q2, q3, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session["user_id"],
            title, year, director, keyword, reflection, q1, q2, q3,
            datetime.now().strftime("%d/%m/%Y %H:%M")
        ))
        conn.commit()
        conn.close()

        flash("Guardado. O que ficou em você agora tem lugar.", "ok")
        return redirect(url_for("index"))

    prompts = [
        "Qual cena ficou com você?",
        "Quem você entendeu — mesmo sem concordar?",
        "Se esse filme tivesse um último plano, qual seria?"
    ]
    return render_template("new_entry.html", prompts=prompts)


@app.route("/e/<int:entry_id>")
@login_required
def view_entry(entry_id):
    uid = session["user_id"]
    conn = get_db()
    entry = conn.execute(
        "SELECT * FROM entries WHERE id = ? AND user_id = ?",
        (entry_id, uid)
    ).fetchone()
    conn.close()

    if not entry:
        flash("Entrada não encontrada (ou não é sua).", "warn")
        return redirect(url_for("index"))

    return render_template("view_entry.html", e=entry)


@app.route("/delete/<int:entry_id>", methods=["POST"])
@login_required
def delete_entry(entry_id):
    uid = session["user_id"]
    conn = get_db()
    conn.execute("DELETE FROM entries WHERE id = ? AND user_id = ?", (entry_id, uid))
    conn.commit()
    conn.close()
    flash("Entrada removida.", "ok")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
