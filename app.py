import os
import secrets
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

# ============ Postgres (Neon) via psycopg v3 ============
try:
    import psycopg
    from psycopg.rows import dict_row
except Exception:
    psycopg = None
    dict_row = None

# ============ SQLite (fallback local) ============
import sqlite3

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SQLITE_PATH = os.path.join(BASE_DIR, "entrelinhas.db")
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-me-now")


def using_postgres() -> bool:
    return bool(DATABASE_URL)


def q(sql: str) -> str:
    """
    Escrevemos SQL com placeholders do Postgres (%s).
    No SQLite local, convertemos %s -> ?.
    """
    return sql if using_postgres() else sql.replace("%s", "?")


def get_db():
    if using_postgres():
        if psycopg is None:
            raise RuntimeError("psycopg não está instalado. Adicione psycopg[binary] no requirements.txt.")
        # Neon exige SSL. Geralmente a URL já vem com sslmode=require.
        return psycopg.connect(DATABASE_URL, row_factory=dict_row)
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _has_column_sqlite(conn, table: str, col: str) -> bool:
    cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(c["name"] == col for c in cols)


def _now_utc():
    return datetime.utcnow()


def _dt_to_str(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _str_to_dt(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")


def init_db():
    conn = get_db()
    cur = conn.cursor()

    if using_postgres():
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS entries (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                title TEXT NOT NULL,
                year TEXT,
                director TEXT,
                keyword TEXT,
                reflection TEXT,
                q1 TEXT,
                q2 TEXT,
                q3 TEXT,
                rating INTEGER,
                critique_link TEXT,
                created_at TEXT NOT NULL
            );
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                token TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                used BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TEXT NOT NULL
            );
        """)

        # Migração leve (caso tabela antiga sem colunas)
        try:
            cur.execute("ALTER TABLE entries ADD COLUMN IF NOT EXISTS rating INTEGER;")
            cur.execute("ALTER TABLE entries ADD COLUMN IF NOT EXISTS critique_link TEXT;")
        except Exception:
            pass

    else:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

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

        if not _has_column_sqlite(conn, "entries", "user_id"):
            cur.execute("ALTER TABLE entries ADD COLUMN user_id INTEGER")
        if not _has_column_sqlite(conn, "entries", "rating"):
            cur.execute("ALTER TABLE entries ADD COLUMN rating INTEGER")
        if not _has_column_sqlite(conn, "entries", "critique_link"):
            cur.execute("ALTER TABLE entries ADD COLUMN critique_link TEXT")

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


def ensure_db_ready():
    init_db()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def send_reset_email(to_email: str, reset_link: str) -> bool:
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


@app.route("/_health")
def health():
    return "OK", 200


@app.route("/_bootstrap")
def bootstrap():
    try:
        ensure_db_ready()
        return "DB OK", 200
    except Exception as e:
        return f"DB ERROR: {e}", 500


@app.route("/signup", methods=["GET", "POST"])
def signup():
    ensure_db_ready()

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
        cur = conn.cursor()

        try:
            cur.execute(q("INSERT INTO users (email, password_hash, created_at) VALUES (%s, %s, %s)"),
                        (email, pw_hash, datetime.now().strftime("%d/%m/%Y %H:%M")))
            conn.commit()
        except Exception:
            conn.close()
            flash("Esse e-mail já está cadastrado. Entre com sua senha.", "warn")
            return redirect(url_for("login"))

        cur.execute(q("SELECT id, email FROM users WHERE email = %s"), (email,))
        user = cur.fetchone()

        # adota entradas antigas sem user_id (só afeta SQLite local; no Postgres quase nunca terá)
        try:
            cur.execute(q("UPDATE entries SET user_id = %s WHERE user_id IS NULL"), (user["id"],))
            conn.commit()
        except Exception:
            pass

        conn.close()

        session["user_id"] = user["id"]
        session["user_email"] = user["email"]
        flash("Conta criada. Bem-vinda(o) ao Entrelinhas.", "ok")
        return redirect(url_for("index"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    ensure_db_ready()

    if session.get("user_id"):
        return redirect(url_for("index"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()

        conn = get_db()
        cur = conn.cursor()
        cur.execute(q("SELECT id, email, password_hash FROM users WHERE email = %s"), (email,))
        user = cur.fetchone()
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


@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    ensure_db_ready()

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        generic_msg = "Se esse e-mail estiver cadastrado, vamos enviar um link de redefinição."

        conn = get_db()
        cur = conn.cursor()
        cur.execute(q("SELECT id, email FROM users WHERE email = %s"), (email,))
        user = cur.fetchone()

        if not user:
            conn.close()
            flash(generic_msg, "ok")
            return redirect(url_for("login"))

        token = secrets.token_urlsafe(32)
        expires = _now_utc() + timedelta(minutes=30)

        if using_postgres():
            cur.execute("""
                INSERT INTO password_resets (user_id, token, expires_at, used, created_at)
                VALUES (%s, %s, %s, FALSE, %s)
            """, (user["id"], token, _dt_to_str(expires), _dt_to_str(_now_utc())))
        else:
            cur.execute("""
                INSERT INTO password_resets (user_id, token, expires_at, used, created_at)
                VALUES (?, ?, ?, 0, ?)
            """, (user["id"], token, _dt_to_str(expires), _dt_to_str(_now_utc())))

        conn.commit()
        conn.close()

        app_base_url = os.getenv("APP_BASE_URL", "").strip()
        reset_link = (app_base_url.rstrip("/") if app_base_url else request.host_url.rstrip("/")) + url_for("reset_password", token=token)

        sent = send_reset_email(user["email"], reset_link)

        if not sent:
            flash("SMTP não configurado. Link de teste gerado abaixo:", "warn")
            return render_template("forgot_password.html", show_link=reset_link)

        flash(generic_msg, "ok")
        return redirect(url_for("login"))

    return render_template("forgot_password.html", show_link=None)


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token: str):
    ensure_db_ready()

    conn = get_db()
    cur = conn.cursor()
    cur.execute(q("SELECT id, user_id, expires_at, used FROM password_resets WHERE token = %s"), (token,))
    row = cur.fetchone()

    if not row:
        conn.close()
        flash("Link inválido.", "warn")
        return redirect(url_for("login"))

    if using_postgres():
        if bool(row["used"]):
            conn.close()
            flash("Esse link já foi usado.", "warn")
            return redirect(url_for("login"))
    else:
        if row["used"] == 1:
            conn.close()
            flash("Esse link já foi usado.", "warn")
            return redirect(url_for("login"))

    expires_at = _str_to_dt(row["expires_at"])
    if _now_utc() > expires_at:
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

        cur.execute(q("UPDATE users SET password_hash = %s WHERE id = %s"), (pw_hash, row["user_id"]))
        if using_postgres():
            cur.execute(q("UPDATE password_resets SET used = TRUE WHERE id = %s"), (row["id"],))
        else:
            cur.execute(q("UPDATE password_resets SET used = 1 WHERE id = %s"), (row["id"],))

        conn.commit()
        conn.close()

        flash("Senha redefinida. Você já pode entrar.", "ok")
        return redirect(url_for("login"))

    conn.close()
    return render_template("reset_password.html")


@app.route("/")
@login_required
def index():
    ensure_db_ready()

    uid = session.get("user_id")
    if not uid:
        flash("Sua sessão expirou. Entre novamente.", "warn")
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute(q("""
        SELECT id, title, year, director, keyword, created_at, rating, critique_link
        FROM entries
        WHERE user_id = %s
        ORDER BY id DESC
    """), (uid,))
    entries = cur.fetchall()
    conn.close()

    return render_template("index.html", entries=entries)


@app.route("/new", methods=["GET", "POST"])
@login_required
def new_entry():
    ensure_db_ready()

    if request.method == "POST":
        uid = session.get("user_id")
        if not uid:
            flash("Sua sessão expirou. Entre novamente.", "warn")
            return redirect(url_for("login"))

        title = (request.form.get("title") or "").strip()
        year = (request.form.get("year") or "").strip()
        director = (request.form.get("director") or "").strip()
        keyword = (request.form.get("keyword") or "").strip()
        reflection = (request.form.get("reflection") or "").strip()
        q1 = (request.form.get("q1") or "").strip()
        q2 = (request.form.get("q2") or "").strip()
        q3 = (request.form.get("q3") or "").strip()

        rating_raw = (request.form.get("rating") or "").strip()
        critique_link = (request.form.get("critique_link") or "").strip()

        rating = None
        if rating_raw:
            try:
                ri = int(rating_raw)
                if 1 <= ri <= 10:
                    rating = ri
            except ValueError:
                rating = None

        if not title:
            flash("Coloque pelo menos o título do filme.", "warn")
            return redirect(url_for("new_entry"))

        conn = get_db()
        cur = conn.cursor()
        cur.execute(q("""
            INSERT INTO entries
            (user_id, title, year, director, keyword, reflection, q1, q2, q3, rating, critique_link, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """), (
            uid,
            title, year, director, keyword, reflection,
            q1, q2, q3,
            rating, critique_link,
            datetime.now().strftime("%d/%m/%Y %H:%M")
        ))
        conn.commit()
        conn.close()

        flash("Guardado. O que ficou em você agora tem lugar.", "ok")
        return redirect(url_for("index"))

    # Renderiza o form vazio
    return render_template("new_entry.html", entry=None, editing=False)


# ====== NOVA ROTA DE EDIÇÃO ======
@app.route("/edit/<int:entry_id>", methods=["GET", "POST"])
@login_required
def edit_entry(entry_id):
    ensure_db_ready()
    uid = session.get("user_id")
    if not uid:
        flash("Sua sessão expirou.", "warn")
        return redirect(url_for("login"))
    
    conn = get_db()
    cur = conn.cursor()
    
    # 1. Busca filme existente para confirmar que é do usuário
    cur.execute(q("SELECT * FROM entries WHERE id = %s AND user_id = %s"), (entry_id, uid))
    entry = cur.fetchone()
    
    if not entry:
        conn.close()
        flash("Filme não encontrado ou você não tem permissão.", "warn")
        return redirect(url_for("index"))

    # 2. Se for POST, atualiza os dados
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        year = (request.form.get("year") or "").strip()
        director = (request.form.get("director") or "").strip()
        keyword = (request.form.get("keyword") or "").strip()
        reflection = (request.form.get("reflection") or "").strip()
        q1 = (request.form.get("q1") or "").strip()
        q2 = (request.form.get("q2") or "").strip()
        q3 = (request.form.get("q3") or "").strip()
        critique_link = (request.form.get("critique_link") or "").strip()
        
        rating_raw = (request.form.get("rating") or "").strip()
        rating = None
        if rating_raw:
            try:
                ri = int(rating_raw)
                if 1 <= ri <= 10:
                    rating = ri
            except ValueError:
                rating = None

        if not title:
            conn.close()
            flash("O título é obrigatório.", "warn")
            return redirect(url_for("edit_entry", entry_id=entry_id))

        try:
            # SQL Update seguro
            cur.execute(q("""
                UPDATE entries 
                SET title=%s, year=%s, director=%s, keyword=%s, 
                    reflection=%s, q1=%s, q2=%s, q3=%s, rating=%s, critique_link=%s
                WHERE id=%s AND user_id=%s
            """), (
                title, year, director, keyword, reflection, 
                q1, q2, q3, rating, critique_link, 
                entry_id, uid
            ))
            conn.commit()
            flash("Filme atualizado com sucesso.", "ok")
            return redirect(url_for("view_entry", entry_id=entry_id))
        except Exception as e:
            flash(f"Erro ao salvar: {e}", "warn")
        finally:
            conn.close()
            
    conn.close()
    
    # 3. Se for GET, renderiza o template 'new_entry' mas com os dados preenchidos
    return render_template("new_entry.html", entry=entry, editing=True)


@app.route("/e/<int:entry_id>")
@login_required
def view_entry(entry_id):
    ensure_db_ready()

    uid = session.get("user_id")
    if not uid:
        flash("Sua sessão expirou. Entre novamente.", "warn")
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute(q("SELECT * FROM entries WHERE id = %s AND user_id = %s"), (entry_id, uid))
    entry = cur.fetchone()
    conn.close()

    if not entry:
        flash("Entrada não encontrada (ou não é sua).", "warn")
        return redirect(url_for("index"))

    return render_template("view_entry.html", e=entry)


@app.route("/delete/<int:entry_id>", methods=["POST"])
@login_required
def delete_entry(entry_id):
    ensure_db_ready()

    uid = session.get("user_id")
    if not uid:
        flash("Sua sessão expirou. Entre novamente.", "warn")
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute(q("DELETE FROM entries WHERE id = %s AND user_id = %s"), (entry_id, uid))
    conn.commit()
    conn.close()

    flash("Entrada removida.", "ok")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
