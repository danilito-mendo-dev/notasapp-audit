"""
NotasApp - Gestor de notas personales con Flask + SQLite (sin ORM).

Ejecutar:  python app.py
"""
import os
import re
import secrets
import sqlite3
from functools import wraps

import nh3
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

# ======================================================================
# CONFIGURACIÓN (todo aquí, como pediste)
# ======================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "notasapp.db")

# Por defecto la app solo escucha en esta máquina (127.0.0.1).
# Para exponerla en la red hay que pedirlo de forma explícita, p. ej.:
#   NOTASAPP_HOST=0.0.0.0 python app.py   (y protegerla con el firewall)
HOST = os.environ.get("NOTASAPP_HOST", "127.0.0.1")
PORT = 5000
# Depurador desactivado: el depurador interactivo de Werkzeug permite
# ejecutar código Python en el servidor (CWE-489 / CWE-94).
DEBUG = False

# Administrador que se crea automáticamente la primera vez.
ADMIN_USERNAME = "admin"
ADMIN_EMAIL = "admin@notasapp.local"
# None = se genera una contraseña aleatoria y se muestra UNA vez en la terminal.
# Puedes poner aquí una tuya (p. ej. "MiClaveDePrueba123") si lo prefieres.
ADMIN_PASSWORD = None

# Etiquetas HTML permitidas en los comentarios (todo lo demás se elimina).
ALLOWED_COMMENT_TAGS = {"b", "i", "u", "strong", "em", "br", "p", "code", "ul", "ol", "li"}

MAX_TITLE_LENGTH = 200
MAX_CONTENT_LENGTH = 20_000
MAX_COMMENT_LENGTH = 2_000
MIN_PASSWORD_LENGTH = 8


# ======================================================================
# CLAVE SECRETA
# Firma las cookies de sesión. Se genera sola y se guarda en un archivo
# (.secret_key) para que no quede escrita en el código: si subes app.py a
# GitHub, nadie podrá falsificar sesiones con ella.
# ======================================================================
def load_secret_key():
    path = os.path.join(BASE_DIR, ".secret_key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
        os.chmod(path, 0o600)
    with open(path) as f:
        return f.read().strip()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,     # JavaScript no puede leer la cookie
    SESSION_COOKIE_SAMESITE="Lax",    # protección extra contra CSRF
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,  # máx. 1 MB por petición
)


# ======================================================================
# BASE DE DATOS (sqlite3 puro)
# ======================================================================
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL,
    password_hash TEXT    NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title      TEXT    NOT NULL,
    content    TEXT    NOT NULL DEFAULT '',
    is_public  INTEGER NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS comments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    note_id    INTEGER NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body       TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_notes_user    ON notes(user_id);
CREATE INDEX IF NOT EXISTS idx_comments_note ON comments(note_id);
"""


def connect_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row          # filas accesibles como row["columna"]
    conn.execute("PRAGMA foreign_keys = ON")  # activa ON DELETE CASCADE
    return conn


def get_db():
    """Una conexión por petición, guardada en g."""
    if "db" not in g:
        g.db = connect_db()
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Crea las tablas (si no existen) y el usuario administrador."""
    conn = connect_db()
    try:
        conn.executescript(SCHEMA)
        exists = conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (ADMIN_USERNAME,)
        ).fetchone()
        if not exists:
            password = ADMIN_PASSWORD or secrets.token_urlsafe(12)
            conn.execute(
                "INSERT INTO users (username, email, password_hash, is_admin) "
                "VALUES (?, ?, ?, 1)",
                (ADMIN_USERNAME, ADMIN_EMAIL, generate_password_hash(password)),
            )
            conn.commit()
            # La contraseña NO se imprime en la terminal (CWE-532): se guarda
            # en un archivo legible solo por el dueño, fuera de git.
            pw_path = os.path.join(BASE_DIR, ".admin_password")
            fd = os.open(pw_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(password + "\n")
            print("=" * 60)
            print(" Usuario administrador creado")
            print(f"   usuario:    {ADMIN_USERNAME}")
            print(f"   contraseña: guardada en {pw_path} (permisos 600)")
            print(" Léela con:  cat .admin_password  y luego bórrala.")
            print("=" * 60)
    finally:
        conn.close()


# ======================================================================
# SEGURIDAD: usuario actual, decoradores y protección CSRF
# ======================================================================
@app.before_request
def load_logged_in_user():
    user_id = session.get("user_id")
    g.user = None
    if user_id is not None:
        g.user = get_db().execute(
            "SELECT id, username, email, is_admin FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if g.user is None:  # el usuario fue borrado
            session.clear()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Inicia sesión para continuar.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not g.user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


@app.before_request
def csrf_protect():
    """Todo POST debe traer el token secreto de la sesión.
    Así otra web no puede enviar formularios en tu nombre."""
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not secrets.compare_digest(sent, expected):
            abort(400, description="Token CSRF inválido. Recarga la página.")


@app.context_processor
def inject_globals():
    return {"csrf_token": get_csrf_token}


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    return response


@app.template_filter("safe_html")
def safe_html(text):
    """Limpia el HTML del comentario dejando solo las etiquetas permitidas
    y sin atributos (nada de onclick, style, href=javascript:...)."""
    return Markup(nh3.clean(text, tags=ALLOWED_COMMENT_TAGS, attributes={}))


# ======================================================================
# FUNCIONES AUXILIARES
# ======================================================================
def get_note_or_404(note_id):
    note = get_db().execute(
        "SELECT n.*, u.username AS author FROM notes n "
        "JOIN users u ON u.id = n.user_id WHERE n.id = ?",
        (note_id,),
    ).fetchone()
    if note is None:
        abort(404)
    return note


def can_view(note):
    return note["is_public"] or note["user_id"] == g.user["id"]


def get_own_note_or_404(note_id):
    """Para editar/borrar: solo el dueño. A los demás les decimos 404
    para no revelar siquiera que la nota existe."""
    note = get_note_or_404(note_id)
    if note["user_id"] != g.user["id"]:
        abort(404)
    return note


def validate_note(title, content):
    if not title:
        return "El título es obligatorio."
    if len(title) > MAX_TITLE_LENGTH:
        return f"El título no puede superar {MAX_TITLE_LENGTH} caracteres."
    if len(content) > MAX_CONTENT_LENGTH:
        return f"El contenido no puede superar {MAX_CONTENT_LENGTH} caracteres."
    return None


# ======================================================================
# AUTENTICACIÓN
# ======================================================================
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        error = None
        if not USERNAME_RE.match(username):
            error = "El usuario debe tener 3-30 caracteres: letras, números o _."
        elif not EMAIL_RE.match(email):
            error = "Introduce un correo válido."
        elif len(password) < MIN_PASSWORD_LENGTH:
            error = f"La contraseña debe tener al menos {MIN_PASSWORD_LENGTH} caracteres."
        elif password != confirm:
            error = "Las contraseñas no coinciden."

        if error is None:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, generate_password_hash(password)),
                )
                db.commit()
            except sqlite3.IntegrityError:  # UNIQUE(username) violado
                error = "Ese nombre de usuario ya existe."
            else:
                flash("Cuenta creada. Ya puedes iniciar sesión.", "success")
                return redirect(url_for("login"))
        flash(error, "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()  # evita "session fixation"
            session["user_id"] = user["id"]
            return redirect(url_for("index"))
        # Mismo mensaje en ambos casos: no revelamos qué usuarios existen.
        flash("Usuario o contraseña incorrectos.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Has cerrado sesión.", "success")
    return redirect(url_for("login"))


# ======================================================================
# NOTAS
# ======================================================================
@app.route("/")
@login_required
def index():
    db = get_db()
    q = request.args.get("q", "").strip()
    if q:
        # Escapamos % y _ para que se busquen literalmente.
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        notes = db.execute(
            "SELECT n.id, n.title, n.content, n.is_public, n.updated_at, n.user_id, "
            "       u.username AS author "
            "FROM notes n JOIN users u ON u.id = n.user_id "
            "WHERE (n.user_id = ? OR n.is_public = 1) "
            "  AND (n.title LIKE ? ESCAPE '\\' OR n.content LIKE ? ESCAPE '\\') "
            "ORDER BY n.updated_at DESC",
            (g.user["id"], like, like),
        ).fetchall()
        return render_template("index.html", notes=notes, public_notes=[], q=q)

    notes = db.execute(
        "SELECT id, title, content, is_public, updated_at, user_id, ? AS author "
        "FROM notes WHERE user_id = ? ORDER BY updated_at DESC",
        (g.user["username"], g.user["id"]),
    ).fetchall()
    public_notes = db.execute(
        "SELECT n.id, n.title, n.content, n.is_public, n.updated_at, n.user_id, "
        "       u.username AS author "
        "FROM notes n JOIN users u ON u.id = n.user_id "
        "WHERE n.is_public = 1 AND n.user_id != ? "
        "ORDER BY n.updated_at DESC LIMIT 20",
        (g.user["id"],),
    ).fetchall()
    return render_template("index.html", notes=notes, public_notes=public_notes, q="")


@app.route("/notes/new", methods=["GET", "POST"])
@login_required
def note_new():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "")
        is_public = 1 if request.form.get("is_public") else 0
        error = validate_note(title, content)
        if error is None:
            db = get_db()
            cur = db.execute(
                "INSERT INTO notes (user_id, title, content, is_public) VALUES (?, ?, ?, ?)",
                (g.user["id"], title, content, is_public),
            )
            db.commit()
            flash("Nota creada.", "success")
            return redirect(url_for("note_detail", note_id=cur.lastrowid))
        flash(error, "error")
    return render_template("note_form.html", note=None)


@app.route("/notes/<int:note_id>")
@login_required
def note_detail(note_id):
    note = get_note_or_404(note_id)
    if not can_view(note):
        abort(404)
    comments = get_db().execute(
        "SELECT c.id, c.body, c.created_at, c.user_id, u.username "
        "FROM comments c JOIN users u ON u.id = c.user_id "
        "WHERE c.note_id = ? ORDER BY c.created_at ASC, c.id ASC",
        (note_id,),
    ).fetchall()
    return render_template(
        "note_detail.html", note=note, comments=comments,
        allowed_tags=sorted(ALLOWED_COMMENT_TAGS),
    )


@app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
@login_required
def note_edit(note_id):
    note = get_own_note_or_404(note_id)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "")
        is_public = 1 if request.form.get("is_public") else 0
        error = validate_note(title, content)
        if error is None:
            db = get_db()
            db.execute(
                "UPDATE notes SET title = ?, content = ?, is_public = ?, "
                "updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
                (title, content, is_public, note_id, g.user["id"]),
            )
            db.commit()
            flash("Nota actualizada.", "success")
            return redirect(url_for("note_detail", note_id=note_id))
        flash(error, "error")
    return render_template("note_form.html", note=note)


@app.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def note_delete(note_id):
    get_own_note_or_404(note_id)
    db = get_db()
    db.execute("DELETE FROM notes WHERE id = ? AND user_id = ?", (note_id, g.user["id"]))
    db.commit()
    flash("Nota borrada.", "success")
    return redirect(url_for("index"))


# ======================================================================
# COMENTARIOS
# ======================================================================
@app.route("/notes/<int:note_id>/comments", methods=["POST"])
@login_required
def comment_add(note_id):
    note = get_note_or_404(note_id)
    if not can_view(note):
        abort(404)
    body = request.form.get("body", "").strip()
    if not body:
        flash("El comentario está vacío.", "error")
    elif len(body) > MAX_COMMENT_LENGTH:
        flash(f"El comentario no puede superar {MAX_COMMENT_LENGTH} caracteres.", "error")
    else:
        db = get_db()
        db.execute(
            "INSERT INTO comments (note_id, user_id, body) VALUES (?, ?, ?)",
            (note_id, g.user["id"], body),
        )
        db.commit()
        flash("Comentario publicado.", "success")
    return redirect(url_for("note_detail", note_id=note_id))


@app.route("/comments/<int:comment_id>/delete", methods=["POST"])
@login_required
def comment_delete(comment_id):
    db = get_db()
    comment = db.execute(
        "SELECT c.id, c.user_id, c.note_id, n.user_id AS note_owner "
        "FROM comments c JOIN notes n ON n.id = c.note_id WHERE c.id = ?",
        (comment_id,),
    ).fetchone()
    if comment is None:
        abort(404)
    # Puede borrarlo su autor o el dueño de la nota.
    if g.user["id"] not in (comment["user_id"], comment["note_owner"]):
        abort(403)
    db.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    db.commit()
    flash("Comentario borrado.", "success")
    return redirect(url_for("note_detail", note_id=comment["note_id"]))


# ======================================================================
# PERFIL
# ======================================================================
@app.route("/user/<int:user_id>")
@login_required
def profile(user_id):
    db = get_db()
    user = db.execute(
        "SELECT id, username, email, is_admin, created_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if user is None:
        abort(404)
    # El correo es un dato privado: solo lo ve el propio usuario o un admin.
    show_email = g.user["id"] == user["id"] or bool(g.user["is_admin"])
    public_notes = db.execute(
        "SELECT id, title, updated_at FROM notes "
        "WHERE user_id = ? AND is_public = 1 ORDER BY updated_at DESC",
        (user_id,),
    ).fetchall()
    return render_template(
        "profile.html", profile_user=user, show_email=show_email, public_notes=public_notes
    )


# ======================================================================
# ADMINISTRACIÓN
# ======================================================================
@app.route("/admin")
@admin_required
def admin_panel():
    users = get_db().execute(
        "SELECT u.id, u.username, u.email, u.is_admin, u.created_at, "
        "       COUNT(n.id) AS note_count "
        "FROM users u LEFT JOIN notes n ON n.user_id = u.id "
        "GROUP BY u.id ORDER BY u.id"
    ).fetchall()
    return render_template("admin.html", users=users)


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    if user_id == g.user["id"]:
        flash("No puedes borrar tu propia cuenta desde el panel.", "error")
        return redirect(url_for("admin_panel"))
    db = get_db()
    cur = db.execute("DELETE FROM users WHERE id = ?", (user_id,))  # CASCADE borra sus notas y comentarios
    db.commit()
    if cur.rowcount:
        flash("Usuario borrado junto con sus notas y comentarios.", "success")
    else:
        flash("Ese usuario no existe.", "error")
    return redirect(url_for("admin_panel"))


# ======================================================================
# ERRORES
# ======================================================================
@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def http_error(err):
    return render_template("error.html", error=err), err.code


# La base de datos se crea sola al importar/arrancar la app.
init_db()

if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=DEBUG)
