import json
import hmac
import hashlib
import os
import re
import secrets
import smtplib
import ssl
import time
import threading
import webbrowser
from http.cookies import SimpleCookie
from datetime import date
from email.message import EmailMessage
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
DEFAULT_DATABASE = "/var/data" if os.environ.get("RENDER") else str(ROOT / "database")
DATABASE = Path(os.environ.get("DATA_DIR", DEFAULT_DATABASE))
DATA_FILE = DATABASE / "db.json"
USERS_FILE = DATABASE / "users.json"
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8080"))
SESSION_COOKIE = "asia_session"
SESSION_MAX_AGE = 8 * 60 * 60
SESSIONS = {}
SETUP_LOCK = threading.Lock()
PASSWORD_ITERATIONS = 310_000
PERMISSIONS = {
    "data.view",
    "courses.manage",
    "students.manage",
    "attendance.manage",
    "payments.manage",
    "workspace.manage",
    "expenses.manage",
    "closing.manage",
    "backups.manage",
    "users.manage",
}
ALL_PERMISSIONS = sorted(PERMISSIONS)


def empty_user_store():
    return {"users": {}, "roles": []}


def get_user_store():
    return read_json(USERS_FILE, empty_user_store())


def save_user_store(store):
    write_json(USERS_FILE, store)


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return {"salt": salt.hex(), "hash": digest.hex(), "iterations": PASSWORD_ITERATIONS}


def verify_password(password, stored):
    try:
        salt = bytes.fromhex(stored["salt"])
        iterations = int(stored["iterations"])
        if iterations < 100_000 or iterations > 1_000_000:
            return False
        expected = bytes.fromhex(stored["hash"])
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except (KeyError, TypeError, ValueError):
        return False


def role_permissions(store, user):
    role = next((item for item in store["roles"] if item["id"] == user["roleId"]), None)
    return set(role["permissions"]) if role else set()


def session_user(handler):
    cookie = SimpleCookie()
    cookie.load(handler.headers.get("Cookie", ""))
    morsel = cookie.get(SESSION_COOKIE)
    session = SESSIONS.get(morsel.value) if morsel else None
    if not session or session["expires"] <= time.time():
        if morsel:
            SESSIONS.pop(morsel.value, None)
        return None
    store = get_user_store()
    user = store["users"].get(session["username"])
    if not user or not user["active"]:
        SESSIONS.pop(morsel.value, None)
        return None
    session["expires"] = time.time() + SESSION_MAX_AGE
    return store, session["username"], user, role_permissions(store, user)


def data_change_permissions(old, new):
    required = set()

    for field, permission in (
        ("dailyPayments", "payments.manage"),
        ("workspace", "workspace.manage"),
        ("expenses", "expenses.manage"),
        ("owners", "closing.manage"),
        ("closings", "closing.manage"),
    ):
        if old.get(field, []) != new.get(field, []):
            required.add(permission)

    old_courses = old.get("courses", [])
    new_courses = new.get("courses", [])
    if len(old_courses) != len(new_courses):
        required.add("courses.manage")
    for index in range(max(len(old_courses), len(new_courses))):
        previous = old_courses[index] if index < len(old_courses) else None
        current = new_courses[index] if index < len(new_courses) else None
        if previous is None or current is None:
            required.add("courses.manage")
            course = previous or current
            if course and course.get("students"):
                required.update(("students.manage", "attendance.manage"))
                if any(
                    student.get("paid") or any(
                        session.get("paid50") for session in student.get("sessions", [])
                    )
                    for student in course["students"]
                ):
                    required.add("payments.manage")
            continue

        for field in ("name", "professor", "fee", "instructorPercentage"):
            if previous.get(field) != current.get(field):
                required.add("courses.manage")
        course_known = {"name", "professor", "fee", "instructorPercentage", "students"}
        if (set(previous) - course_known != set(current) - course_known or
                any(previous.get(key) != current.get(key) for key in (set(previous) & set(current)) - course_known)):
            required.add("users.manage")

        old_students = previous.get("students", [])
        new_students = current.get("students", [])
        if len(old_students) != len(new_students):
            required.add("students.manage")
        for student_index in range(max(len(old_students), len(new_students))):
            old_student = old_students[student_index] if student_index < len(old_students) else None
            new_student = new_students[student_index] if student_index < len(new_students) else None
            if old_student is None or new_student is None:
                required.add("students.manage")
                student = old_student or new_student
                if student and student.get("sessions"):
                    required.add("attendance.manage")
                if student and student.get("paid"):
                    required.add("payments.manage")
                continue
            for field in ("name", "phone", "fee"):
                if old_student.get(field) != new_student.get(field):
                    required.add("students.manage")
            student_known = {"name", "phone", "fee", "paid", "sessions"}
            if (set(old_student) - student_known != set(new_student) - student_known or
                    any(old_student.get(key) != new_student.get(key) for key in (set(old_student) & set(new_student)) - student_known)):
                required.add("users.manage")
            if old_student.get("paid") != new_student.get("paid"):
                required.add("payments.manage")
            old_sessions = old_student.get("sessions", [])
            new_sessions = new_student.get("sessions", [])
            if old_sessions != new_sessions:
                required.add("attendance.manage")
                for session_index in range(max(len(old_sessions), len(new_sessions))):
                    old_session = old_sessions[session_index] if session_index < len(old_sessions) else None
                    new_session = new_sessions[session_index] if session_index < len(new_sessions) else None
                    if old_session is None or new_session is None:
                        if (old_session or new_session or {}).get("paid50"):
                            required.add("payments.manage")
                    elif old_session.get("paid50") != new_session.get("paid50"):
                        required.add("payments.manage")

    known_fields = {"courses", "dailyPayments", "workspace", "expenses", "owners", "closings"}
    if (set(old) - known_fields != set(new) - known_fields or
            any(old.get(key) != new.get(key) for key in set(old) - known_fields)):
        required.add("users.manage")
    return required


def valid_data_shape(data):
    list_fields = ("courses", "workspace", "dailyPayments", "expenses", "owners", "closings")
    if not isinstance(data, dict) or any(not isinstance(data.get(field), list) for field in list_fields):
        return False
    if any(not isinstance(entry, dict) for field in list_fields for entry in data[field]):
        return False
    return all(
        isinstance(course.get("students", []), list) and
        all(isinstance(student, dict) for student in course.get("students", []))
        for course in data["courses"]
    )


def default_data():
    return {
        "courses": [],
        "workspace": [],
        "dailyPayments": [],
        "expenses": [],
        "owners": [],
        "closings": [],
    }


def valid_user_store(store):
    if not isinstance(store, dict) or not isinstance(store.get("users"), dict) or not isinstance(store.get("roles"), list):
        return False

    role_ids = set()
    for role in store["roles"]:
        if not isinstance(role, dict):
            return False
        role_id = role.get("id")
        name = role.get("name")
        permissions = role.get("permissions")
        if (not isinstance(role_id, str) or not role_id or role_id in role_ids or
                not isinstance(name, str) or not name or len(name) > 80 or
                not isinstance(permissions, list) or
                any(not isinstance(permission, str) or permission not in PERMISSIONS for permission in permissions)):
            return False
        role_ids.add(role_id)

    active_user_with_admin_access = False
    for username, user in store["users"].items():
        if (not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username) or
                not isinstance(user, dict) or not isinstance(user.get("active"), bool) or
                user.get("roleId") not in role_ids):
            return False
        password = user.get("password")
        if not isinstance(password, dict):
            return False
        try:
            salt = bytes.fromhex(password["salt"])
            digest = bytes.fromhex(password["hash"])
            iterations = int(password["iterations"])
        except (KeyError, TypeError, ValueError):
            return False
        if not salt or len(digest) != hashlib.sha256().digest_size or not 100_000 <= iterations <= 1_000_000:
            return False
        role = next(item for item in store["roles"] if item["id"] == user["roleId"])
        if user["active"] and "users.manage" in role["permissions"]:
            active_user_with_admin_access = True

    return not store["users"] or active_user_with_admin_access


def build_full_backup():
    data = read_json(DATA_FILE, default_data())
    for key, value in default_data().items():
        data.setdefault(key, value)
    return {
        "format": "asia-center-backup",
        "version": 1,
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "data": data,
        "accounts": read_json(USERS_FILE, empty_user_store()),
    }


def send_backup_email(recipient):
    sender = os.environ.get("ASIA_GMAIL_ADDRESS", "").strip()
    app_password = re.sub(r"\s+", "", os.environ.get("ASIA_GMAIL_APP_PASSWORD", ""))
    if not sender or not app_password:
        raise RuntimeError("Email sender is not configured")

    backup = build_full_backup()
    message = EmailMessage()
    message["Subject"] = f"نسخة احتياطية - بيانات سنتر آسيا بتاريخ {date.today().isoformat()}"
    message["From"] = sender
    message["To"] = recipient
    message.set_content("مرفق نسخة بيانات سنتر آسيا الاحتياطية.")
    message.add_attachment(
        json.dumps(backup, ensure_ascii=False, indent=2).encode("utf-8"),
        maintype="application",
        subtype="json",
        filename=f"asia_center_backup_{date.today().isoformat()}.json",
    )

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=30) as smtp:
        smtp.login(sender, app_password)
        smtp.send_message(message)


def read_json(path, fallback):
    if not path.exists():
        return fallback
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND), **kwargs)

    def log_message(self, format, *args):
        print("[%s] %s" % (self.log_date_time_string(), format % args))

    def _send_json(self, payload, status=200, cookie=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length < 0 or length > 12 * 1024 * 1024:
            raise ValueError("invalid request size")
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8"))

    def _require_permission(self, permission):
        identity = session_user(self)
        if identity is None:
            self._send_json({"ok": False, "error": "authentication required"}, 401)
            return None
        if permission not in identity[3]:
            self._send_json({"ok": False, "error": "permission denied"}, 403)
            return None
        return identity

    def _same_origin(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        from urllib.parse import urlsplit
        return urlsplit(origin).netloc.lower() == self.headers.get("Host", "").lower()

    def _session_cookie(self, value, max_age):
        from urllib.parse import urlsplit
        origin = self.headers.get("Origin", "")
        forwarded_protocol = self.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
        secure = "; Secure" if forwarded_protocol == "https" or urlsplit(origin).scheme.lower() == "https" else ""
        return f"{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"

    def do_GET(self):
        path = unquote(self.path.split("?", 1)[0])
        if path == "/api/auth/session":
            identity = session_user(self)
            if identity is None:
                self._send_json({"authenticated": False, "setupRequired": not get_user_store()["users"]})
                return
            store, username, user, permissions = identity
            self._send_json({
                "authenticated": True,
                "username": username,
                "role": next((role["name"] for role in store["roles"] if role["id"] == user["roleId"]), ""),
                "permissions": sorted(permissions),
            })
            return
        if path == "/api/data":
            if self._require_permission("data.view") is None:
                return
            data = read_json(DATA_FILE, {
                "courses": [],
                "workspace": [],
                "dailyPayments": [],
                "expenses": [],
                "owners": [],
                "closings": [],
            })
            data.setdefault("courses", [])
            data.setdefault("workspace", [])
            data.setdefault("dailyPayments", [])
            data.setdefault("expenses", [])
            data.setdefault("owners", [])
            data.setdefault("closings", [])
            self._send_json(data)
            return
        if path == "/api/data/export":
            if self._require_permission("backups.manage") is None:
                return
            self._send_json(build_full_backup())
            return
        if path in ("/api/admin/users", "/api/admin/roles"):
            identity = self._require_permission("users.manage")
            if identity is None:
                return
            store = identity[0]
            if path.endswith("/roles"):
                self._send_json({"roles": store["roles"], "permissions": ALL_PERMISSIONS})
            else:
                self._send_json({"users": [
                    {"username": username, "roleId": user["roleId"], "active": user["active"]}
                    for username, user in store["users"].items()
                ], "roles": store["roles"]})
            return
        if path in ("/", "/index.html"):
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        path = unquote(self.path.split("?", 1)[0])
        if path.startswith("/api/") and not self._same_origin():
            self._send_json({"ok": False, "error": "cross-origin request rejected"}, 403)
            return
        if path in ("/api/auth/setup", "/api/auth/login", "/api/auth/logout", "/api/auth/password"):
            try:
                data = self._read_body()
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                self._send_json({"ok": False, "error": "invalid request"}, 400)
                return
            if not isinstance(data, dict):
                self._send_json({"ok": False, "error": "invalid request"}, 400)
                return
            if path == "/api/auth/setup":
                username = str(data.get("username") or "").strip()
                password = str(data.get("password") or "")
                if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username) or len(password) < 12:
                    self._send_json({"ok": False, "error": "Use a 3-40 character username and password of at least 12 characters."}, 400)
                    return
                with SETUP_LOCK:
                    store = get_user_store()
                    if store["users"]:
                        self._send_json({"ok": False, "error": "setup already completed"}, 409)
                        return
                    admin_role = {"id": secrets.token_urlsafe(12), "name": "Administrator", "permissions": ALL_PERMISSIONS}
                    store["roles"] = [admin_role]
                    store["users"] = {username: {
                        "password": hash_password(password),
                        "roleId": admin_role["id"],
                        "active": True,
                    }}
                    save_user_store(store)
                sid = secrets.token_urlsafe(32)
                SESSIONS[sid] = {"username": username, "expires": time.time() + SESSION_MAX_AGE}
                self._send_json({"ok": True}, cookie=self._session_cookie(sid, SESSION_MAX_AGE))
                return
            if path == "/api/auth/login":
                username = str(data.get("username") or "").strip()
                user = get_user_store()["users"].get(username)
                if not user or not user["active"] or not verify_password(str(data.get("password") or ""), user["password"]):
                    self._send_json({"ok": False, "error": "Invalid username or password."}, 401)
                    return
                sid = secrets.token_urlsafe(32)
                SESSIONS[sid] = {"username": username, "expires": time.time() + SESSION_MAX_AGE}
                self._send_json({"ok": True}, cookie=self._session_cookie(sid, SESSION_MAX_AGE))
                return
            if path == "/api/auth/logout":
                cookie = SimpleCookie()
                cookie.load(self.headers.get("Cookie", ""))
                morsel = cookie.get(SESSION_COOKIE)
                if morsel:
                    SESSIONS.pop(morsel.value, None)
                self._send_json({"ok": True}, cookie=self._session_cookie("", 0))
                return
            identity = session_user(self)
            if identity is None:
                self._send_json({"ok": False, "error": "authentication required"}, 401)
                return
            current_user = identity[2]
            old_password = str(data.get("oldPassword") or "")
            new_password = str(data.get("newPassword") or "")
            if not verify_password(old_password, current_user["password"]) or len(new_password) < 12:
                self._send_json({"ok": False, "error": "Current password is incorrect or new password is too short."}, 400)
                return
            current_user["password"] = hash_password(new_password)
            save_user_store(identity[0])
            self._send_json({"ok": True})
            return
        if path in ("/api/admin/users", "/api/admin/roles"):
            identity = self._require_permission("users.manage")
            if identity is None:
                return
            try:
                data = self._read_body()
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                self._send_json({"ok": False, "error": "invalid request"}, 400)
                return
            if not isinstance(data, dict):
                self._send_json({"ok": False, "error": "invalid request"}, 400)
                return
            store = identity[0]
            if path.endswith("/roles"):
                action = data.get("action")
                if action == "delete":
                    role_id = str(data.get("id") or "")
                    if any(user["roleId"] == role_id for user in store["users"].values()):
                        self._send_json({"ok": False, "error": "Role is assigned to users."}, 409)
                        return
                    store["roles"] = [role for role in store["roles"] if role["id"] != role_id]
                else:
                    role_id = str(data.get("id") or "")
                    name = str(data.get("name") or "").strip()
                    permissions = data.get("permissions")
                    if (not name or len(name) > 80 or not isinstance(permissions, list) or
                            any(not isinstance(item, str) or item not in PERMISSIONS for item in permissions)):
                        self._send_json({"ok": False, "error": "Invalid role name or permissions."}, 400)
                        return
                    if role_id:
                        role = next((item for item in store["roles"] if item["id"] == role_id), None)
                        if role is None:
                            self._send_json({"ok": False, "error": "Role not found."}, 404)
                            return
                        role.update({"name": name, "permissions": sorted(set(permissions))})
                    else:
                        store["roles"].append({"id": secrets.token_urlsafe(12), "name": name, "permissions": sorted(set(permissions))})
                if not any(user["active"] and "users.manage" in role_permissions(store, user) for user in store["users"].values()):
                    self._send_json({"ok": False, "error": "At least one active user must retain user-management permission."}, 409)
                    return
                save_user_store(store)
                self._send_json({"ok": True})
                return

            action = data.get("action")
            username = str(data.get("username") or "").strip()
            if action == "delete":
                if username not in store["users"]:
                    self._send_json({"ok": False, "error": "User not found."}, 404)
                    return
                if username == identity[1]:
                    self._send_json({"ok": False, "error": "You cannot remove your own account."}, 400)
                    return
                del store["users"][username]
            elif action == "save":
                role_id = str(data.get("roleId") or "")
                if not any(role["id"] == role_id for role in store["roles"]):
                    self._send_json({"ok": False, "error": "Choose a valid role."}, 400)
                    return
                existing = store["users"].get(username)
                password = str(data.get("password") or "")
                if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username) or (existing is None and len(password) < 12) or (password and len(password) < 12):
                    self._send_json({"ok": False, "error": "Use a valid username and password of at least 12 characters."}, 400)
                    return
                if existing is None:
                    existing = {"password": hash_password(password), "active": True}
                    store["users"][username] = existing
                elif password:
                    existing["password"] = hash_password(password)
                existing["roleId"] = role_id
                if not isinstance(data.get("active", True), bool):
                    self._send_json({"ok": False, "error": "Invalid active status."}, 400)
                    return
                existing["active"] = data.get("active", True)
            else:
                self._send_json({"ok": False, "error": "Invalid action."}, 400)
                return
            if not any(user["active"] and "users.manage" in role_permissions(store, user) for user in store["users"].values()):
                self._send_json({"ok": False, "error": "At least one active user must retain user-management permission."}, 409)
                return
            save_user_store(store)
            self._send_json({"ok": True})
            return
        if path == "/api/send-backup":
            if self._require_permission("backups.manage") is None:
                return
            try:
                data = self._read_body()
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                self._send_json({"ok": False, "error": "بيانات الطلب غير صالحة."}, 400)
                return
            if not isinstance(data, dict):
                self._send_json({"ok": False, "error": "بيانات الطلب غير صالحة."}, 400)
                return

            recipient = str(data.get("recipient") or "").strip()
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", recipient):
                self._send_json({"ok": False, "error": "عنوان البريد الإلكتروني غير صالح."}, 400)
                return

            if (
                not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", os.environ.get("ASIA_GMAIL_ADDRESS", "").strip())
                or not re.sub(r"\s+", "", os.environ.get("ASIA_GMAIL_APP_PASSWORD", ""))
            ):
                self._send_json({
                    "ok": False,
                    "error": "لم يتم إعداد Gmail على هذا الكمبيوتر. اضبط ASIA_GMAIL_ADDRESS وASIA_GMAIL_APP_PASSWORD ثم أعد تشغيل البرنامج.",
                }, 503)
                return

            try:
                send_backup_email(recipient)
            except (smtplib.SMTPException, OSError, RuntimeError) as exc:
                print("Backup email delivery failed: %s" % type(exc).__name__)
                self._send_json({
                    "ok": False,
                    "error": "تعذر إرسال البريد عبر Gmail. تحقق من إعدادات حساب المرسل واتصال الإنترنت.",
                }, 502)
                return

            self._send_json({"ok": True})
            return
        if path == "/api/data/restore":
            if self._require_permission("backups.manage") is None:
                return
            try:
                data = self._read_body()
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                self._send_json({"ok": False, "error": "invalid backup data"}, 400)
                return
            if not isinstance(data, dict):
                self._send_json({"ok": False, "error": "invalid backup structure"}, 400)
                return
            is_full_backup = data.get("format") == "asia-center-backup"
            if is_full_backup:
                if data.get("version") != 1 or not isinstance(data.get("data"), dict):
                    self._send_json({"ok": False, "error": "unsupported backup format"}, 400)
                    return
                backup_data = data["data"]
                account_store = data.get("accounts")
                if not valid_user_store(account_store):
                    self._send_json({"ok": False, "error": "invalid account data in backup"}, 400)
                    return
            else:
                backup_data = data
                account_store = None
                for key in ("expenses", "owners", "closings"):
                    backup_data.setdefault(key, [])
            if not valid_data_shape(backup_data):
                self._send_json({"ok": False, "error": "invalid backup structure"}, 400)
                return
            previous_data = read_json(DATA_FILE, default_data())
            previous_accounts = read_json(USERS_FILE, empty_user_store()) if is_full_backup else None
            try:
                write_json(DATA_FILE, backup_data)
                if is_full_backup:
                    write_json(USERS_FILE, account_store)
            except OSError:
                write_json(DATA_FILE, previous_data)
                if is_full_backup:
                    write_json(USERS_FILE, previous_accounts)
                raise
            if is_full_backup:
                SESSIONS.clear()
            self._send_json({"ok": True})
            return
        if path == "/api/data":
            identity = self._require_permission("data.view")
            if identity is None:
                return
            try:
                data = self._read_body()
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                self._send_json({"ok": False, "error": "invalid data"}, 400)
                return
            if not valid_data_shape(data):
                self._send_json({"ok": False, "error": "invalid data"}, 400)
                return
            data.setdefault("courses", [])
            data.setdefault("workspace", [])
            data.setdefault("dailyPayments", [])
            data.setdefault("expenses", [])
            data.setdefault("owners", [])
            data.setdefault("closings", [])
            old_data = read_json(DATA_FILE, {})
            required = data_change_permissions(old_data, data)
            missing = required - identity[3]
            if missing:
                self._send_json({"ok": False, "error": "permission denied", "permissions": sorted(missing)}, 403)
                return
            write_json(DATA_FILE, data)
            self._send_json({"ok": True})
            return
        self.send_error(404, "Not Found")


def main():
    if os.environ.get("RENDER") and not DATABASE.is_mount():
        raise RuntimeError(
            f"Persistent storage is not mounted at {DATABASE}. Attach a Render persistent disk at this path before starting."
        )
    DATABASE.mkdir(parents=True, exist_ok=True)
    if not DATA_FILE.exists():
        write_json(DATA_FILE, {
            "courses": [],
            "workspace": [],
            "dailyPayments": [],
            "expenses": [],
            "owners": [],
            "closings": [],
        })
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    url = f"http://127.0.0.1:{PORT}/"
    print("Asia Center is running")
    print(url)
    if not os.environ.get("RENDER"):
        print("Close this window to stop.")
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
