import os
import secrets
import threading
import time

SESSION_TTL_SECONDS = max(300, int(os.getenv("CSM_OPERATOR_SESSION_MINUTES", "30")) * 60)
USERNAME_PREFIX = os.getenv("CSM_OPERATOR_USERNAME_PREFIX", "adm-").strip()

_SESSIONS = {}
_LOCK = threading.Lock()


def _now():
    return time.time()


def _cleanup_locked(now=None):
    now = now or _now()
    expired = [token for token, item in _SESSIONS.items() if now - item["last_used"] > SESSION_TTL_SECONDS]
    for token in expired:
        item = _SESSIONS.pop(token, None)
        if item:
            item["password"] = ""
            item["secret"] = ""


def validate_username(username: str) -> str:
    value = (username or "").strip()
    if not value:
        raise ValueError("Informe o usuario administrativo Cisco")
    if USERNAME_PREFIX and not value.lower().startswith(USERNAME_PREFIX.lower()):
        raise ValueError(f"O usuario Cisco deve iniciar com {USERNAME_PREFIX}")
    if len(value) > 120:
        raise ValueError("Usuario Cisco muito longo")
    return value


def create_session(username: str, password: str, secret: str = ""):
    username = validate_username(username)
    if not password:
        raise ValueError("Informe a senha do usuario Cisco")
    token = secrets.token_urlsafe(32)
    now = _now()
    item = {
        "username": username,
        "password": password,
        "secret": secret or "",
        "created_at": now,
        "last_used": now,
    }
    with _LOCK:
        _cleanup_locked(now)
        _SESSIONS[token] = item
    return token, public_session(item, now)


def public_session(item, now=None):
    now = now or _now()
    elapsed = max(0, now - item["last_used"])
    return {
        "active": True,
        "username": item["username"],
        "expires_in_seconds": max(0, int(SESSION_TTL_SECONDS - elapsed)),
        "session_minutes": SESSION_TTL_SECONDS // 60,
        "has_enable_secret": bool(item.get("secret")),
    }


def get_session(token: str | None, touch: bool = True):
    if not token:
        return None
    now = _now()
    with _LOCK:
        _cleanup_locked(now)
        item = _SESSIONS.get(token)
        if not item:
            return None
        if touch:
            item["last_used"] = now
        return {
            "username": item["username"],
            "password": item["password"],
            "secret": item.get("secret", ""),
            "public": public_session(item, now),
        }


def delete_session(token: str | None):
    if not token:
        return False
    with _LOCK:
        item = _SESSIONS.pop(token, None)
    if item:
        item["password"] = ""
        item["secret"] = ""
        return True
    return False
