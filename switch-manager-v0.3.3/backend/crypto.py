import os
from pathlib import Path
from cryptography.fernet import Fernet

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
KEY_FILE = DATA_DIR / "secret.key"


def _load_key() -> bytes:
    env_key = os.getenv("CSM_MASTER_KEY", "").strip()
    if env_key:
        return env_key.encode()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes().strip()
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    try:
        os.chmod(KEY_FILE, 0o600)
    except OSError:
        pass
    return key


FERNET = Fernet(_load_key())


def encrypt(value: str | None) -> str:
    if not value:
        return ""
    return FERNET.encrypt(value.encode()).decode()


def decrypt(value: str | None) -> str:
    if not value:
        return ""
    return FERNET.decrypt(value.encode()).decode()
