import re
import uuid
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt

from app.core.config import get_settings
from app.core.kv import get_kv

PASSWORD_RULES = "12 caractères minimum, avec majuscule, minuscule et chiffre"


def validate_password_strength(password: str) -> None:
    if (
        len(password) < 12
        or not re.search(r"[A-Z]", password)
        or not re.search(r"[a-z]", password)
        or not re.search(r"\d", password)
    ):
        raise ValueError(f"Mot de passe trop faible : {PASSWORD_RULES}")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:
        return False


# A hash used to keep login timing constant when the e-mail is unknown.
DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt(rounds=12)).decode()


def _encode(sub: str, token_type: str, ttl: timedelta, extra: dict) -> str:
    s = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": sub,
        "type": token_type,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + ttl,
        **extra,
    }
    return jwt.encode(payload, s.jwt_secret, algorithm=s.jwt_algorithm)


def create_access_token(user_id: uuid.UUID, org_id: uuid.UUID, role: str) -> str:
    ttl = timedelta(minutes=get_settings().access_token_minutes)
    return _encode(str(user_id), "access", ttl, {"org": str(org_id), "role": role})


def create_refresh_token(user_id: uuid.UUID) -> str:
    return _encode(str(user_id), "refresh", timedelta(days=get_settings().refresh_token_days), {})


class TokenError(Exception):
    pass


def decode_token(token: str, expected_type: str) -> dict:
    s = get_settings()
    try:
        payload = jwt.decode(token, s.jwt_secret, algorithms=[s.jwt_algorithm])
    except jwt.PyJWTError as exc:
        raise TokenError("Jeton invalide ou expiré") from exc
    if payload.get("type") != expected_type:
        raise TokenError("Type de jeton inattendu")
    if get_kv().get(f"revoked:{payload['jti']}"):
        raise TokenError("Jeton révoqué")
    return payload


def revoke_token(payload: dict) -> None:
    ttl = int(payload["exp"] - datetime.now(UTC).timestamp())
    if ttl > 0:
        get_kv().set(f"revoked:{payload['jti']}", "1", ttl)
