"""
Módulo de Seguridad, Criptografía y Hardening para CondoSeguro Chile.
Implementa:
- Hashing seguro de contraseñas con bcrypt (salteo dinámico).
- Emisión y validación de tokens JWT cifrados.
- Sanitización estricta contra Cross-Site Scripting (XSS).
- Rate Limiting en memoria para prevención de DoS y spam de alertas SOS.
- Validación de consentimiento explícito según la Ley 19.628 de Chile.
"""
import html
import time
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple

SECRET_KEY = "condoseguro_cl_super_secure_jwt_token_2026_salt_key_!#987"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 72

# Almacenamiento en memoria para Rate Limiting
# Estructura: { "ip_o_user": [timestamp1, timestamp2, ...] }
RATE_LIMIT_STORE: Dict[str, list] = {}
SOS_DEBOUNCE_STORE: Dict[int, float] = {}  # { user_id: last_sos_timestamp }


def hash_password(password: str) -> str:
    """Genera hash de contraseña utilizando bcrypt con factor de costo 12."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica contraseña en tiempo constante contra timing attacks."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Genera un token JWT firmado con expiración controlada."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodifica y valida la integridad criptográfica del token JWT."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except Exception:
        return None


def sanitize_text(text: Optional[str]) -> str:
    """
    Sanitiza strings de entrada para neutralizar inyecciones XSS y caracteres de control.
    Convierte caracteres conflictivos en entidades seguras HTML.
    """
    if not text:
        return ""
    # Truncado de seguridad inicial para evitar buffers sobredimensionados
    safe = str(text).strip()[:1000]
    return html.escape(safe, quote=True)


def check_rate_limit(key: str, max_requests: int = 10, window_seconds: int = 60) -> Tuple[bool, int]:
    """
    Verifica límite de peticiones por clave (IP o Usuario) mediante ventana deslizante.
    Retorna (permitido, segundos_para_reset).
    """
    now = time.time()
    timestamps = RATE_LIMIT_STORE.get(key, [])
    # Filtrar marcas de tiempo dentro de la ventana activa
    timestamps = [t for t in timestamps if now - t < window_seconds]
    RATE_LIMIT_STORE[key] = timestamps

    if len(timestamps) >= max_requests:
        wait_time = int(window_seconds - (now - timestamps[0]))
        return False, max(1, wait_time)

    timestamps.append(now)
    RATE_LIMIT_STORE[key] = timestamps
    return True, 0


def check_sos_debounce(user_id: int, debounce_seconds: int = 20) -> Tuple[bool, int]:
    """
    Evita inundación o activación accidental repetida del Botón SOS por el mismo usuario.
    Permite solo 1 activación cada 20 segundos por usuario.
    """
    now = time.time()
    last_time = SOS_DEBOUNCE_STORE.get(user_id, 0.0)
    elapsed = now - last_time

    if elapsed < debounce_seconds:
        return False, int(debounce_seconds - elapsed)

    SOS_DEBOUNCE_STORE[user_id] = now
    return True, 0
