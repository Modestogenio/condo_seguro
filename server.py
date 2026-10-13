"""
Servidor Central y API RESTful para CondoSeguro Chile.
Construido con FastAPI, middlewares de hardening, limitación estricta de payloads,
rate limiting, encabezados CSP y UI web integrada para Móvil y Desktop.
"""
import sys
import html
import time
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from database import get_db_connection, log_audit, DB_PATH
from security import (
    hash_password, verify_password, create_access_token, decode_access_token,
    sanitize_text, check_rate_limit, check_sos_debounce
)
from schemas import (
    UserRegisterRequest, UserLoginRequest, CreateCondoRequest,
    IncidentReportRequest, AnnouncementCreateRequest, UserApprovalRequest,
    PackageRegisterRequest, PetReportRequest, SupportRequestCreate,
    MarkedPointCreateRequest
)

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(
    title="CondoSeguro Chile - Plataforma de Seguridad Vecinal",
    version="1.0.0",
    docs_url=None,  # Deshabilitar swagger público en prod para reducir superficie de ataque
    redoc_url=None
)

# ----------------- MIDDLEWARE DE PROTECCIÓN CONTRA BUFFER OVERFLOW / DoS -----------------
class PayloadSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Bloquea cualquier petición HTTP que supere 350 KB de payload en el cuerpo.
    Permite imágenes comprimidas mientras previene ataques de desbordamiento de memoria (Memory Exhaustion).
    """
    def __init__(self, app, max_content_length: int = 358400):
        super().__init__(app)
        self.max_content_length = max_content_length

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_content_length:
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={"detail": "Payload supera el límite máximo permitido (350 KB). Rechazado por seguridad."}
            )
        response = await call_next(request)
        return response

app.add_middleware(PayloadSizeLimitMiddleware, max_content_length=358400)

# ----------------- MIDDLEWARE DE CABECERAS DE SEGURIDAD (CSP, HSTS, X-FRAME) -----------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https: data:;"
        )
        return response

app.add_middleware(SecurityHeadersMiddleware)


# ----------------- INYECCIÓN DE DEPENDENCIAS DE AUTENTICACIÓN -----------------
async def get_current_user(request: Request) -> Dict[str, Any]:
    """Extrae y valida el token JWT del encabezado Authorization o Cookie."""
    auth_header = request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    
    if not token:
        token = request.cookies.get("condo_token")

    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sesión no iniciada o token ausente")

    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido o expirado")

    user_id = payload.get("user_id")
    conn = get_db_connection()
    user = conn.execute("""
        SELECT u.*, c.name as condo_name, c.commune, c.security_municipal_phone
        FROM users u
        JOIN condos c ON u.condo_id = c.id
        WHERE u.id = ?
    """, (user_id,)).fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario inexistente")

    return dict(user)


# ----------------- ENDPOINTS PÚBLICOS Y AUTENTICACIÓN -----------------
@app.get("/api/condos/public")
def get_public_condos():
    """Lista condominios activos para selección durante el registro."""
    conn = get_db_connection()
    rows = conn.execute("SELECT id, name, commune, address FROM condos WHERE status = 'ACTIVE' ORDER BY name").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/auth/register")
async def register_user(req: UserRegisterRequest, request: Request):
    """Registro de nuevo residente con consentimiento de Ley 19.628."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    
    # Rate limit: máximo 5 registros cada 5 minutos por IP
    allowed, wait = check_rate_limit(f"reg_{client_ip}", max_requests=5, window_seconds=300)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=f"Demasiados intentos. Espera {wait} segundos.")

    conn = get_db_connection()
    # Verificar si el correo ya existe
    existing = conn.execute("SELECT id FROM users WHERE email = ?", (req.email.lower().strip(),)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El correo ya se encuentra registrado.")

    # Verificar si el condominio existe
    condo = conn.execute("SELECT id FROM condos WHERE id = ?", (req.condo_id,)).fetchone()
    if not condo:
        conn.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Condominio no encontrado.")

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    pwd_hash = hash_password(req.password)
    
    conn.execute("""
        INSERT INTO users (
            condo_id, full_name, house_unit, phone, email, 
            password_hash, role, is_approved, consent_law_19628, consent_timestamp, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'RESIDENT', 0, 1, ?, ?)
    """, (
        req.condo_id,
        sanitize_text(req.full_name),
        sanitize_text(req.house_unit),
        sanitize_text(req.phone),
        req.email.lower().strip(),
        pwd_hash,
        now, now
    ))
    new_user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit()
    conn.close()

    log_audit("USER_REGISTER", condo_id=req.condo_id, user_id=new_user_id, ip_address=client_ip, details=f"Registro de {req.full_name} ({req.house_unit})")

    return {
        "status": "success",
        "message": "Registro completado. Tu cuenta está en revisión por la representante del condominio.",
        "user_id": new_user_id
    }


@app.post("/api/auth/login")
async def login_user(req: UserLoginRequest, request: Request):
    """Inicio de sesión seguro con protección contra fuerza bruta."""
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Rate limiting: max 5 intentos fallidos por minuto
    allowed, wait = check_rate_limit(f"login_{client_ip}", max_requests=8, window_seconds=60)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=f"Demasiados intentos. Espera {wait} segundos.")

    conn = get_db_connection()
    user = conn.execute("""
        SELECT u.*, c.name as condo_name, c.commune, c.security_municipal_phone
        FROM users u
        JOIN condos c ON u.condo_id = c.id
        WHERE u.email = ?
    """, (req.email.lower().strip(),)).fetchone()
    conn.close()

    if not user or not verify_password(req.password, user["password_hash"]):
        log_audit("LOGIN_FAILED", ip_address=client_ip, details=f"Intento fallido: {req.email}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales incorrectas.")

    # Generar token
    token = create_access_token({
        "user_id": user["id"],
        "condo_id": user["condo_id"],
        "role": user["role"],
        "email": user["email"]
    })

    log_audit("LOGIN_SUCCESS", condo_id=user["condo_id"], user_id=user["id"], ip_address=client_ip, details=f"Login de {user['full_name']}")

    return {
        "token": token,
        "user": {
            "id": user["id"],
            "condo_id": user["condo_id"],
            "condo_name": user["condo_name"],
            "commune": user["commune"],
            "security_municipal_phone": user["security_municipal_phone"],
            "full_name": user["full_name"],
            "house_unit": user["house_unit"],
            "phone": user["phone"],
            "email": user["email"],
            "role": user["role"],
            "is_approved": bool(user["is_approved"])
        }
    }


@app.get("/api/auth/me")
def get_me(user: Dict[str, Any] = Depends(get_current_user)):
    """Obtiene datos de la sesión activa."""
    return user


# ----------------- GESTIÓN DE INCIDENTES Y BOTÓN SOS DE PÁNICO -----------------
@app.get("/api/incidents")
def list_incidents(user: Dict[str, Any] = Depends(get_current_user)):
    """Lista incidentes y alertas del condominio del usuario (Aislamiento Multi-tenant)."""
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT i.*, u.full_name as author_name, u.house_unit
        FROM incidents i
        JOIN users u ON i.user_id = u.id
        WHERE i.condo_id = ?
        ORDER BY i.is_active DESC, i.id DESC
        LIMIT 30
    """, (user["condo_id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/incidents")
def create_incident(req: IncidentReportRequest, user: Dict[str, Any] = Depends(get_current_user)):
    """Crea un reporte de seguridad o activa la alarma SOS de pánico."""
    # Control anti-inundación de SOS (debounce de 20 segundos)
    if req.category.startswith("SOS_"):
        allowed, wait = check_sos_debounce(user["id"], debounce_seconds=20)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Alerta SOS ya enviada recientemente. Por favor espera {wait} segundos antes de reiterar."
            )

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    title_safe = sanitize_text(req.title)
    desc_safe = sanitize_text(req.description)
    zone_safe = sanitize_text(req.zone or "ACCESO_PORTON")

    conn = get_db_connection()
    conn.execute("""
        INSERT INTO incidents (condo_id, user_id, title, category, description, zone, image_data, latitude, longitude, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
    """, (user["condo_id"], user["id"], title_safe, req.category, desc_safe, zone_safe, req.image_data, req.latitude, req.longitude, now))
    inc_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit()
    conn.close()

    log_audit("INCIDENT_CREATED", condo_id=user["condo_id"], user_id=user["id"], details=f"Cat: {req.category} | {title_safe}")

    return {
        "status": "success",
        "incident_id": inc_id,
        "message": "¡Alerta registrada y difundida a la comunidad!"
    }


# ----------------- MAPA REAL: PUNTOS MARCADOS POR USUARIOS -----------------
@app.get("/api/map/points")
def get_map_points(user: Dict[str, Any] = Depends(get_current_user)):
    """Obtiene los puntos marcados por usuarios y los incidentes geo-referenciados del condominio."""
    conn = get_db_connection()
    marked = conn.execute("""
        SELECT mp.*, u.full_name as author_name, u.house_unit
        FROM marked_points mp
        JOIN users u ON mp.user_id = u.id
        WHERE mp.condo_id = ?
        ORDER BY mp.id DESC
        LIMIT 60
    """, (user["condo_id"],)).fetchall()
    
    incidents = conn.execute("""
        SELECT i.id, i.title, i.category, i.zone, i.latitude, i.longitude, i.created_at, i.is_active, u.full_name as author_name, u.house_unit
        FROM incidents i
        JOIN users u ON i.user_id = u.id
        WHERE i.condo_id = ? AND i.latitude IS NOT NULL AND i.longitude IS NOT NULL
        ORDER BY i.id DESC
        LIMIT 40
    """, (user["condo_id"],)).fetchall()
    conn.close()

    return {
        "marked_points": [dict(m) for m in marked],
        "incidents": [dict(i) for i in incidents]
    }


@app.post("/api/map/points")
def create_map_point(req: MarkedPointCreateRequest, user: Dict[str, Any] = Depends(get_current_user)):
    """Permite al residente marcar cualquier punto en el mapa real (peligro, foco, cámara, etc.)."""
    title_safe = sanitize_text(req.title)
    notes_safe = sanitize_text(req.notes or "")
    cat_safe = sanitize_text(req.category)
    now = time.strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    conn.execute("""
        INSERT INTO marked_points (condo_id, user_id, title, category, latitude, longitude, notes, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (user["condo_id"], user["id"], title_safe, cat_safe, req.latitude, req.longitude, notes_safe, now))
    point_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit()
    conn.close()

    log_audit("MAP_POINT_CREATED", condo_id=user["condo_id"], user_id=user["id"], details=f"Punto ({req.latitude}, {req.longitude}): {title_safe}")

    return {
        "status": "success",
        "point_id": point_id,
        "message": "Punto marcado con éxito en el mapa."
    }


@app.delete("/api/map/points/{point_id}")
def delete_map_point(point_id: int, user: Dict[str, Any] = Depends(get_current_user)):
    """Elimina un punto marcado en el mapa."""
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM marked_points WHERE id = ? AND condo_id = ?", (point_id, user["condo_id"])).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Punto no encontrado.")

    if user["role"] not in ("SUPERADMIN", "SUBADMIN") and row["user_id"] != user["id"]:
        conn.close()
        raise HTTPException(status_code=403, detail="No tienes permisos para eliminar este punto.")

    conn.execute("DELETE FROM marked_points WHERE id = ?", (point_id,))
    conn.commit()
    conn.close()

    return {"status": "success", "message": "Punto eliminado del mapa."}


# ----------------- MOTOR PREDICTIVO Y OPORTUNIDADES DE MEJORA -----------------
@app.get("/api/predictive/improvements")
def get_predictive_improvements(user: Dict[str, Any] = Depends(get_current_user)):
    """
    Motor Predictivo de Seguridad Vecinal:
    Analiza la concentración espacial de reportes de emergencia y genera oportunidades de mejora preventivas.
    """
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT zone, category, COUNT(*) as count
        FROM incidents
        WHERE condo_id = ?
        GROUP BY zone, category
    """, (user["condo_id"],)).fetchall()
    
    condo = conn.execute("SELECT * FROM condos WHERE id = ?", (user["condo_id"],)).fetchone()
    conn.close()

    improvements = []
    zone_counts = {}
    for r in rows:
        z = r["zone"]
        zone_counts[z] = zone_counts.get(z, 0) + r["count"]

    # Regla 1: Zona Acceso y Portón
    gate_issues = zone_counts.get("ACCESO_PORTON", 0)
    if gate_issues >= 2:
        improvements.append({
            "sector": "Acceso Principal y Portón Vehicular",
            "type": "CONTROL_ACCESO",
            "priority": "ALTA",
            "detected_pattern": f"{gate_issues} incidencias registradas (merodeo o falla de cierre)",
            "action_title": "Ajuste de Electrocierre y Sensor de Portón Abierto",
            "action_description": "Instalar sensor magnético de portón abierto con alarma sonora a los 30s de apertura prolongada, más ajuste del brazo hidráulico.",
            "estimated_cost_clp": "$45.000 - $80.000 CLP"
        })
    
    # Regla 2: Juegos Infantiles / Áreas Verdes
    park_issues = zone_counts.get("JUEGOS_NINOS", 0)
    if park_issues >= 1:
        improvements.append({
            "sector": "Plaza de Juegos Infantiles / Áreas Verdes",
            "type": "VIDEOVIGILANCIA",
            "priority": "ALTA",
            "detected_pattern": "Reportes de personas ajenas en sector de juegos infantiles",
            "action_title": "Cámara IP Domo con Detección Perimetral de Personas",
            "action_description": "Instalación de cámara IP domo 4MP con visión nocturna infrarroja enfocada a la plaza de juegos para monitoreo en vivo desde la app.",
            "estimated_cost_clp": "$65.000 - $110.000 CLP"
        })

    # Regla 3: Pasajes / Perímetro Trasero
    back_issues = zone_counts.get("PASAJE_2", 0) + zone_counts.get("ESTACIONAMIENTOS", 0)
    if back_issues >= 1:
        improvements.append({
            "sector": "Pasaje 2 y Perímetro Trasero (Puntos Ciegos)",
            "type": "ILUMINACION",
            "priority": "MEDIA",
            "detected_pattern": "Reportes de merodeo nocturno y ruidos en zona de baja visibilidad",
            "action_title": "Foco LED 100W con Fotocélula y Sensor de Movimiento",
            "action_description": "Reforzar iluminación en puntos ciegos perimetrales para disuadir intentos de escalamiento o merodeo nocturno.",
            "estimated_cost_clp": "$35.000 - $55.000 CLP"
        })

    if not improvements:
        improvements.append({
            "sector": "Perímetro General del Condominio",
            "type": "PREVENTIVO",
            "priority": "BAJA",
            "detected_pattern": "Condominio con baja siniestralidad actual",
            "action_title": "Plan de Mantención Preventiva Trimestral",
            "action_description": "Revisión mensual de fotocélulas perimetrales y prueba del pulsador del portón de acceso.",
            "estimated_cost_clp": "$20.000 CLP"
        })

    score = max(50, 100 - (len(rows) * 7))
    return {
        "condo_type": condo["condo_type"] if "condo_type" in condo.keys() else "HOUSES",
        "security_score": score,
        "score_label": "Zona Segura y Protegida" if score >= 75 else "Atención Preventiva Requerida",
        "total_incidents_analyzed": sum(zone_counts.values()),
        "improvements": improvements
    }


# ----------------- MÓDULOS COMUNITARIOS (ENCOMIENDAS, MASCOTAS, APOYO, ESPACIOS) -----------------
@app.get("/api/packages")
def get_packages(user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM packages WHERE condo_id = ? ORDER BY id DESC LIMIT 20", (user["condo_id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/packages")
def create_package(req: PackageRegisterRequest, user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db_connection()
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("""
        INSERT INTO packages (condo_id, target_house_unit, receiver_name, receiver_house_unit, carrier, status, image_data, created_at)
        VALUES (?, ?, ?, ?, ?, 'RECEIVED', ?, ?)
    """, (user["condo_id"], sanitize_text(req.target_house_unit), user["full_name"], sanitize_text(req.receiver_house_unit), sanitize_text(req.carrier), req.image_data, now))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Encomienda registrada exitosamente."}

@app.post("/api/packages/{package_id}/deliver")
def mark_package_delivered(package_id: int, user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db_connection()
    conn.execute("UPDATE packages SET status = 'DELIVERED' WHERE id = ? AND condo_id = ?", (package_id, user["condo_id"]))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Paquete marcado como entregado a su dueño."}

@app.get("/api/pets")
def get_pets(user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM pets WHERE condo_id = ? ORDER BY id DESC LIMIT 20", (user["condo_id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/pets")
def create_pet(req: PetReportRequest, user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db_connection()
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("""
        INSERT INTO pets (condo_id, user_id, pet_name, pet_type, status, description, contact_phone, image_data, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user["condo_id"], user["id"], sanitize_text(req.pet_name), sanitize_text(req.pet_type), req.status, sanitize_text(req.description), sanitize_text(req.contact_phone), req.image_data, now))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Reporte de mascota publicado."}

@app.post("/api/pets/{pet_id}/resolve")
def resolve_pet(pet_id: int, user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db_connection()
    conn.execute("UPDATE pets SET status = 'FOUND' WHERE id = ? AND condo_id = ?", (pet_id, user["condo_id"]))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Estado de mascota actualizado a Encontrado/a."}

@app.get("/api/support")
def get_support(user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM support_requests WHERE condo_id = ? ORDER BY id DESC LIMIT 20", (user["condo_id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/support")
def create_support(req: SupportRequestCreate, user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db_connection()
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("""
        INSERT INTO support_requests (condo_id, user_id, title, category, house_unit, description, is_resolved, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 0, ?)
    """, (user["condo_id"], user["id"], sanitize_text(req.title), sanitize_text(req.category), sanitize_text(req.house_unit), sanitize_text(req.description), now))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Aviso de apoyo vecinal publicado."}

@app.get("/api/amenities")
def get_amenities(user: Dict[str, Any] = Depends(get_current_user)):
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM amenities WHERE condo_id = ? ORDER BY id ASC", (user["condo_id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/amenities/{amenity_id}/toggle")
def toggle_amenity_status(amenity_id: int, user: Dict[str, Any] = Depends(get_current_user)):
    if user["role"] not in ("SUBADMIN", "SUPERADMIN"):
        raise HTTPException(status_code=403, detail="Solo el representante puede modificar el estado de espacios comunes.")
    conn = get_db_connection()
    curr = conn.execute("SELECT status FROM amenities WHERE id = ? AND condo_id = ?", (amenity_id, user["condo_id"])).fetchone()
    if not curr:
        conn.close()
        raise HTTPException(status_code=404, detail="Espacio no encontrado.")
    new_st = "MAINTENANCE" if curr["status"] == "AVAILABLE" else "AVAILABLE"
    conn.execute("UPDATE amenities SET status = ? WHERE id = ?", (new_st, amenity_id))
    conn.commit()
    conn.close()
    return {"status": "success", "new_status": new_st}


@app.post("/api/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: int, user: Dict[str, Any] = Depends(get_current_user)):
    """Desactiva una alerta una vez atendida por vecinos o autoridades."""
    conn = get_db_connection()
    # Solo el autor, el subadmin o superadmin pueden desactivarla
    inc = conn.execute("SELECT * FROM incidents WHERE id = ? AND condo_id = ?", (incident_id, user["condo_id"])).fetchone()
    if not inc:
        conn.close()
        raise HTTPException(status_code=404, detail="Incidente no encontrado.")

    if inc["user_id"] != user["id"] and user["role"] not in ("SUBADMIN", "SUPERADMIN"):
        conn.close()
        raise HTTPException(status_code=403, detail="No tienes permisos para cerrar este reporte.")

    conn.execute("UPDATE incidents SET is_active = 0 WHERE id = ?", (incident_id,))
    conn.commit()
    conn.close()

    log_audit("INCIDENT_RESOLVED", condo_id=user["condo_id"], user_id=user["id"], details=f"Incidente #{incident_id} resuelto")
    return {"status": "success", "message": "Incidente marcado como resuelto."}


# ----------------- COMUNICADOS OFICIALES (REPRESENTANTE) -----------------
@app.get("/api/announcements")
def list_announcements(user: Dict[str, Any] = Depends(get_current_user)):
    """Lista comunicados oficiales emitidos por el representante vecinal."""
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT a.*, u.full_name as author_name
        FROM announcements a
        JOIN users u ON a.author_id = u.id
        WHERE a.condo_id = ?
        ORDER BY a.id DESC
        LIMIT 20
    """, (user["condo_id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/announcements")
def create_announcement(req: AnnouncementCreateRequest, user: Dict[str, Any] = Depends(get_current_user)):
    """Publica un nuevo comunicado oficial (solo SUBADMIN o SUPERADMIN)."""
    if user["role"] not in ("SUBADMIN", "SUPERADMIN"):
        raise HTTPException(status_code=403, detail="Solo el representante vecinal puede emitir comunicados oficiales.")

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    title_safe = sanitize_text(req.title)
    content_safe = sanitize_text(req.content)

    conn = get_db_connection()
    conn.execute("""
        INSERT INTO announcements (condo_id, author_id, title, content, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (user["condo_id"], user["id"], title_safe, content_safe, now))
    conn.commit()
    conn.close()

    log_audit("ANNOUNCEMENT_CREATED", condo_id=user["condo_id"], user_id=user["id"], details=title_safe)
    return {"status": "success", "message": "Comunicado oficial publicado exitosamente."}


# ----------------- PANEL SUB-ADMIN (REPRESENTANTE VECINAL) -----------------
@app.get("/api/subadmin/residents")
def list_residents(user: Dict[str, Any] = Depends(get_current_user)):
    """Lista residentes del condominio para validación y control vecinal."""
    if user["role"] not in ("SUBADMIN", "SUPERADMIN"):
        raise HTTPException(status_code=403, detail="Acceso denegado a panel de representante.")

    conn = get_db_connection()
    rows = conn.execute("""
        SELECT id, full_name, house_unit, phone, email, is_approved, created_at, consent_timestamp
        FROM users
        WHERE condo_id = ? AND role = 'RESIDENT'
        ORDER BY is_approved ASC, house_unit ASC
    """, (user["condo_id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/subadmin/approve-resident")
def approve_resident(req: UserApprovalRequest, user: Dict[str, Any] = Depends(get_current_user)):
    """Aprueba o rechaza a un vecino registrado para permitir su acceso."""
    if user["role"] not in ("SUBADMIN", "SUPERADMIN"):
        raise HTTPException(status_code=403, detail="Acceso denegado a panel de representante.")

    conn = get_db_connection()
    target = conn.execute("SELECT id, full_name, condo_id FROM users WHERE id = ?", (req.user_id,)).fetchone()
    if not target or target["condo_id"] != user["condo_id"]:
        conn.close()
        raise HTTPException(status_code=404, detail="Usuario no encontrado en tu condominio.")

    new_val = 1 if req.approve else 0
    conn.execute("UPDATE users SET is_approved = ? WHERE id = ?", (new_val, req.user_id))
    conn.commit()
    conn.close()

    log_audit(
        "RESIDENT_APPROVED" if req.approve else "RESIDENT_SUSPENDED",
        condo_id=user["condo_id"], user_id=user["id"],
        details=f"Vecino #{req.user_id} ({target['full_name']}) estado: {new_val}"
    )

    return {"status": "success", "message": f"Vecino {'aprobado' if req.approve else 'suspendido'} con éxito."}


# ----------------- PANEL SUPER-ADMIN (MANTENEDOR DEL SERVICIO / TÚ) -----------------
@app.get("/api/admin/condos")
def list_all_condos_admin(user: Dict[str, Any] = Depends(get_current_user)):
    """Lista métricas consolidadas de todos los condominios afiliados."""
    if user["role"] != "SUPERADMIN":
        raise HTTPException(status_code=403, detail="Acceso exclusivo al mantenedor del sistema.")

    conn = get_db_connection()
    rows = conn.execute("""
        SELECT c.*,
            (SELECT COUNT(*) FROM users u WHERE u.condo_id = c.id) as total_users,
            (SELECT COUNT(*) FROM incidents i WHERE i.condo_id = c.id) as total_incidents,
            (SELECT COUNT(*) FROM incidents i WHERE i.condo_id = c.id AND i.is_active = 1) as active_incidents
        FROM condos c
        ORDER BY c.id DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/admin/condos")
def create_condo_admin(req: CreateCondoRequest, user: Dict[str, Any] = Depends(get_current_user)):
    """Da de alta a un nuevo condominio en la plataforma."""
    if user["role"] != "SUPERADMIN":
        raise HTTPException(status_code=403, detail="Acceso exclusivo al mantenedor del sistema.")

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO condos (name, address, commune, security_municipal_phone, status, created_at)
        VALUES (?, ?, ?, ?, 'ACTIVE', ?)
    """, (
        sanitize_text(req.name),
        sanitize_text(req.address),
        sanitize_text(req.commune),
        sanitize_text(req.security_municipal_phone),
        now
    ))
    new_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit()
    conn.close()

    log_audit("CONDO_CREATED", condo_id=new_id, user_id=user["id"], details=f"Nuevo condominio: {req.name} ({req.commune})")
    return {"status": "success", "condo_id": new_id, "message": "Condominio creado exitosamente."}


@app.get("/api/admin/audit-logs")
def view_audit_logs(limit: int = 50, user: Dict[str, Any] = Depends(get_current_user)):
    """Inspección de logs de seguridad y auditoría (Cumplimiento Ley 19.628)."""
    if user["role"] != "SUPERADMIN":
        raise HTTPException(status_code=403, detail="Acceso exclusivo al mantenedor del sistema.")

    conn = get_db_connection()
    rows = conn.execute("""
        SELECT a.*, c.name as condo_name, u.full_name as user_name
        FROM audit_logs a
        LEFT JOIN condos c ON a.condo_id = c.id
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.id DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/admin/backup-db")
def download_database_backup(user: Dict[str, Any] = Depends(get_current_user)):
    """Genera y descarga un respaldo instantáneo de la base SQLite."""
    if user["role"] != "SUPERADMIN":
        raise HTTPException(status_code=403, detail="Acceso exclusivo al mantenedor del sistema.")

    backup_name = f"condo_seguro_backup_{time.strftime('%Y%m%d_%H%M%S')}.db"
    backup_path = BASE_DIR / backup_name
    shutil.copyfile(DB_PATH, backup_path)
    return FileResponse(path=backup_path, filename=backup_name, media_type="application/octet-stream")


# ----------------- VISTA WEB PRINCIPAL (UI RESPONSIVA MÓVIL Y DESKTOP) -----------------
@app.get("/", response_class=HTMLResponse)
def index_page():
    """Sirve la aplicación de interfaz de usuario Single-Page."""
    html_path = BASE_DIR / "templates" / "index.html"
    return html_path.read_text(encoding="utf-8")


if __name__ == "__main__":
    import uvicorn
    from database import init_db
    init_db()
    print("==================================================================")
    print(" 🇨🇱 CONDOSEGURO CHILE - SERVIDOR DE SEGURIDAD VECINAL ACTIVO")
    print(" Acceso Web: http://localhost:8000")
    print(" SuperAdmin Demo: admin@condoseguro.cl / admin123456")
    print(" SubAdmin Demo:   representante@aromos.cl / representante123")
    print(" Vecino Demo:     vecino1@aromos.cl / vecino123")
    print("==================================================================")
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False, log_level="info")
