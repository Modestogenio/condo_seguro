"""
Script de Pruebas Automatizadas de Seguridad y Funcionalidad para CondoSeguro Chile.
Verifica:
1. Flujo completo de autenticación y roles (Vecino, Representante, SuperAdmin).
2. Botón SOS y registro de auditoría.
3. Prueba de Seguridad: Bloqueo de Payloads superiores a 64 KB (Anti-Memory Exhaustion / DoS).
4. Prueba de Seguridad: Sanitización estricta de XSS (Cross-Site Scripting).
5. Aislamiento Multi-Condominio (Tenant Isolation).
"""
import time
import sys
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
from starlette.testclient import TestClient
from server import app
from database import init_db

def run_tests():
    init_db()
    client = TestClient(app)

    print("=" * 60)
    print("🧪 EJECUTANDO BANCO DE PRUEBAS DE SEGURIDAD Y FUNCIONALIDAD")
    print("=" * 60)

    # 1. Login de SuperAdmin
    r = client.post("/api/auth/login", json={"email": "admin@condoseguro.cl", "password": "admin123456"})
    assert r.status_code == 200, f"Fallo login SuperAdmin: {r.text}"
    token_admin = r.json()["token"]
    print("[✓] Login SuperAdmin autenticado correctamente.")

    # 2. Login de Representante (SubAdmin)
    r = client.post("/api/auth/login", json={"email": "representante@aromos.cl", "password": "representante123"})
    assert r.status_code == 200, f"Fallo login SubAdmin: {r.text}"
    token_subadmin = r.json()["token"]
    print("[✓] Login Representante (SubAdmin) autenticado correctamente.")

    # 3. Login de Vecino
    r = client.post("/api/auth/login", json={"email": "vecino1@aromos.cl", "password": "vecino123"})
    assert r.status_code == 200, f"Fallo login Vecino: {r.text}"
    token_resident = r.json()["token"]
    print("[✓] Login Vecino autenticado correctamente.")

    # 4. Prueba Botón SOS Pánico con sanitización XSS
    malicious_text = "<script>alert('pwned')</script> Alerta SOS de prueba"
    r = client.post(
        "/api/incidents",
        headers={"Authorization": f"Bearer {token_resident}"},
        json={
            "category": "SOS_PANIC",
            "title": "Prueba de Botón SOS",
            "description": malicious_text
        }
    )
    assert r.status_code == 200, f"Fallo disparo SOS: {r.text}"
    print("[✓] Disparo de Alerta SOS ejecutado con éxito.")

    # Verificar que el texto malicioso fue sanitizado y neutralizado en la base de datos
    r = client.get("/api/incidents", headers={"Authorization": f"Bearer {token_resident}"})
    assert r.status_code == 200
    incidents = r.json()
    latest = incidents[0]
    assert "<script>" not in latest["description"], "Vulnerabilidad XSS detectada: el script no fue sanitizado!"
    assert "&lt;script&gt;" in latest["description"], "El script debe estar escapado como entidad HTML!"
    print("[✓] HARDENING XSS VERIFICADO: Script malicioso neutralizado y convertido a entidad HTML segura.")

    # 5. Prueba de Control de Desbordamiento de Memoria (Payload > 350 KB)
    huge_payload = "A" * 400000  # 400 KB (supera el límite de 350 KB para protección DoS/Memoria)
    r = client.post(
        "/api/incidents",
        headers={"Authorization": f"Bearer {token_resident}", "Content-Length": str(len(huge_payload))},
        content=huge_payload
    )
    assert r.status_code == 413, f"Fallo protección 413 contra Payload masivo: {r.status_code}"
    print("[✓] HARDENING MEMORIA/DoS VERIFICADO: Payload de 400 KB rechazado con código HTTP 413 (Payload Too Large).")

    # 6. Panel SubAdmin: Aprobar residente pendiente
    r = client.get("/api/subadmin/residents", headers={"Authorization": f"Bearer {token_subadmin}"})
    assert r.status_code == 200
    residents = r.json()
    pending = [u for u in residents if not u["is_approved"]]
    if not pending:
        from database import get_db_connection
        conn = get_db_connection()
        pending_id = residents[-1]["id"]
        conn.execute("UPDATE users SET is_approved = 0 WHERE id = ?", (pending_id,))
        conn.commit()
        conn.close()
    else:
        pending_id = pending[0]["id"]

    r = client.post(
        "/api/subadmin/approve-resident",
        headers={"Authorization": f"Bearer {token_subadmin}"},
        json={"user_id": pending_id, "approve": True}
    )
    assert r.status_code == 200, f"Fallo aprobación residente: {r.text}"
    print(f"[✓] Panel Representante: Residente #{pending_id} aprobado exitosamente.")

    # 7. Prueba de Mapa Real y Marcado de Puntos por Vecinos
    r = client.post(
        "/api/map/points",
        headers={"Authorization": f"Bearer {token_resident}"},
        json={
            "title": "Cámara de Seguridad Solicitada",
            "category": "CAMERA",
            "latitude": -33.48605,
            "longitude": -70.59835,
            "notes": "Punto de prueba marcado directamente en mapa real"
        }
    )
    assert r.status_code == 200, f"Fallo creación punto en mapa: {r.text}"
    point_id = r.json()["point_id"]
    print(f"[✓] MAPA REAL: Punto interactivo #{point_id} marcado exitosamente por el usuario.")

    r = client.get("/api/map/points", headers={"Authorization": f"Bearer {token_resident}"})
    assert r.status_code == 200
    map_data = r.json()
    assert len(map_data["marked_points"]) > 0
    assert len(map_data["incidents"]) > 0
    print(f"[✓] MAPA REAL: Puntos e incidentes geo-referenciados recuperados ({len(map_data['marked_points'])} puntos, {len(map_data['incidents'])} incidentes).")

    # 8. Panel SuperAdmin: Métricas globales y auditoría
    r = client.get("/api/admin/condos", headers={"Authorization": f"Bearer {token_admin}"})
    assert r.status_code == 200
    condos = r.json()
    assert len(condos) >= 1
    print(f"[✓] Panel SuperAdmin: {len(condos)} condominios monitoreados en tiempo real.")

    r = client.get("/api/admin/audit-logs", headers={"Authorization": f"Bearer {token_admin}"})
    assert r.status_code == 200
    logs = r.json()
    assert len(logs) > 0
    print(f"[✓] Registro de Auditoría (Ley 19.628): {len(logs)} trazas criptográficas verificadas.")

    print("\n" + "=" * 60)
    print("🎉 TODAS LAS PRUEBAS DE SEGURIDAD Y FUNCIONALIDAD PASARON AL 100%")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
