"""
Módulo de Base de Datos para CondoSeguro Chile.
Manejo de persistencia con SQLite parametrizado al 100% (prevención total de SQL Injection),
aislamiento multi-condominio y registro de auditoría exigido por la Ley 19.628.
"""
import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Optional
import time

DB_PATH = Path(__file__).resolve().parent / "condo_seguro.db"


def get_db_connection() -> sqlite3.Connection:
    """Crea una conexión con row_factory para acceso por nombre de columna."""
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Inicializa el esquema relacional con índices de seguridad."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Tabla de Condominios (Multi-tenant)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS condos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        address TEXT NOT NULL,
        commune TEXT NOT NULL,
        security_municipal_phone TEXT NOT NULL,
        status TEXT DEFAULT 'ACTIVE',
        created_at TEXT NOT NULL
    )
    """)

    # 2. Tabla de Usuarios y Residentes
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        condo_id INTEGER NOT NULL,
        full_name TEXT NOT NULL,
        house_unit TEXT NOT NULL,
        phone TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('SUPERADMIN', 'SUBADMIN', 'RESIDENT')),
        is_approved INTEGER DEFAULT 0,
        consent_law_19628 INTEGER DEFAULT 1,
        consent_timestamp TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (condo_id) REFERENCES condos(id) ON DELETE CASCADE
    )
    """)

    # 3. Tabla de Incidentes y Alertas de Pánico SOS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        condo_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL CHECK(category IN (
            'SOS_PANIC', 'SOS_MEDICAL', 'SOS_FIRE', 
            'SUSPICIOUS_PERSON', 'STRANGE_VEHICLE', 
            'NOISE', 'GATE_OPEN', 'GENERAL'
        )),
        description TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL,
        FOREIGN KEY (condo_id) REFERENCES condos(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # 4. Tabla de Avisos y Comunicados Oficiales (Sub-Admin / Representante)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS announcements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        condo_id INTEGER NOT NULL,
        author_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (condo_id) REFERENCES condos(id) ON DELETE CASCADE,
        FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # 5. Tabla de Espacios Comunes (Quincho, Piscina, Gimnasio)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS amenities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        condo_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        status TEXT DEFAULT 'AVAILABLE',
        capacity INTEGER DEFAULT 20,
        rules_info TEXT,
        FOREIGN KEY (condo_id) REFERENCES condos(id) ON DELETE CASCADE
    )
    """)

    # 6. Tabla de Encomiendas y Paquetes (Recepción Solidaria entre Vecinos)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS packages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        condo_id INTEGER NOT NULL,
        target_house_unit TEXT NOT NULL,
        receiver_name TEXT NOT NULL,
        receiver_house_unit TEXT NOT NULL,
        carrier TEXT NOT NULL,
        status TEXT DEFAULT 'RECEIVED',
        image_data TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (condo_id) REFERENCES condos(id) ON DELETE CASCADE
    )
    """)

    # 7. Tabla de Mascotas Perdidas / Encontradas
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        condo_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        pet_name TEXT NOT NULL,
        pet_type TEXT NOT NULL,
        status TEXT DEFAULT 'LOST',
        description TEXT NOT NULL,
        contact_phone TEXT NOT NULL,
        image_data TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (condo_id) REFERENCES condos(id) ON DELETE CASCADE
    )
    """)

    # 8. Tabla de Red de Apoyo Vecinal (Enfermos, Adultos Mayores, Asistencia)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS support_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        condo_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        house_unit TEXT NOT NULL,
        description TEXT NOT NULL,
        is_resolved INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (condo_id) REFERENCES condos(id) ON DELETE CASCADE
    )
    """)

    # 9. Registro de Auditoría y Acceso (Requisito Ley 19.628 y Trazabilidad)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        condo_id INTEGER,
        user_id INTEGER,
        action TEXT NOT NULL,
        ip_address TEXT,
        details TEXT,
        created_at TEXT NOT NULL
    )
    """)

    # 10. Tabla de Puntos Marcados en el Mapa por Residentes
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS marked_points (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        condo_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        latitude REAL NOT NULL,
        longitude REAL NOT NULL,
        notes TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (condo_id) REFERENCES condos(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # Migraciones en línea para columnas nuevas
    try:
        cursor.execute("ALTER TABLE condos ADD COLUMN condo_type TEXT DEFAULT 'HOUSES'")
    except Exception:
        pass

    try:
        cursor.execute("ALTER TABLE incidents ADD COLUMN zone TEXT DEFAULT 'ACCESO_PORTON'")
    except Exception:
        pass

    try:
        cursor.execute("ALTER TABLE incidents ADD COLUMN image_data TEXT")
    except Exception:
        pass

    try:
        cursor.execute("ALTER TABLE incidents ADD COLUMN latitude REAL")
    except Exception:
        pass

    try:
        cursor.execute("ALTER TABLE incidents ADD COLUMN longitude REAL")
    except Exception:
        pass

    # Índices para consultas de alta velocidad y aislamiento
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_condo ON users(condo_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_condo ON incidents(condo_id, is_active)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_announcements_condo ON announcements(condo_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_packages_condo ON packages(condo_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pets_condo ON pets(condo_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_support_condo ON support_requests(condo_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_marked_points_condo ON marked_points(condo_id)")

    conn.commit()
    conn.close()


def log_audit(action: str, condo_id: Optional[int] = None, user_id: Optional[int] = None, ip_address: str = "127.0.0.1", details: str = ""):
    """Registra una acción de seguridad en el log inmutable."""
    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO audit_logs (condo_id, user_id, action, ip_address, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (condo_id, user_id, action, ip_address, details, time.strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
    except Exception:
        pass
