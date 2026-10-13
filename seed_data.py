"""
Script de Poblamiento Inicial y Demo para CondoSeguro Chile.
Crea la base de datos con un condominio de ejemplo, roles de SuperAdmin,
SubAdmin (Representante) y Vecinos con incidentes y comunicados.
"""
import time
from database import init_db, get_db_connection
from security import hash_password


import sys

def seed(force=False):
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    if not force and len(sys.argv) > 1 and sys.argv[1] in ("--reset", "--force"):
        force = True

    if force:
        cursor.execute("DELETE FROM marked_points")
        cursor.execute("DELETE FROM support_requests")
        cursor.execute("DELETE FROM pets")
        cursor.execute("DELETE FROM packages")
        cursor.execute("DELETE FROM amenities")
        cursor.execute("DELETE FROM announcements")
        cursor.execute("DELETE FROM incidents")
        cursor.execute("DELETE FROM users")
        cursor.execute("DELETE FROM condos")
        conn.commit()
    else:
        cursor.execute("SELECT COUNT(*) FROM condos")
        if cursor.fetchone()[0] > 0:
            print("[*] Base de datos ya cuenta con datos iniciales.")
            conn.close()
            return

    now = time.strftime("%Y-%m-%d %H:%M:%S")

    # 1. Crear Condominio Demo
    cursor.execute("""
    INSERT INTO condos (name, address, commune, security_municipal_phone, condo_type, status, created_at)
    VALUES (?, ?, ?, ?, 'HOUSES', 'ACTIVE', ?)
    """, ("Condominio Los Aromos de Macul", "Av. Quilín 3240", "Macul", "1444", now))
    condo_id = cursor.lastrowid

    # 2. Crear SuperAdmin (Mantenedor de la Plataforma / Tú)
    cursor.execute("""
    INSERT INTO users (condo_id, full_name, house_unit, phone, email, password_hash, role, is_approved, consent_law_19628, consent_timestamp, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 'SUPERADMIN', 1, 1, ?, ?)
    """, (
        condo_id,
        "Administrador General (Mantenedor)",
        "Soporte Central",
        "+56911223344",
        "admin@condoseguro.cl",
        hash_password("admin123456"),
        now, now
    ))

    # 3. Crear SubAdmin (Representante Vecinal Elegida por la Comunidad)
    cursor.execute("""
    INSERT INTO users (condo_id, full_name, house_unit, phone, email, password_hash, role, is_approved, consent_law_19628, consent_timestamp, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 'SUBADMIN', 1, 1, ?, ?)
    """, (
        condo_id,
        "Patricia Morales (Representante Vecinal)",
        "Casa 7",
        "+56987654321",
        "representante@aromos.cl",
        hash_password("representante123"),
        now, now
    ))
    subadmin_id = cursor.lastrowid

    # 4. Crear Residentes Aprobados
    cursor.execute("""
    INSERT INTO users (condo_id, full_name, house_unit, phone, email, password_hash, role, is_approved, consent_law_19628, consent_timestamp, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 'RESIDENT', 1, 1, ?, ?)
    """, (
        condo_id,
        "Juan Pérez",
        "Casa 1",
        "+56976543210",
        "vecino1@aromos.cl",
        hash_password("vecino123"),
        now, now
    ))
    res1_id = cursor.lastrowid

    cursor.execute("""
    INSERT INTO users (condo_id, full_name, house_unit, phone, email, password_hash, role, is_approved, consent_law_19628, consent_timestamp, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 'RESIDENT', 1, 1, ?, ?)
    """, (
        condo_id,
        "Carolina Soto",
        "Casa 3",
        "+56965432109",
        "vecino2@aromos.cl",
        hash_password("vecino123"),
        now, now
    ))

    # 5. Crear Residente Pendiente de Aprobación (para demostrar el panel del SubAdmin)
    cursor.execute("""
    INSERT INTO users (condo_id, full_name, house_unit, phone, email, password_hash, role, is_approved, consent_law_19628, consent_timestamp, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 'RESIDENT', 0, 1, ?, ?)
    """, (
        condo_id,
        "Rodrigo Fuenzalida (Nuevo Vecino)",
        "Casa 12",
        "+56954321098",
        "pendiente@aromos.cl",
        hash_password("vecino123"),
        now, now
    ))

    # 6. Crear un Comunicado Oficial del Representante
    cursor.execute("""
    INSERT INTO announcements (condo_id, author_id, title, content, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, (
        condo_id,
        subadmin_id,
        "Pruebas de Portón Eléctrico y Activación de Plataforma",
        "Estimados vecinos: Les informamos que este sábado de 10:00 a 12:00 se realizará mantención del motor del portón de acceso. Favor utilizar esta app para cualquier alerta SOS o reporte de seguridad.",
        now
    ))

    # 7. Crear Incidentes con Zonas y Coordenadas GPS para Mapa Real y Modelo Predictivo
    cursor.execute("""
    INSERT INTO incidents (condo_id, user_id, title, category, description, zone, latitude, longitude, is_active, created_at)
    VALUES (?, ?, ?, 'SUSPICIOUS_PERSON', ?, 'ACCESO_PORTON', -33.48550, -70.59890, 0, ?)
    """, (
        condo_id, res1_id,
        "Persona merodeando cerca del portón principal",
        "Se observó a un sujeto en bicicleta mirando hacia el interior por más de 10 minutos. Se llamó a Seguridad Macul y se retiró.",
        now
    ))

    cursor.execute("""
    INSERT INTO incidents (condo_id, user_id, title, category, description, zone, latitude, longitude, is_active, created_at)
    VALUES (?, ?, ?, 'SUSPICIOUS_PERSON', ?, 'JUEGOS_NINOS', -33.48590, -70.59880, 0, ?)
    """, (
        condo_id, res1_id,
        "Sujeto desconocido sentado en sector juegos infantiles",
        "Persona ajena al condominio permaneció en la plaza de juegos sin acompañar a niños durante la tarde.",
        now
    ))

    cursor.execute("""
    INSERT INTO incidents (condo_id, user_id, title, category, description, zone, latitude, longitude, is_active, created_at)
    VALUES (?, ?, ?, 'GATE_OPEN', ?, 'ACCESO_PORTON', -33.48555, -70.59895, 0, ?)
    """, (
        condo_id, res1_id,
        "Falla de cierre automático en portón vehicular",
        "El portón quedó abierto durante 35 minutos sin que el sensor cerrara el brazo hidráulico.",
        now
    ))

    cursor.execute("""
    INSERT INTO incidents (condo_id, user_id, title, category, description, zone, latitude, longitude, is_active, created_at)
    VALUES (?, ?, ?, 'NOISE', ?, 'PASAJE_2', -33.48610, -70.59820, 0, ?)
    """, (
        condo_id, res1_id,
        "Merodeo nocturno y ruidos en sector trasero pasaje 2",
        "Se escucharon ruidos de forcejeo cerca de la pandereta perimetral en la zona con baja iluminación.",
        now
    ))

    # Puntos Marcados en el Mapa Real por Vecinos
    cursor.execute("""
    INSERT INTO marked_points (condo_id, user_id, title, category, latitude, longitude, notes, created_at)
    VALUES (?, ?, 'Portón Peatonal - Pestillo con holgura', 'INTEREST', -33.48552, -70.59888, 'Cerradura no traba bien al empujar', ?)
    """, (condo_id, res1_id, now))

    cursor.execute("""
    INSERT INTO marked_points (condo_id, user_id, title, category, latitude, longitude, notes, created_at)
    VALUES (?, ?, 'Poste Pasaje 2 - Luminaria quemada', 'LIGHTING', -33.48608, -70.59825, 'Foco LED 100W fundido hace 3 días', ?)
    """, (condo_id, res1_id, now))

    cursor.execute("""
    INSERT INTO marked_points (condo_id, user_id, title, category, latitude, longitude, notes, created_at)
    VALUES (?, ?, 'Sector Juegos - Propuesta Cámara Domo', 'CAMERA', -33.48588, -70.59878, 'Ángulo directo hacia juegos infantiles y quincho', ?)
    """, (condo_id, subadmin_id, now))

    # 8. Espacios Comunes
    cursor.execute("""
    INSERT INTO amenities (condo_id, name, type, status, capacity, rules_info)
    VALUES (?, 'Quincho Comunitario', 'QUINCHO', 'AVAILABLE', 25, 'Horario de uso: 12:00 a 22:00 hrs. Aseo a cargo del residente.')
    """, (condo_id,))
    cursor.execute("""
    INSERT INTO amenities (condo_id, name, type, status, capacity, rules_info)
    VALUES (?, 'Piscina de Temporada', 'PISCINA', 'AVAILABLE', 15, 'Horario: 10:00 a 20:00 hrs. Menores acompañados de un adulto.')
    """, (condo_id,))
    cursor.execute("""
    INSERT INTO amenities (condo_id, name, type, status, capacity, rules_info)
    VALUES (?, 'Sala Multiuso & Gimnasio', 'GYM', 'MAINTENANCE', 10, 'En mantención de piso flotante hasta el viernes.')
    """, (condo_id,))

    # 9. Encomiendas Recibidas Solidariamente
    cursor.execute("""
    INSERT INTO packages (condo_id, target_house_unit, receiver_name, receiver_house_unit, carrier, status, created_at)
    VALUES (?, 'Casa 12', 'Carolina Soto', 'Casa 3', 'MercadoLibre', 'RECEIVED', ?)
    """, (condo_id, now))

    # 10. Mascotas
    cursor.execute("""
    INSERT INTO pets (condo_id, user_id, pet_name, pet_type, status, description, contact_phone, created_at)
    VALUES (?, ?, 'Toby', 'Perro Poodle Blanco', 'LOST', 'Poodle blanco con collar azul, se escapó cerca del portón vehicular.', '+56987654321', ?)
    """, (condo_id, subadmin_id, now))

    # 11. Red de Apoyo Vecinal / Asistencia
    cursor.execute("""
    INSERT INTO support_requests (condo_id, user_id, title, category, house_unit, description, is_resolved, created_at)
    VALUES (?, ?, 'Apoyo en compras de farmacia para adultos mayores', 'MEDICINE', 'Casa 3', 'Hola vecinos, voy a la farmacia los martes y jueves en la mañana. Quien necesite medicamentos con receta me puede avisar.', 0, ?)
    """, (condo_id, res1_id, now))

    conn.commit()
    conn.close()
    print("[OK] Datos de prueba iniciales cargados exitosamente.")


if __name__ == "__main__":
    seed()
