"""
Esquemas Pydantic para Validación de Entradas de CondoSeguro Chile.
Previene desbordamientos de memoria (Memory Overflows / JSON Bombs) mediante:
- Restricción estricta de longitud máxima en cada campo.
- Prohibición de atributos no declarados (extra = 'forbid').
- Tipado fuerte y sanitización automática.
"""
from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional


class UserRegisterRequest(BaseModel):
    condo_id: int = Field(..., ge=1, description="ID del condominio correspondiente")
    full_name: str = Field(..., min_length=3, max_length=70, description="Nombre y apellido del residente")
    house_unit: str = Field(..., min_length=1, max_length=30, description="Casa o Departamento (ej: Casa 4, Depto 302)")
    phone: str = Field(..., min_length=8, max_length=15, description="Teléfono chileno (ej: +56912345678)")
    email: EmailStr = Field(..., description="Correo electrónico institucional o personal")
    password: str = Field(..., min_length=6, max_length=50, description="Contraseña segura")
    consent_law_19628: bool = Field(..., description="Aceptación expresa de la Ley 19.628 de Protección de Datos")

    class Config:
        extra = "forbid"

    @field_validator("consent_law_19628")
    @classmethod
    def validate_consent(cls, v: bool) -> bool:
        if not v:
            raise ValueError("Debe aceptar expresamente el tratamiento de datos para emergencias conforme a la Ley 19.628.")
        return v


class UserLoginRequest(BaseModel):
    email: EmailStr = Field(..., description="Correo electrónico registrado")
    password: str = Field(..., min_length=1, max_length=50, description="Contraseña")

    class Config:
        extra = "forbid"


class CreateCondoRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=80, description="Nombre del condominio")
    address: str = Field(..., min_length=5, max_length=120, description="Dirección física")
    commune: str = Field(..., min_length=3, max_length=50, description="Comuna en Chile")
    security_municipal_phone: str = Field(..., min_length=3, max_length=15, description="Número de seguridad municipal (ej: 1405)")
    condo_type: Optional[str] = Field("HOUSES", max_length=15, description="Tipo: HOUSES o BUILDINGS")

    class Config:
        extra = "forbid"


class IncidentReportRequest(BaseModel):
    category: str = Field(..., min_length=3, max_length=30, description="Categoría del reporte o alerta SOS")
    title: str = Field(..., min_length=3, max_length=80, description="Título descriptivo breve")
    description: str = Field(..., min_length=3, max_length=600, description="Detalle de lo ocurrido")
    zone: Optional[str] = Field("ACCESO_PORTON", max_length=30, description="Zona del condominio")
    image_data: Optional[str] = Field(None, max_length=250000, description="Imagen opcional en formato base64 comprimido")
    latitude: Optional[float] = Field(None, ge=-90.0, le=90.0, description="Latitud GPS exacta")
    longitude: Optional[float] = Field(None, ge=-180.0, le=180.0, description="Longitud GPS exacta")

    class Config:
        extra = "forbid"


class MarkedPointCreateRequest(BaseModel):
    title: str = Field(..., min_length=2, max_length=80, description="Título o descripción del punto marcado")
    category: str = Field(..., min_length=2, max_length=30, description="Categoría (SOS, SUSPICIOUS, LIGHTING, CAMERA, PACKAGE, PET, INTEREST)")
    latitude: float = Field(..., ge=-90.0, le=90.0, description="Latitud GPS")
    longitude: float = Field(..., ge=-180.0, le=180.0, description="Longitud GPS")
    notes: Optional[str] = Field(None, max_length=300, description="Notas u observaciones adicionales")

    class Config:
        extra = "forbid"


class AnnouncementCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=90, description="Título del comunicado")
    content: str = Field(..., min_length=5, max_length=1200, description="Cuerpo del comunicado oficial")

    class Config:
        extra = "forbid"


class UserApprovalRequest(BaseModel):
    user_id: int = Field(..., ge=1)
    approve: bool = Field(...)

    class Config:
        extra = "forbid"


class PackageRegisterRequest(BaseModel):
    target_house_unit: str = Field(..., min_length=1, max_length=30)
    receiver_house_unit: str = Field(..., min_length=1, max_length=30)
    carrier: str = Field(..., min_length=2, max_length=50)
    image_data: Optional[str] = Field(None, max_length=250000)

    class Config:
        extra = "forbid"


class PetReportRequest(BaseModel):
    pet_name: str = Field(..., min_length=1, max_length=50)
    pet_type: str = Field(..., min_length=2, max_length=50)
    status: str = Field("LOST", min_length=3, max_length=10)
    description: str = Field(..., min_length=3, max_length=400)
    contact_phone: str = Field(..., min_length=8, max_length=20)
    image_data: Optional[str] = Field(None, max_length=250000)

    class Config:
        extra = "forbid"


class SupportRequestCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=80)
    category: str = Field(..., min_length=2, max_length=30)
    description: str = Field(..., min_length=5, max_length=500)
    house_unit: str = Field(..., min_length=1, max_length=30)

    class Config:
        extra = "forbid"
