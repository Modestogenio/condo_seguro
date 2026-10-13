@echo off
title CondoSeguro Chile - Servidor de Seguridad Vecinal
echo ===================================================================
echo   🛡️ CONDOSEGURO CHILE - SERVIDOR Y RED DE SEGURIDAD VECINAL
echo ===================================================================
echo   Iniciando servidor FastAPI en http://localhost:8000 ...
echo.
echo   Credenciales de Demostracion:
echo   - SuperAdmin (Mantenedor):   admin@condoseguro.cl / admin123456
echo   - Representante (SubAdmin):   representante@aromos.cl / representante123
echo   - Vecino (Casa 1):           vecino1@aromos.cl / vecino123
echo.
echo   Abriendo navegador web...
start http://localhost:8000
cd /d "%~dp0"
python server.py
pause
