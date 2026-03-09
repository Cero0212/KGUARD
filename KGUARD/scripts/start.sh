#!/bin/bash
set -e

# Cambiar al directorio raíz del proyecto
cd "$(dirname "$0")/.."

# 1. Verificar si el entorno virtual existe
if [ ! -d "venv" ]; then
    echo "Error: Entorno virtual no encontrado."
    echo "Ejecuta primero: ./scripts/install.sh"
    exit 1
fi

# 2. Activar el entorno virtual
source venv/bin/activate

# 3. Validar que las dependencias estén instaladas (opcional pero profesional)
if [ ! -f "venv/bin/python" ]; then
    echo "Error: Python no encontrado en el entorno virtual."
    exit 1
fi

# 4. Configurar variables de entorno
export PYTHONPATH="$(pwd)/backend:$PYTHONPATH"
export FLASK_APP=backend/app.py

echo "------------------------------------------"
echo "KGUARD starting on http://127.0.0.1:1717"
echo "Press Ctrl+C to stop"
echo "------------------------------------------"
echo ""

# 5. Ejecutar la aplicación
python backend/app.py
