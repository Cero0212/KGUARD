#!/bin/bash

cd "$(dirname "$0")/.."

echo "🔍 Verificando KGUARD..."
echo "========================"

# Verificar directorios
echo "📁 Directorios:"
for dir in scans data data/cache logs; do
    if [ -d "$dir" ]; then
        echo "  ✅ $dir/ existe"
        # Verificar permisos de escritura
        if [ -w "$dir" ]; then
            echo "     ✓ Tiene permisos de escritura"
        else
            echo "     ❌ No tiene permisos de escritura - corrigiendo..."
            sudo chmod 755 "$dir"
            echo "     ✓ Permisos corregidos"
        fi
    else
        echo "  ❌ $dir/ no existe - creando..."
        sudo mkdir -p "$dir"
        sudo chmod 755 "$dir"
    fi
done

echo ""

# Verificar entorno virtual
if [ -f "venv/bin/activate" ]; then
    echo "✅ Entorno virtual encontrado"
    source venv/bin/activate
    
    # Verificar dependencias
    echo "📦 Dependencias:"
    python -c "
import sys
deps = [
    ('flask', 'Flask'),
    ('flask_cors', 'Flask-CORS'),
    ('requests', 'Requests'),
    ('psutil', 'Psutil'),
    ('dotenv', 'Python-Dotenv')
]
missing = []
for module, name in deps:
    try:
        __import__(module)
        print(f'  ✅ {name}')
    except ImportError:
        print(f'  ❌ {name} - No instalado')
        missing.append(name)
if missing:
    sys.exit(1)
"
    deactivate
else:
    echo "❌ Entorno virtual no encontrado"
    echo "Ejecuta: python -m venv venv && source venv/bin/activate && pip install flask flask-cors requests psutil python-dotenv"
    exit 1
fi

echo ""
echo "Para iniciar: ./scripts/start.sh"
