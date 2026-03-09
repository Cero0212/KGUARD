#!/bin/bash

echo "Iniciando instalación de KGUARD..."

# 1. Crear estructura de directorios
mkdir -p ../scans
mkdir -p ../data/cache
mkdir -p ../logs

# 2. Crear entorno virtual (aislado del sistema)
echo "Creando entorno virtual..."
python3 -m venv venv

# 3. Activar el entorno
source venv/bin/activate

# 4. Instalar dependencias dentro del entorno
echo "Instalando dependencias..."
pip install --upgrade pip
pip install -r ../backend/requirements.txt

# 5. Crear base de datos inicial
echo "Configurando base de datos..."
python -c "
import sqlite3
conn = sqlite3.connect('../data/threats.db')
cursor = conn.cursor()
cursor.execute('CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, target TEXT, type TEXT, start_time TEXT, end_time TEXT, findings_count INTEGER, summary TEXT, file_path TEXT)')
cursor.execute('CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, title TEXT, description TEXT, severity TEXT, remediation TEXT, evidence TEXT, created_at TEXT)')
cursor.execute('CREATE TABLE IF NOT EXISTS threat_intel (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT, last_update TEXT, entries_count INTEGER, status TEXT)')
conn.commit()
conn.close()
"

echo "------------------------------------------"
echo "Instalación completada correctamente."
echo "Para iniciar la app, usa: ./start.sh"
