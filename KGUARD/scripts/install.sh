#!/bin/bash

echo "Instalando KGUARD..."

# Crear estructura de directorios
mkdir -p ../scans
mkdir -p ../data/cache
mkdir -p ../logs

# Instalar dependencias de Python
pip install -r ../backend/requirement.txt

# Crear base de datos inicial
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

echo "Instalación completada."
echo "Para iniciar: python ../backend/app.py"

