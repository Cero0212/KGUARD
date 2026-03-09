#!/bin/bash
# install.sh
echo "Instalando KGUARD..."

# Crea el venv en la raíz del proyecto
python3 -m venv venv

# Activa y actualiza pip
source venv/bin/activate
pip install --upgrade pip

# Instala las dependencias usando ruta absoluta
# Asegúrate de que el archivo existe en backend/requirements.txt
pip install -r backend/requirements.txt

echo "Instalación completada."
