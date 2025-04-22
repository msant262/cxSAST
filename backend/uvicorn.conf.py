import os
import sys

# Adiciona o diretório atual ao PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configuração do uvicorn
bind = "127.0.0.1:8000"
workers = 1
reload = True
app = "main:app" 