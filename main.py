"""gmail-alerting-app/main.py

Script principal que conecta con la API de Gmail para leer mensajes
recientes, detectar palabras clave y adjuntos peligrosos, y generar
alertas. Las alertas se registran en `alertas.txt`  adicionalmente se
envían a un Webhook de Slack definido por la variable de entorno
`WEBHOOK_URL`.

Flujo general:
 - Cargar variables de entorno (opcionalmente desde `.env`).
 - Inicializar logger que escribe en `alertas.txt` y en consola.
 - Autenticar con OAuth2 usando `credentials.json` / `token.json`.
 - Leer mensajes recientes y evaluar asunto, snippet y adjuntos.
 - Registrar y reportar alertas detectadas.

Notas:
 - `token.json` se genera en el primer arranque tras autorizar la
     aplicación en el navegador.
 - Ajustar `KEYWORDS`, `WHITELIST_DOMAINS` y `DANGEROUS_EXTENSIONS`
     según necesidades.
"""

import os  # Acceso a variables de entorno y operaciones con el sistema de archivos
import sys  # Módulo para interactuar con el sistema, usado para salir del programa en caso de error crítico.
import json  # Leer/escribir JSON (p. ej. token.json)
import requests  # Enviar HTTP requests (usado para Webhook de Slack)
from google.auth.transport.requests import Request  # Utilidad para refrescar tokens OAuth
from google.oauth2.credentials import Credentials  # Gestiona credenciales OAuth (token.json)
from google_auth_oauthlib.flow import InstalledAppFlow  # Flujo interactivo de OAuth (abre navegador)
from googleapiclient.discovery import build  # Construir cliente de la API de Gmail
from datetime import datetime  # Marcas de tiempo o parseo si se necesita más tarde
import logging  # Sistema de logging para registrar alertas en archivo/console
from dotenv import load_dotenv  # Cargar variables desde .env


# Carga las variables desde un archivo .env si existe (útil en desarrollo)
load_dotenv()

# Obtener variables de entorno
# - `WEBHOOK_URL`: URL del Webhook de Slack para notificaciones. Si no
#   existe, las alertas solo se registran en `alertas.txt`.
WEBHOOK_URL = os.getenv('WEBHOOK_URL')
GMAIL_MAX_RESULTS = int(os.getenv('GMAIL_MAX_RESULTS', 10))

# OAuth scopes requeridos: solo lectura de Gmail en este POC
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Reglas de detección (puedes parametrizarlas o cargarlas desde .env)
KEYWORDS = ['confidencial', 'contraseña']
WHITELIST_DOMAINS = ['@empresa.com', '@amazon.com']
DANGEROUS_EXTENSIONS = ['.zip', '.exe', '.js', '.bat']


# Configuración básica del sistema de logs
# Permitir ajustar el nivel de logs mediante la variable de entorno `LOG_LEVEL`
level_name = os.getenv('LOG_LEVEL', 'INFO').upper()
level = getattr(logging, level_name, logging.INFO)

logging.basicConfig(
    level=level,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler("alertas.txt", encoding='utf-8'), # Escribir en archivo
        logging.StreamHandler() # Mostrar en consola
    ]
)

logger = logging.getLogger("GmailAlerts")

def get_service():
    """Autentica y devuelve un cliente de la API de Gmail.

    Comportamiento:
    - Si existe `token.json`, lo usa para crear las credenciales.
    - Si el token ha caducado y hay `refresh_token`, lo refresca.
    - Si no hay credenciales válidas, inicia `InstalledAppFlow` y abre
      el navegador para que el usuario autorice la app. Tras la
      autorización guarda `token.json` para futuros arranques.

    Retorna:
      Un objeto `Resource` creado por `googleapiclient.discovery.build`
      listo para hacer llamadas `service.users().messages()...`.
    """
    creds = None
    if os.path.exists('token.json'):
        # `token.json` contiene access/refresh tokens generados previamente
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            # Intentar refrescar automáticamente si es posible
            creds.refresh(Request())
        else:
            try:
                # Flujo interactivo: abre navegador y solicita permiso al usuario
                flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
            except FileNotFoundError:
                logger.critical("Error: El archivo 'credentials.json' no se encontró.")
                logger.critical("Por favor, descarga tus credenciales de OAuth 2.0 desde Google Cloud Console y colócalas en la raíz del proyecto.")
                sys.exit(1)
        # Guardar credenciales para usos posteriores
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    # Construir el cliente de la API de Gmail
    return build('gmail', 'v1', credentials=creds, cache_discovery=False)

def log_alert(subject, sender, reason):
    """Registrar y (opcionalmente) notificar una alerta.

    Parámetros:
      - subject: asunto del correo
      - sender: remitente (cabecera From)
      - reason: motivo de la alerta (p. ej. palabra detectada)

    Acciones realizadas:
      1. Formatea un mensaje para Slack (clave `text`).
      2. Registra la alerta en el logger (se escribe en `alertas.txt`).
      3. Si `WEBHOOK_URL` está configurada, hace un `POST` a Slack.
    """

    detection_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Preparar mensaje para Slack (formato simple en texto)
    mensaje_slack = {
        "text": f"*ALERTA DETECTADA*\n> *Motivo:* {reason}\n> *Remitente:* {sender}\n> *Asunto:* {subject}\n> *Fecha/Hora Detección:* {detection_time}"
    }

    # Registrar localmente (archivo + consola)
    log_local = f"{reason} | Remitente: {sender} | Asunto: {subject}"
    logger.warning(log_local)

    # Enviar a Slack si se configuró el webhook
    if WEBHOOK_URL:
        try:
            response = requests.post(
                WEBHOOK_URL,
                json=mensaje_slack,
                headers={'Content-type': 'application/json'},
                timeout=5
            )
            if response.status_code != 200:
                logger.error(f"Error en Slack: {response.status_code} - {response.text}")
        except Exception as e:
            # No interrumpe la ejecución principal, solo registra el fallo
            logger.error(f"Fallo en envío de Webhook: {e}")
    else:
        logger.info("Aviso: No se envió notificación a Slack (WEBHOOK_URL no configurada).")

def analyze_emails():
        """Leer y analizar mensajes recientes de la cuenta autorizada.

        - Obtiene una lista de mensajes (configurable con `GMAIL_MAX_RESULTS`).
        - Para cada mensaje descarga el detalle, extrae `Subject`, `From`
            y `snippet`.
        - Excluye remitentes cuyos dominios estén en `WHITELIST_DOMAINS`.
        - Busca `KEYWORDS` en el `snippet` y en el asunto; si encuentra
            coincidencias llama a `log_alert`.
        - Recorre las partes del payload para verificar si hay archivos
            cuya extensión esté en `DANGEROUS_EXTENSIONS` y registra alertas.
        """
        service = get_service()

        # 1. Leer la lista de los últimos correos
        results = service.users().messages().list(userId='me', maxResults=GMAIL_MAX_RESULTS).execute()
        messages = results.get('messages', [])

        for msg in messages:
                # 2. Obtener el contenido completo de cada mensaje por su ID
                msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
                headers = msg_data['payload']['headers']

                # 3. Extraer campos útiles (con valores por defecto si no existen)
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "Sin Asunto")
                sender = next((h['value'] for h in headers if h['name'] == 'From'), "Desconocido")
                snippet = msg_data.get('snippet', '').lower()

                # Excluir dominios de confianza para reducir falsos positivos
                if any(domain in sender for domain in WHITELIST_DOMAINS):
                        continue

                # Buscar palabras clave en snippet y asunto
                for word in KEYWORDS:
                        if word in snippet or word in subject.lower():
                                log_alert(subject, sender, f"Palabra detectada: {word}")

                # Analizar adjuntos de forma simple (comprobar nombre de fichero)
                parts = msg_data['payload'].get('parts', [])
                for part in parts:
                        filename = part.get('filename', '')
                        if any(filename.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS):
                                log_alert(subject, sender, f"Adjunto peligroso: {filename}")

if __name__ == '__main__':
    analyze_emails()