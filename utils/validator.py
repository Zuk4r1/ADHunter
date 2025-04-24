import re
import socket
import requests

def validate_url(url):
    """Valida si la URL proporcionada tiene el formato correcto."""
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// o https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # dominio
        r'localhost|' # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|' # IP
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)' # IPv6
        r'(?::\d+)?' # puerto opcional
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    return re.match(regex, url) is not None

def validate_ip(ip):
    """Valida si la IP proporcionada es válida."""
    try:
        socket.inet_aton(ip)  # Verifica si la IP es válida (IPv4)
        return True
    except socket.error:
        return False

def check_url_exists(url):
    """Verifica si la URL es accesible (código de estado HTTP)."""
    try:
        response = requests.get(url, timeout=10)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def validate_credentials(username, password):
    """Valida si las credenciales de usuario cumplen con ciertos requisitos."""
    if len(username) < 5 or len(password) < 8:
        return False
    # Agregar más validaciones si es necesario
    return True

def validate_email(email):
    """Valida si el correo electrónico tiene un formato correcto."""
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email) is not None

def validate_integer(value):
    """Valida si el valor es un número entero."""
    try:
        int(value)
        return True
    except ValueError:
        return False

def validate_ssl(url):
    """Verifica si la URL tiene habilitado SSL (https)."""
    if url.startswith("https://"):
        return True
    return False

def validate_response_for_sql_injection(response, payload):
    """Valida si la respuesta contiene patrones comunes de inyección SQL."""
    sql_patterns = [
        "error in your SQL syntax",
        "Warning: mysql",
        "MySQL server error",
        "You have an error in your SQL syntax",
        "SQLException"
    ]
    for pattern in sql_patterns:
        if pattern.lower() in response.lower():
            print(f"Possible SQL Injection detected with payload: {payload}")
            return True
    return False
