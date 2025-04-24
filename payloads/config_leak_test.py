import re
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Archivos comúnmente expuestos que podrían contener credenciales
COMMON_CONFIG_FILES = [
    "/.env",
    "/config.php",
    "/web.config",
    "/settings.py",
    "/appsettings.json",
]

def create_session():
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.3,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,es;q=0.8',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'no-cache',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Dest': 'document'
    })
    
    return session

def detect_sensitive_data(text):
    patterns = [
        r"(password|passwd|pwd)\s*=\s*['\"]?.+?['\"]?",
        r"(?i)aws_secret_access_key\s*=\s*['\"]?.+?['\"]?",
        r"(?i)api[_-]?key\s*[:=]\s*['\"]?.+?['\"]?",
        r"(?i)(slack|github|discord)[_-]?token\s*[:=]\s*['\"]?.+?['\"]?",
        r"(?i)secret\s*[:=]\s*['\"]?.+?['\"]?",
        r"(?i)jwt\s*[:=]\s*['\"]?.+?\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+['\"]?",
        r"mongodb(\+srv)?://[^\s'\"]+",
        r"ldap://[^\s'\"]+",
        r"(?i)user(name)?\s*=\s*['\"]?.+?['\"]?",
    ]
    for pattern in patterns:
        if re.search(pattern, text):
            return True
    return False

def is_text_response(response):
    content_type = response.headers.get("Content-Type", "")
    return "text" in content_type or "json" in content_type or "xml" in content_type

def test_config_leaks(base_url):
    results = []
    session = create_session()
    
    for path in COMMON_CONFIG_FILES:
        full_url = base_url.rstrip("/") + path
        try:
            response = session.get(full_url, timeout=5, allow_redirects=False)

            if response.status_code == 200 and is_text_response(response) and len(response.text) > 10:
                snippet = response.text[:200].replace("\n", " ").replace("\r", "")
                if detect_sensitive_data(response.text):
                    results.append(f"[!!] FUGA CRÍTICA: {full_url} → {snippet}...")
                else:
                    results.append(f"[!] Posible fuga: {full_url} → {snippet}...")

            elif response.status_code == 403:
                results.append(f"[!] {full_url} denegado (403), posible archivo protegido.")
            elif response.status_code == 404:
                results.append(f"[.] {full_url} no encontrado (404), no hay fuga.")
            
        except requests.exceptions.Timeout:
            results.append(f"[ERROR] Timeout al intentar verificar {full_url}.")
        except requests.exceptions.TooManyRedirects:
            results.append(f"[ERROR] Demasiadas redirecciones en {full_url}.")
        except requests.exceptions.RequestException as e:
            results.append(f"[ERROR] No se pudo verificar {full_url}: {str(e)}")

    return results

# Ejecución independiente
if __name__ == "__main__":
    target = input("Introduce la URL base (ej: https://example.com): ").strip()
    results = test_config_leaks(target)
    for r in results:
        print(r)