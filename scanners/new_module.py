# new_module.py
import requests

def check_ldap_injection(url):
    if "login" in url:
        return "[!] Posible LDAP Injection: Endpoint de login detectado."
    return None

def check_ntlm_endpoints(url):
    if "/rpc" in url or "/ews" in url:
        return "[!] NTLM posible: Endpoint RPC/EWS puede aceptar autenticación NTLM."
    return None

def check_sensitive_files(url):
    sensitive_files = ["/.env", "/web.config"]
    for f in sensitive_files:
        if f in url:
            return f"[!] Archivo sensible posiblemente expuesto: {f}"
    return None

def check_ntlmv1_weak_auth(url):
    try:
        headers = {
            'Authorization': 'NTLM ' + 'TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAA=='
        }
        response = requests.get(url, headers=headers, timeout=5)
        if 'NTLM' in response.headers.get('WWW-Authenticate', ''):
            return "[!] NTLMv1 vulnerable: El servidor podría estar aceptando autenticación NTLMv1."
    except Exception as e:
        return f"[x] Error al verificar NTLMv1: {e}"
    return None

def check_kerberoasting(url):
    try:
        response = requests.get(url + "/rpc", timeout=5)
        if "Microsoft" in response.text or "RPC" in response.text:
            return "[!] Posible Kerberoasting: Endpoint /rpc podría estar expuesto."
    except Exception as e:
        return f"[x] Error al verificar Kerberoasting: {e}"
    return None

def check_exposed_ad_endpoints(url):
    try:
        endpoints = ["/rpc", "/autodiscover/", "/owa"]
        exposed = []
        for ep in endpoints:
            full_url = url.rstrip("/") + ep
            r = requests.get(full_url, timeout=5)
            if r.status_code == 200:
                exposed.append(ep)
        if exposed:
            return f"[!] Endpoints expuestos: {', '.join(exposed)}"
    except Exception as e:
        return f"[x] Error al verificar endpoints críticos: {e}"
    return None
